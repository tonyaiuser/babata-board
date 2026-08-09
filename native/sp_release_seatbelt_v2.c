/*
 * SPSPY isolated release selector v2 (Darwin only).
 *
 * current.payload is an atomically selected, still-untrusted data artifact.
 * This program never extracts it, imports it, or executes any candidate byte.
 * The native boundary exists to make selection/rollback crash-durable while
 * two fixed workers are unable to fork, exec, or communicate over a network.
 */
#define _DARWIN_C_SOURCE 1
#if !defined(__APPLE__)
#error "sp_release_seatbelt_v2 is Darwin-only"
#endif

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
#include <CommonCrypto/CommonDigest.h>
#include <sandbox.h>
#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <spawn.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/event.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

extern char **environ;
/* Exported by libSystem, but no longer present in the deprecated public
 * sandbox.h.  It is used only as a policy query; see probe_boundary(). */
extern int sandbox_check(pid_t, const char *, int, ...);

#if !defined(__BYTE_ORDER__) || __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "sp_release_seatbelt_v2 protocol v3 requires little-endian Darwin"
#endif

#define V2_MAGIC 0x53505232U
#define V2_VERSION 3U
#define MAX_PAYLOAD_BYTES (280U * 1024U * 1024U)
#define ROLE_ACTIVATE 1U
#define ROLE_ROLLBACK 2U
#define RESULT_OK 0U
#define RESULT_FAILED 1U

#define PHASE_PREPARED 1U
#define PHASE_GO_COMMITTED 2U
#define PHASE_ACTIVATING 3U
#define PHASE_ROLLBACK_GO 4U
#define PHASE_COMMITTED 5U
#define PHASE_ROLLED_BACK 6U
#define PHASE_UNCERTAIN 7U
#define PHASE_RECOVERING_ROLLBACK 8U

#define CURRENT_UNKNOWN 0U
#define CURRENT_ABSENT 1U
#define CURRENT_PAYLOAD 2U
#define CURRENT_PRIOR 3U

#define ZERO_SHA256_HEX "0000000000000000000000000000000000000000000000000000000000000000"
#define SELECTOR_LOCK_NAME ".sp-release-v2.lock"
#define ACTIVATE_LEASE_NAME ".sp-release-v2.activate.lease"
#define ROLLBACK_LEASE_NAME ".sp-release-v2.rollback.lease"
#define STATE_NAME ".sp-release-v2.state"

#ifndef SP_TOTAL_TIMEOUT_MS
#define SP_TOTAL_TIMEOUT_MS 60000
#endif
#ifndef SP_CLEANUP_TIMEOUT_MS
#define SP_CLEANUP_TIMEOUT_MS 5000
#endif
#ifndef SP_TEST_CRASH_AFTER_PHASE
#define SP_TEST_CRASH_AFTER_PHASE 0
#endif
#ifndef SP_TEST_REGISTER_FAILURE
#define SP_TEST_REGISTER_FAILURE 0
#endif
#ifndef SP_TEST_WORKER_BEFORE_READY_ROLE
#define SP_TEST_WORKER_BEFORE_READY_ROLE 0
#endif
#ifndef SP_TEST_WORKER_AFTER_READY_ROLE
#define SP_TEST_WORKER_AFTER_READY_ROLE 0
#endif
#ifndef SP_TEST_WORKER_STALL_ROLE
#define SP_TEST_WORKER_STALL_ROLE 0
#endif
#ifndef SP_TEST_OPERATION_FAILURE_ROLE
#define SP_TEST_OPERATION_FAILURE_ROLE 0
#endif
#ifndef SP_TEST_OPERATION_FAILURE_AFTER_SELECT_ROLE
#define SP_TEST_OPERATION_FAILURE_AFTER_SELECT_ROLE 0
#endif
#ifndef SP_MAX_NONCE_MARKERS
#define SP_MAX_NONCE_MARKERS 4096
#endif
#ifndef SP_LOCK_TIMEOUT_MS
#define SP_LOCK_TIMEOUT_MS 500
#endif
#ifndef SP_TEST_RECOVERY_CRASH_POINT
#define SP_TEST_RECOVERY_CRASH_POINT 0
#endif
#ifndef SP_TEST_ALLOW_OWNER_HELPER
#define SP_TEST_ALLOW_OWNER_HELPER 0
#endif

/* allow-default is an additional fixed-worker boundary, not the trust basis:
 * raw evidence is verified before entry, candidate bytes stay data-only, and
 * the explicit denials below are probed before either worker reports READY. */
static const char k_profile[] =
    "(version 1)"
    "(allow default)"
    "(deny process-fork)"
    "(deny process-exec)"
    "(deny network*)";

static volatile sig_atomic_t g_stop_requested = 0;

static void recovery_crash(int point) {
  if (SP_TEST_RECOVERY_CRASH_POINT == point) _exit(120 + point);
}

typedef struct __attribute__((packed)) {
  uint64_t dev;
  uint64_t ino;
  uint64_t size;
  uint64_t mtime_ns;
  uint64_t ctime_ns;
  uint32_t mode;
  uint32_t nlink;
  uint32_t uid;
} FdIdentity;

typedef struct __attribute__((packed)) {
  uint32_t magic;
  uint32_t version;
  uint32_t role;
  uint32_t prior_present;
  uint32_t reserved;
  int32_t pid;
  int32_t ppid;
  uint64_t epoch;
  uint8_t nonce[32];
  uint8_t payload_digest[32];
  uint8_t previous_digest[32];
  uint8_t authority_digest[32];
  uint8_t trusted_root_digest[32];
  uint8_t envelope_digest[32];
  uint8_t helper_digest[32];
  uint8_t profile_digest[32];
  FdIdentity root_identity;
  FdIdentity payload_identity;
  FdIdentity previous_identity;
  FdIdentity lease_identity;
} Ready;

typedef struct __attribute__((packed)) {
  uint32_t magic;
  uint32_t version;
  uint32_t role;
  uint32_t prior_present;
  uint32_t reserved;
  uint64_t epoch;
  uint8_t nonce[32];
  uint8_t payload_digest[32];
  uint8_t previous_digest[32];
  uint8_t authority_digest[32];
  uint8_t trusted_root_digest[32];
  uint8_t envelope_digest[32];
  uint8_t helper_digest[32];
} Go;

typedef struct __attribute__((packed)) {
  uint32_t magic;
  uint32_t version;
  uint32_t role;
  uint32_t prior_present;
  uint32_t reserved;
  uint32_t status;
  int32_t error_number;
  uint64_t epoch;
  uint8_t nonce[32];
  uint8_t expected_digest[32];
  uint8_t observed_digest[32];
  uint8_t authority_digest[32];
  uint8_t trusted_root_digest[32];
  uint8_t envelope_digest[32];
  uint8_t helper_digest[32];
} Result;

typedef struct __attribute__((packed)) {
  uint32_t magic;
  uint32_t version;
  uint32_t phase;
  uint32_t prior_present;
  uint32_t recovery_from_phase;
  uint32_t reserved;
  uint64_t epoch;
  int32_t activation_pid;
  int32_t rollback_pid;
  uint64_t activation_started_ns;
  uint64_t rollback_started_ns;
  uint8_t nonce[32];
  uint8_t payload_digest[32];
  uint8_t previous_digest[32];
  uint8_t authority_digest[32];
  uint8_t trusted_root_digest[32];
  uint8_t envelope_digest[32];
  uint8_t helper_digest[32];
  uint8_t profile_digest[32];
  FdIdentity activation_lease_identity;
  FdIdentity rollback_lease_identity;
} DurableState;

typedef struct __attribute__((packed)) {
  uint32_t magic;
  uint32_t version;
  uint32_t prior_present;
  uint32_t reserved;
  uint64_t epoch;
  uint8_t nonce[32];
  uint8_t payload_digest[32];
  uint8_t previous_digest[32];
  uint8_t authority_digest[32];
  uint8_t trusted_root_digest[32];
  uint8_t envelope_digest[32];
  uint8_t helper_digest[32];
  FdIdentity activation_lease_identity;
  FdIdentity rollback_lease_identity;
} NonceMarker;

typedef struct {
  pid_t pid;
  int control_fd;
  int registered;
  int reaped;
  uint32_t role;
  uint64_t started_ns;
} Child;

typedef struct {
  int root_fd;
  int payload_fd;
  int previous_fd;
  int helper_fd;
  uint32_t prior_present;
  uint64_t epoch;
  uint8_t nonce[32];
  uint8_t payload_digest[32];
  uint8_t previous_digest[32];
  uint8_t authority_digest[32];
  uint8_t trusted_root_digest[32];
  uint8_t envelope_digest[32];
  uint8_t helper_digest[32];
  FdIdentity root_identity;
  FdIdentity payload_identity;
  FdIdentity previous_identity;
  FdIdentity activation_lease_identity;
  FdIdentity rollback_lease_identity;
} Transaction;

_Static_assert(sizeof(FdIdentity) == 52, "FdIdentity protocol size");
_Static_assert(sizeof(Ready) == 500, "Ready protocol size");
_Static_assert(offsetof(Ready, epoch) == 28, "Ready epoch offset");
_Static_assert(offsetof(Ready, nonce) == 36, "Ready nonce offset");
_Static_assert(offsetof(Ready, lease_identity) == 448, "Ready lease offset");
_Static_assert(sizeof(Go) == 252, "Go protocol size");
_Static_assert(offsetof(Go, epoch) == 20, "Go epoch offset");
_Static_assert(sizeof(Result) == 260, "Result protocol size");
_Static_assert(offsetof(Result, epoch) == 28, "Result epoch offset");
_Static_assert(sizeof(DurableState) == 416, "DurableState protocol size");
_Static_assert(offsetof(DurableState, epoch) == 24, "DurableState epoch offset");
_Static_assert(offsetof(DurableState, nonce) == 56, "DurableState nonce offset");
_Static_assert(offsetof(DurableState, activation_lease_identity) == 312, "DurableState lease offset");
_Static_assert(sizeof(NonceMarker) == 352, "NonceMarker protocol size");
_Static_assert(offsetof(NonceMarker, epoch) == 16, "NonceMarker epoch offset");

static void stop_handler(int unused) {
  (void)unused;
  g_stop_requested = 1;
}

static uint64_t monotonic_ns(void) {
  struct timespec value;
  if (clock_gettime(CLOCK_MONOTONIC, &value) != 0) return 0;
  return (uint64_t)value.tv_sec * 1000000000ULL + (uint64_t)value.tv_nsec;
}

static int bytes_equal(const void *left, const void *right, size_t size) {
  return memcmp(left, right, size) == 0;
}

static int bytes_zero(const uint8_t *value, size_t size) {
  size_t index;
  for (index = 0; index < size; ++index) if (value[index] != 0) return 0;
  return 1;
}

static int parse_fd(const char *value, int *result) {
  char *end = NULL;
  long parsed;
  errno = 0;
  parsed = strtol(value, &end, 10);
  if (errno != 0 || end == value || *end != '\0' || parsed < 0 || parsed > INT32_MAX) return EINVAL;
  *result = (int)parsed;
  return 0;
}

static int parse_optional_fd(const char *value, int *result) {
  if (value != NULL && strcmp(value, "-1") == 0) {
    *result = -1;
    return 0;
  }
  return parse_fd(value, result);
}

static int parse_present(const char *value, uint32_t *result) {
  if (value != NULL && strcmp(value, "0") == 0) {
    *result = 0;
    return 0;
  }
  if (value != NULL && strcmp(value, "1") == 0) {
    *result = 1;
    return 0;
  }
  return EINVAL;
}

static int parse_epoch(const char *value, uint64_t *result) {
  char *end = NULL;
  unsigned long long parsed;
  errno = 0;
  parsed = strtoull(value, &end, 10);
  if (errno != 0 || end == value || *end != '\0' || parsed == 0) return EINVAL;
  *result = (uint64_t)parsed;
  return 0;
}

static int parse_hex32(const char *value, uint8_t result[32]) {
  size_t index;
  if (value == NULL || strlen(value) != 64) return EINVAL;
  for (index = 0; index < 32; ++index) {
    unsigned int parsed;
    char a = value[index * 2], b = value[index * 2 + 1];
    if (!((a >= '0' && a <= '9') || (a >= 'a' && a <= 'f')) ||
        !((b >= '0' && b <= '9') || (b >= 'a' && b <= 'f')) ||
        sscanf(value + index * 2, "%2x", &parsed) != 1) return EINVAL;
    result[index] = (uint8_t)parsed;
  }
  return 0;
}

static void hex32(const uint8_t value[32], char output[65]) {
  static const char digits[] = "0123456789abcdef";
  size_t index;
  for (index = 0; index < 32; ++index) {
    output[index * 2] = digits[value[index] >> 4];
    output[index * 2 + 1] = digits[value[index] & 15U];
  }
  output[64] = '\0';
}

static int identity_zero(const FdIdentity *identity) {
  return bytes_zero((const uint8_t *)identity, sizeof(*identity));
}

static int write_full(int fd, const void *buffer, size_t size) {
  const uint8_t *input = (const uint8_t *)buffer;
  size_t offset = 0;
  while (offset < size) {
    ssize_t written = write(fd, input + offset, size - offset);
    if (written < 0) {
      if (errno == EINTR && !g_stop_requested) continue;
      return errno == 0 ? EIO : errno;
    }
    if (written == 0) return EIO;
    offset += (size_t)written;
  }
  return 0;
}

static int read_until(int fd, void *buffer, size_t size, uint64_t deadline_ns) {
  uint8_t *output = (uint8_t *)buffer;
  size_t offset = 0;
  while (offset < size) {
    struct pollfd poll_fd;
    uint64_t now = monotonic_ns();
    int timeout_ms, poll_result;
    ssize_t amount;
    if (g_stop_requested) return EINTR;
    if (now == 0 || now >= deadline_ns) return ETIMEDOUT;
    timeout_ms = (int)((deadline_ns - now + 999999ULL) / 1000000ULL);
    poll_fd.fd = fd;
    poll_fd.events = POLLIN | POLLHUP;
    poll_fd.revents = 0;
    poll_result = poll(&poll_fd, 1, timeout_ms);
    if (poll_result == 0) return ETIMEDOUT;
    if (poll_result < 0) {
      if (errno == EINTR && !g_stop_requested) continue;
      return errno == 0 ? EIO : errno;
    }
    if (poll_fd.revents & (POLLERR | POLLNVAL)) return EIO;
    amount = read(fd, output + offset, size - offset);
    if (amount == 0) return EPIPE;
    if (amount < 0) {
      if (errno == EINTR && !g_stop_requested) continue;
      return errno == 0 ? EIO : errno;
    }
    offset += (size_t)amount;
  }
  return 0;
}

static uint64_t stat_mtime_ns(const struct stat *value) {
  return (uint64_t)value->st_mtimespec.tv_sec * 1000000000ULL + (uint64_t)value->st_mtimespec.tv_nsec;
}

static uint64_t stat_ctime_ns(const struct stat *value) {
  return (uint64_t)value->st_ctimespec.tv_sec * 1000000000ULL + (uint64_t)value->st_ctimespec.tv_nsec;
}

static int fd_identity(int fd, FdIdentity *result, int directory, int allow_empty) {
  struct stat observed;
  if (fstat(fd, &observed) != 0) return errno;
  if (directory) {
    if (!S_ISDIR(observed.st_mode) || observed.st_uid != getuid() ||
        (observed.st_mode & 0777) != 0700 || observed.st_nlink < 2) return EPERM;
  } else {
    if (!S_ISREG(observed.st_mode) || observed.st_uid != getuid() || observed.st_nlink != 1 ||
        (observed.st_mode & 0777) != 0600 || (!allow_empty && observed.st_size <= 0) ||
        observed.st_size < 0 || (uint64_t)observed.st_size > MAX_PAYLOAD_BYTES) return EPERM;
  }
  result->dev = (uint64_t)observed.st_dev;
  result->ino = (uint64_t)observed.st_ino;
  result->size = (uint64_t)observed.st_size;
  result->mtime_ns = stat_mtime_ns(&observed);
  result->ctime_ns = stat_ctime_ns(&observed);
  result->mode = (uint32_t)observed.st_mode;
  result->nlink = (uint32_t)observed.st_nlink;
  result->uid = (uint32_t)observed.st_uid;
  return 0;
}

static int payload_source_identity(int fd, FdIdentity *result, int recovery) {
  struct stat observed;
  if (!recovery) return fd_identity(fd, result, 0, 0);
  if (fstat(fd, &observed) != 0) return errno;
  if (!S_ISREG(observed.st_mode) || observed.st_uid != getuid() || observed.st_nlink != 0 ||
      (observed.st_mode & 0777) != 0600 || observed.st_size <= 0 ||
      (uint64_t)observed.st_size > MAX_PAYLOAD_BYTES) return EPERM;
  result->dev = (uint64_t)observed.st_dev;
  result->ino = (uint64_t)observed.st_ino;
  result->size = (uint64_t)observed.st_size;
  result->mtime_ns = stat_mtime_ns(&observed);
  result->ctime_ns = stat_ctime_ns(&observed);
  result->mode = (uint32_t)observed.st_mode;
  result->nlink = (uint32_t)observed.st_nlink;
  result->uid = (uint32_t)observed.st_uid;
  return 0;
}

static int same_root(const FdIdentity *left, const FdIdentity *right) {
  return left->dev == right->dev && left->ino == right->ino && left->mode == right->mode && left->uid == right->uid;
}

static int safe_control_fd(int fd) {
  FdIdentity ignored;
  return fd_identity(fd, &ignored, 0, 1);
}

static int bounded_flock(int fd, int operation) {
  uint64_t deadline = monotonic_ns() + (uint64_t)SP_LOCK_TIMEOUT_MS * 1000000ULL;
  struct timespec pause_time;
  pause_time.tv_sec = 0;
  pause_time.tv_nsec = 10000000L;
  for (;;) {
    if (flock(fd, operation | LOCK_NB) == 0) return 0;
    if (errno != EWOULDBLOCK && errno != EAGAIN && errno != EACCES) return errno;
    if (monotonic_ns() >= deadline) return EWOULDBLOCK;
    (void)nanosleep(&pause_time, NULL);
  }
}

static int open_existing_control(int root_fd, const char *name, int *fd_out, FdIdentity *identity_out) {
  int fd = openat(root_fd, name, O_RDWR | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
  int result;
  if (fd < 0) return errno;
  result = fd_identity(fd, identity_out, 0, 1);
  if (result != 0) { close(fd); return result; }
  *fd_out = fd;
  return 0;
}

static int open_or_create_control(int root_fd, const char *name, int *fd_out, FdIdentity *identity_out) {
  int fd, created = 0, result;
  fd = openat(root_fd, name, O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC, 0600);
  if (fd >= 0) created = 1;
  else if (errno == EEXIST) fd = openat(root_fd, name, O_RDWR | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
  if (fd < 0) return errno;
  result = 0;
  if ((created && fchmod(fd, 0600) != 0) || fd_identity(fd, identity_out, 0, 1) != 0) result = errno == 0 ? EPERM : errno;
  if (result == 0 && created && (fsync(fd) != 0 || fsync(root_fd) != 0)) result = errno == 0 ? EIO : errno;
  if (result != 0) { close(fd); return result; }
  *fd_out = fd;
  return 0;
}

static int named_identity_matches(int root_fd, const char *name, const FdIdentity *expected) {
  int fd = -1, result;
  FdIdentity observed;
  result = open_existing_control(root_fd, name, &fd, &observed);
  if (result == 0 && !bytes_equal(&observed, expected, sizeof(observed))) result = EBUSY;
  if (fd >= 0) close(fd);
  return result;
}

static int locked_selector_valid(int root_fd, int selector_fd) {
  FdIdentity expected;
  int result = fd_identity(selector_fd, &expected, 0, 1);
  if (result != 0 || expected.size != 0) return result == 0 ? EPERM : result;
  result = named_identity_matches(root_fd, SELECTOR_LOCK_NAME, &expected);
  if (result != 0) return result;
  return bounded_flock(selector_fd, LOCK_EX);
}

static int prepare_lease_files_mode(Transaction *transaction, int lease_fds[2], int allow_create) {
  int result;
  lease_fds[0] = -1;
  lease_fds[1] = -1;
  result = allow_create ?
      open_or_create_control(transaction->root_fd, ACTIVATE_LEASE_NAME, &lease_fds[0],
                             &transaction->activation_lease_identity) :
      open_existing_control(transaction->root_fd, ACTIVATE_LEASE_NAME, &lease_fds[0],
                            &transaction->activation_lease_identity);
  if (result == 0) result = allow_create ?
      open_or_create_control(transaction->root_fd, ROLLBACK_LEASE_NAME, &lease_fds[1],
                             &transaction->rollback_lease_identity) :
      open_existing_control(transaction->root_fd, ROLLBACK_LEASE_NAME, &lease_fds[1],
                            &transaction->rollback_lease_identity);
  if (result == 0 && transaction->activation_lease_identity.dev == transaction->rollback_lease_identity.dev &&
      transaction->activation_lease_identity.ino == transaction->rollback_lease_identity.ino) result = EPERM;
  if (result == 0) result = bounded_flock(lease_fds[0], LOCK_EX);
  if (result == 0) result = bounded_flock(lease_fds[1], LOCK_EX);
  if (lease_fds[1] >= 0) (void)flock(lease_fds[1], LOCK_UN);
  if (lease_fds[0] >= 0) (void)flock(lease_fds[0], LOCK_UN);
  if (result != 0) {
    if (lease_fds[1] >= 0) close(lease_fds[1]);
    if (lease_fds[0] >= 0) close(lease_fds[0]);
    lease_fds[0] = lease_fds[1] = -1;
  }
  return result;
}

static int prepare_lease_files(Transaction *transaction, int lease_fds[2]) {
  return prepare_lease_files_mode(transaction, lease_fds, 1);
}

static int prepare_existing_lease_files(Transaction *transaction, int lease_fds[2]) {
  return prepare_lease_files_mode(transaction, lease_fds, 0);
}

static int safe_existing_regular(int parent_fd, const char *name, size_t exact_size, int optional) {
  struct stat observed;
  if (fstatat(parent_fd, name, &observed, AT_SYMLINK_NOFOLLOW) != 0) {
    if (optional && errno == ENOENT) return 0;
    return errno;
  }
  if (!S_ISREG(observed.st_mode) || observed.st_uid != getuid() || observed.st_nlink != 1 ||
      (observed.st_mode & 0777) != 0600 || (exact_size != 0 && (size_t)observed.st_size != exact_size)) return EPERM;
  return 0;
}

static int hash_fd(int fd, uint8_t digest[32], FdIdentity *identity) {
  FdIdentity before, after;
  CC_SHA256_CTX context;
  uint8_t buffer[65536];
  uint64_t total = 0;
  ssize_t amount;
  int result = fd_identity(fd, &before, 0, 0);
  if (result != 0) return result;
  if (lseek(fd, 0, SEEK_SET) < 0) return errno;
  CC_SHA256_Init(&context);
  while ((amount = read(fd, buffer, sizeof(buffer))) != 0) {
    if (amount < 0) {
      if (errno == EINTR && !g_stop_requested) continue;
      return errno == 0 ? EIO : errno;
    }
    total += (uint64_t)amount;
    if (total > MAX_PAYLOAD_BYTES) return EFBIG;
    CC_SHA256_Update(&context, buffer, (CC_LONG)amount);
  }
  result = fd_identity(fd, &after, 0, 0);
  if (result != 0 || total != before.size || !bytes_equal(&before, &after, sizeof(before))) return result == 0 ? EBUSY : result;
  CC_SHA256_Final(digest, &context);
  if (lseek(fd, 0, SEEK_SET) < 0) return errno;
  if (identity != NULL) *identity = before;
  return 0;
}

static int hash_helper_fd(int fd, uint8_t digest[32]) {
  struct stat before, after;
  CC_SHA256_CTX context;
  uint8_t buffer[65536];
  uint64_t total = 0;
  ssize_t amount;
  if (fd < 0 || fstat(fd, &before) != 0 || !S_ISREG(before.st_mode) || before.st_nlink != 1 ||
      !((SP_TEST_ALLOW_OWNER_HELPER && before.st_uid == getuid() && (before.st_mode & 0777) == 0700) ||
        (before.st_uid == 0 && (before.st_mode & 0777) == 0555)) || before.st_size <= 0 ||
      (uint64_t)before.st_size > 8U * 1024U * 1024U || lseek(fd, 0, SEEK_SET) < 0) return EPERM;
  CC_SHA256_Init(&context);
  while ((amount = read(fd, buffer, sizeof(buffer))) != 0) {
    if (amount < 0) { if (errno == EINTR) continue; return errno; }
    total += (uint64_t)amount;
    if (total > 8U * 1024U * 1024U) return EFBIG;
    CC_SHA256_Update(&context, buffer, (CC_LONG)amount);
  }
  if (fstat(fd, &after) != 0 || total != (uint64_t)before.st_size || before.st_dev != after.st_dev ||
      before.st_ino != after.st_ino || before.st_size != after.st_size || before.st_mode != after.st_mode ||
      before.st_uid != after.st_uid || before.st_nlink != after.st_nlink ||
      before.st_mtimespec.tv_sec != after.st_mtimespec.tv_sec || before.st_mtimespec.tv_nsec != after.st_mtimespec.tv_nsec ||
      before.st_ctimespec.tv_sec != after.st_ctimespec.tv_sec || before.st_ctimespec.tv_nsec != after.st_ctimespec.tv_nsec)
    return EBUSY;
  CC_SHA256_Final(digest, &context);
  return lseek(fd, 0, SEEK_SET) < 0 ? errno : 0;
}

static int hash_bound_helper(const char *path, int fd, uint8_t digest[32]) {
  struct stat named_before, named_after, opened;
  int result;
  if (path == NULL || path[0] != '/' || lstat(path, &named_before) != 0 || fstat(fd, &opened) != 0 ||
      !S_ISREG(named_before.st_mode) || named_before.st_nlink != 1 ||
      !((SP_TEST_ALLOW_OWNER_HELPER && named_before.st_uid == getuid() && (named_before.st_mode & 0777) == 0700) ||
        (named_before.st_uid == 0 && (named_before.st_mode & 0777) == 0555)) || named_before.st_dev != opened.st_dev ||
      named_before.st_ino != opened.st_ino || named_before.st_mode != opened.st_mode ||
      named_before.st_uid != opened.st_uid || named_before.st_nlink != opened.st_nlink) return EPERM;
  result = hash_helper_fd(fd, digest);
  if (result != 0 || lstat(path, &named_after) != 0 || named_before.st_dev != named_after.st_dev ||
      named_before.st_ino != named_after.st_ino || named_before.st_size != named_after.st_size ||
      named_before.st_mode != named_after.st_mode || named_before.st_uid != named_after.st_uid ||
      named_before.st_nlink != named_after.st_nlink ||
      named_before.st_mtimespec.tv_sec != named_after.st_mtimespec.tv_sec ||
      named_before.st_mtimespec.tv_nsec != named_after.st_mtimespec.tv_nsec ||
      named_before.st_ctimespec.tv_sec != named_after.st_ctimespec.tv_sec ||
      named_before.st_ctimespec.tv_nsec != named_after.st_ctimespec.tv_nsec) return result == 0 ? EBUSY : result;
  return 0;
}

static int hash_named_regular(int parent_fd, const char *name, uint8_t digest[32]) {
  int fd, result;
  FdIdentity opened, named;
  struct stat observed;
  fd = openat(parent_fd, name, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
  if (fd < 0) return errno;
  result = hash_fd(fd, digest, &opened);
  if (result == 0) {
    if (fstatat(parent_fd, name, &observed, AT_SYMLINK_NOFOLLOW) != 0) result = errno;
    else {
      memset(&named, 0, sizeof(named));
      named.dev = (uint64_t)observed.st_dev; named.ino = (uint64_t)observed.st_ino;
      named.size = (uint64_t)observed.st_size; named.mtime_ns = stat_mtime_ns(&observed);
      named.ctime_ns = stat_ctime_ns(&observed); named.mode = (uint32_t)observed.st_mode;
      named.nlink = (uint32_t)observed.st_nlink; named.uid = (uint32_t)observed.st_uid;
      if (!bytes_equal(&opened, &named, sizeof(opened))) result = EBUSY;
    }
  }
  close(fd);
  return result;
}

static int named_absent_stable(int parent_fd, const char *name) {
  struct stat observed;
  if (fstatat(parent_fd, name, &observed, AT_SYMLINK_NOFOLLOW) == 0) return EEXIST;
  if (errno != ENOENT) return errno;
  if (fstatat(parent_fd, name, &observed, AT_SYMLINK_NOFOLLOW) == 0) return EBUSY;
  return errno == ENOENT ? 0 : errno;
}

static int lease_identity_semantics_valid(const FdIdentity *identity) {
  return identity->size == 0 && S_ISREG((mode_t)identity->mode) && identity->uid == (uint32_t)getuid() &&
      identity->nlink == 1 && ((mode_t)identity->mode & 0777) == 0600;
}

static int prior_semantics_valid(uint32_t prior_present, const uint8_t previous_digest[32]) {
  if (prior_present > 1U) return 0;
  return prior_present ? !bytes_zero(previous_digest, 32) : bytes_zero(previous_digest, 32);
}

static int read_exact_control_file(int parent_fd, const char *name, void *value, size_t size, int *present) {
  struct stat before, after;
  uint8_t *output = (uint8_t *)value;
  size_t offset = 0;
  int fd = openat(parent_fd, name, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
  if (fd < 0) {
    if (errno == ENOENT) { *present = 0; return 0; }
    return errno;
  }
  *present = 1;
  if (fstat(fd, &before) != 0 || !S_ISREG(before.st_mode) || before.st_uid != getuid() || before.st_nlink != 1 ||
      (before.st_mode & 0777) != 0600 || (size_t)before.st_size != size) { close(fd); return EPERM; }
  while (offset < size) {
    ssize_t amount = read(fd, output + offset, size - offset);
    if (amount < 0) { if (errno == EINTR) continue; close(fd); return errno; }
    if (amount == 0) { close(fd); return EIO; }
    offset += (size_t)amount;
  }
  {
    uint8_t extra;
    if (read(fd, &extra, 1) != 0) { close(fd); return EIO; }
  }
  if (fstat(fd, &after) != 0 || before.st_dev != after.st_dev || before.st_ino != after.st_ino ||
      before.st_size != after.st_size || before.st_mtimespec.tv_sec != after.st_mtimespec.tv_sec ||
      before.st_mtimespec.tv_nsec != after.st_mtimespec.tv_nsec || before.st_ctimespec.tv_sec != after.st_ctimespec.tv_sec ||
      before.st_ctimespec.tv_nsec != after.st_ctimespec.tv_nsec || before.st_mode != after.st_mode ||
      before.st_uid != after.st_uid || before.st_nlink != after.st_nlink) { close(fd); return EBUSY; }
  close(fd);
  return 0;
}

static int valid_phase(uint32_t phase) {
  return phase >= PHASE_PREPARED && phase <= PHASE_RECOVERING_ROLLBACK;
}

static int state_semantics_valid(const DurableState *state) {
  if (state->magic != V2_MAGIC || state->version != V2_VERSION || !valid_phase(state->phase) || state->epoch == 0 ||
      state->reserved != 0 || !prior_semantics_valid(state->prior_present, state->previous_digest) ||
      state->activation_pid <= 1 || state->rollback_pid <= 1 || state->activation_started_ns == 0 ||
      state->rollback_started_ns == 0 || bytes_zero(state->nonce, 32) || bytes_zero(state->payload_digest, 32) ||
      bytes_zero(state->authority_digest, 32) ||
      bytes_zero(state->trusted_root_digest, 32) || bytes_zero(state->envelope_digest, 32) ||
      bytes_zero(state->helper_digest, 32) || bytes_zero(state->profile_digest, 32) ||
      (state->prior_present && bytes_equal(state->payload_digest, state->previous_digest, 32)) ||
      !lease_identity_semantics_valid(&state->activation_lease_identity) ||
      !lease_identity_semantics_valid(&state->rollback_lease_identity) ||
      (state->activation_lease_identity.dev == state->rollback_lease_identity.dev &&
       state->activation_lease_identity.ino == state->rollback_lease_identity.ino)) return 0;
  if (state->phase == PHASE_UNCERTAIN) {
    if (state->recovery_from_phase < PHASE_PREPARED || state->recovery_from_phase > PHASE_ROLLED_BACK) return 0;
  } else if (state->phase == PHASE_RECOVERING_ROLLBACK) {
    if (state->recovery_from_phase != PHASE_ROLLBACK_GO) return 0;
  } else if (state->recovery_from_phase != 0) return 0;
  return 1;
}

static int state_is_terminal(uint32_t phase) {
  return phase == PHASE_COMMITTED || phase == PHASE_ROLLED_BACK;
}

static int validate_old_state(const Transaction *transaction, DurableState *old, int *present) {
  uint8_t selected[32], current_digest[32];
  uint32_t selected_present;
  int result = read_exact_control_file(transaction->root_fd, ".sp-release-v2.state", old, sizeof(*old), present);
  if (result != 0) return result;
  if (!*present) {
    if (transaction->prior_present != 0 || !bytes_zero(transaction->previous_digest, 32)) return EBADMSG;
    return named_absent_stable(transaction->root_fd, "current.payload");
  }
  if (!state_semantics_valid(old) || !state_is_terminal(old->phase)) return EOWNERDEAD;
  if (transaction->epoch <= old->epoch || bytes_equal(transaction->nonce, old->nonce, 32)) return EALREADY;
  if (old->phase == PHASE_COMMITTED) {
    selected_present = 1;
    memcpy(selected, old->payload_digest, 32);
  } else {
    selected_present = old->prior_present;
    memcpy(selected, old->previous_digest, 32);
  }
  if (transaction->prior_present != selected_present ||
      !bytes_equal(transaction->previous_digest, selected, 32)) return EBADMSG;
  if (!selected_present) return named_absent_stable(transaction->root_fd, "current.payload");
  result = hash_named_regular(transaction->root_fd, "current.payload", current_digest);
  if (result != 0) return result;
  return bytes_equal(current_digest, selected, 32) ? 0 : EBADMSG;
}

static int write_control_file(int parent_fd, const char *temporary, const char *target, const void *value, size_t size,
                              int recovery) {
  int fd, result = 0;
  if (safe_existing_regular(parent_fd, target, size, 1) != 0) return EPERM;
  fd = openat(parent_fd, temporary, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC, 0600);
  if (fd < 0) return errno;
  if (fchmod(fd, 0600) != 0 || safe_control_fd(fd) != 0 || write_full(fd, value, size) != 0 || fsync(fd) != 0) result = errno == 0 ? EIO : errno;
  if (close(fd) != 0 && result == 0) result = errno;
  if (result == 0 && recovery) recovery_crash(1);
  if (result == 0 && renameat(parent_fd, temporary, parent_fd, target) != 0) result = errno;
  if (result == 0 && recovery) recovery_crash(2);
  if (result == 0 && fsync(parent_fd) != 0) result = errno;
  if (result == 0 && recovery) recovery_crash(3);
  if (result != 0) (void)unlinkat(parent_fd, temporary, 0);
  return result;
}

static int state_temporary_name(char *output, size_t size, const char *nonce_hex, uint32_t phase) {
  int length = snprintf(output, size, "%s.%s.%u.tmp", STATE_NAME, nonce_hex, phase);
  return length < 0 || length >= (int)size ? ENAMETOOLONG : 0;
}

static int write_state(int root_fd, const DurableState *state, const char *nonce_hex) {
  char temporary[160];
  int result = state_temporary_name(temporary, sizeof(temporary), nonce_hex, state->phase);
  if (result != 0) return result;
  result = write_control_file(root_fd, temporary, STATE_NAME, state, sizeof(*state), 0);
  if (result == 0 && SP_TEST_CRASH_AFTER_PHASE == (int)state->phase) _exit(90 + (int)state->phase);
  return result;
}


static int write_recovery_state(int root_fd, const DurableState *state, const char *nonce_hex) {
  char temporary[160];
  int result = state_temporary_name(temporary, sizeof(temporary), nonce_hex, state->phase);
  if (result != 0) return result;
  return write_control_file(root_fd, temporary, STATE_NAME, state, sizeof(*state), 1);
}

static int marker_semantics_valid(const NonceMarker *marker) {
  return marker->magic == V2_MAGIC && marker->version == V2_VERSION && marker->reserved == 0 && marker->epoch != 0 &&
      prior_semantics_valid(marker->prior_present, marker->previous_digest) && !bytes_zero(marker->nonce, 32) &&
      !bytes_zero(marker->payload_digest, 32) && !bytes_zero(marker->authority_digest, 32) &&
      !bytes_zero(marker->trusted_root_digest, 32) && !bytes_zero(marker->envelope_digest, 32) &&
      !bytes_zero(marker->helper_digest, 32) &&
      !(marker->prior_present && bytes_equal(marker->payload_digest, marker->previous_digest, 32)) &&
      lease_identity_semantics_valid(&marker->activation_lease_identity) &&
      lease_identity_semantics_valid(&marker->rollback_lease_identity) &&
      !(marker->activation_lease_identity.dev == marker->rollback_lease_identity.dev &&
        marker->activation_lease_identity.ino == marker->rollback_lease_identity.ino);
}

static int validate_nonce_journal(int root_fd, const FdIdentity *activation_lease,
                                  const FdIdentity *rollback_lease) {
  /* Markers are permanent within one activation root.  The hard cap bounds
   * growth and fails closed; reaching it requires an explicit audited root
   * rotation/archive, never automatic deletion that could permit replay. */
  static const char prefix[] = ".sp-release-v2.nonce.";
  DIR *directory;
  struct dirent *entry;
  size_t count = 0, index;
  int duplicate_fd = openat(root_fd, ".", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC), result = 0;
  if (duplicate_fd < 0) return errno;
  directory = fdopendir(duplicate_fd);
  if (directory == NULL) { close(duplicate_fd); return errno; }
  for (;;) {
    const char *suffix;
    NonceMarker marker;
    uint8_t named_nonce[32];
    int present = 0;
    errno = 0;
    entry = readdir(directory);
    if (entry == NULL) {
      if (errno != 0) result = errno;
      break;
    }
    if (strncmp(entry->d_name, prefix, sizeof(prefix) - 1) != 0) continue;
    suffix = entry->d_name + sizeof(prefix) - 1;
    if (strlen(suffix) != 64) { result = EPROTO; break; }
    for (index = 0; index < 64; ++index) {
      char value = suffix[index];
      if (!((value >= '0' && value <= '9') || (value >= 'a' && value <= 'f'))) { result = EPROTO; break; }
    }
    if (result != 0 || parse_hex32(suffix, named_nonce) != 0 ||
        read_exact_control_file(root_fd, entry->d_name, &marker, sizeof(marker), &present) != 0 || !present ||
        !marker_semantics_valid(&marker) || !bytes_equal(marker.nonce, named_nonce, 32) ||
        !bytes_equal(&marker.activation_lease_identity, activation_lease, sizeof(*activation_lease)) ||
        !bytes_equal(&marker.rollback_lease_identity, rollback_lease, sizeof(*rollback_lease))) {
      if (result == 0) result = EPROTO;
      break;
    }
    ++count;
    if (count >= SP_MAX_NONCE_MARKERS) { result = ENOSPC; break; }
  }
  closedir(directory);
  return result;
}

static int create_nonce_marker(int root_fd, const Transaction *transaction, const char *nonce_hex) {
  char target[128];
  NonceMarker marker;
  int fd, result = 0;
  result = validate_nonce_journal(root_fd, &transaction->activation_lease_identity,
                                  &transaction->rollback_lease_identity);
  if (result != 0) return result;
  if (snprintf(target, sizeof(target), ".sp-release-v2.nonce.%s", nonce_hex) >= (int)sizeof(target)) return ENAMETOOLONG;
  memset(&marker, 0, sizeof(marker));
  marker.magic = V2_MAGIC; marker.version = V2_VERSION; marker.prior_present = transaction->prior_present;
  marker.epoch = transaction->epoch;
  memcpy(marker.nonce, transaction->nonce, 32); memcpy(marker.payload_digest, transaction->payload_digest, 32);
  memcpy(marker.previous_digest, transaction->previous_digest, 32); memcpy(marker.authority_digest, transaction->authority_digest, 32);
  memcpy(marker.trusted_root_digest, transaction->trusted_root_digest, 32); memcpy(marker.envelope_digest, transaction->envelope_digest, 32);
  memcpy(marker.helper_digest, transaction->helper_digest, 32);
  marker.activation_lease_identity = transaction->activation_lease_identity;
  marker.rollback_lease_identity = transaction->rollback_lease_identity;
  fd = openat(root_fd, target, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC, 0600);
  if (fd < 0) return errno;
  if (fchmod(fd, 0600) != 0 || safe_control_fd(fd) != 0 || write_full(fd, &marker, sizeof(marker)) != 0 ||
      fsync(fd) != 0 || safe_existing_regular(root_fd, target, sizeof(marker), 0) != 0) result = errno == 0 ? EIO : errno;
  if (close(fd) != 0 && result == 0) result = errno;
  if (result == 0 && fsync(root_fd) != 0) result = errno;
  return result;
}

static int validate_state_marker(int root_fd, const DurableState *state) {
  char nonce_hex[65], name[128];
  NonceMarker marker;
  int present = 0, result;
  hex32(state->nonce, nonce_hex);
  if (snprintf(name, sizeof(name), ".sp-release-v2.nonce.%s", nonce_hex) >= (int)sizeof(name)) return ENAMETOOLONG;
  result = read_exact_control_file(root_fd, name, &marker, sizeof(marker), &present);
  if (result != 0 || !present || !marker_semantics_valid(&marker)) return result == 0 ? EPROTO : result;
  if (marker.prior_present != state->prior_present || marker.epoch != state->epoch ||
      !bytes_equal(marker.nonce, state->nonce, 32) || !bytes_equal(marker.payload_digest, state->payload_digest, 32) ||
      !bytes_equal(marker.previous_digest, state->previous_digest, 32) ||
      !bytes_equal(marker.authority_digest, state->authority_digest, 32) ||
      !bytes_equal(marker.trusted_root_digest, state->trusted_root_digest, 32) ||
      !bytes_equal(marker.envelope_digest, state->envelope_digest, 32) ||
      !bytes_equal(marker.helper_digest, state->helper_digest, 32) ||
      !bytes_equal(&marker.activation_lease_identity, &state->activation_lease_identity, sizeof(FdIdentity)) ||
      !bytes_equal(&marker.rollback_lease_identity, &state->rollback_lease_identity, sizeof(FdIdentity))) return EBADMSG;
  return 0;
}

static int state_transaction_equal(const DurableState *left, const DurableState *right) {
  return left->magic == right->magic && left->version == right->version &&
      left->prior_present == right->prior_present && left->epoch == right->epoch &&
      left->activation_pid == right->activation_pid && left->rollback_pid == right->rollback_pid &&
      left->activation_started_ns == right->activation_started_ns && left->rollback_started_ns == right->rollback_started_ns &&
      bytes_equal(left->nonce, right->nonce, 32) && bytes_equal(left->payload_digest, right->payload_digest, 32) &&
      bytes_equal(left->previous_digest, right->previous_digest, 32) &&
      bytes_equal(left->authority_digest, right->authority_digest, 32) &&
      bytes_equal(left->trusted_root_digest, right->trusted_root_digest, 32) &&
      bytes_equal(left->envelope_digest, right->envelope_digest, 32) &&
      bytes_equal(left->helper_digest, right->helper_digest, 32) &&
      bytes_equal(left->profile_digest, right->profile_digest, 32) &&
      bytes_equal(&left->activation_lease_identity, &right->activation_lease_identity, sizeof(FdIdentity)) &&
      bytes_equal(&left->rollback_lease_identity, &right->rollback_lease_identity, sizeof(FdIdentity));
}

static int classify_current(int root_fd, const DurableState *state, uint32_t *kind, uint8_t digest[32]) {
  int result;
  memset(digest, 0, 32);
  result = named_absent_stable(root_fd, "current.payload");
  if (result == 0) {
    *kind = CURRENT_ABSENT;
    return 0;
  }
  if (result != EEXIST) { *kind = CURRENT_UNKNOWN; return result; }
  result = hash_named_regular(root_fd, "current.payload", digest);
  if (result != 0) { memset(digest, 0, 32); *kind = CURRENT_UNKNOWN; return result; }
  if (bytes_equal(digest, state->payload_digest, 32)) *kind = CURRENT_PAYLOAD;
  else if (state->prior_present && bytes_equal(digest, state->previous_digest, 32)) *kind = CURRENT_PRIOR;
  else *kind = CURRENT_UNKNOWN;
  return 0;
}

static int current_is_prior(const DurableState *state, uint32_t current_kind) {
  return state->prior_present ? current_kind == CURRENT_PRIOR : current_kind == CURRENT_ABSENT;
}

static const char *current_name(uint32_t current_kind) {
  if (current_kind == CURRENT_ABSENT) return "ABSENT";
  if (current_kind == CURRENT_PAYLOAD) return "PAYLOAD";
  if (current_kind == CURRENT_PRIOR) return "PRIOR";
  return "UNKNOWN";
}

static void print_reconciliation(const char *prefix, const char *operation, const char *classification,
                                 const uint8_t state_digest[32], const DurableState *state,
                                 uint32_t current_kind, const uint8_t current_digest[32]) {
  char state_hex[65], current_hex[65];
  hex32(state_digest, state_hex);
  hex32(current_digest, current_hex);
  printf("%s {\"protocol\":\"SP_RELEASE_V3\",\"operation\":\"%s\",\"classification\":\"%s\","
         "\"state_sha256\":\"%s\",\"epoch\":%llu,\"phase\":%u,\"recovery_from_phase\":%u,"
         "\"prior_present\":%s,\"current\":\"%s\",\"current_sha256\":\"%s\"}\n",
         prefix, operation, classification, state_hex, (unsigned long long)state->epoch, state->phase,
         state->recovery_from_phase, state->prior_present ? "true" : "false", current_name(current_kind), current_hex);
}

static int state_transition_temp_allowed(const DurableState *base, const DurableState *temporary) {
  if (!state_semantics_valid(temporary) || !state_transaction_equal(base, temporary)) return 0;
  switch (base->phase) {
    case PHASE_PREPARED:
      return temporary->phase == PHASE_GO_COMMITTED ||
          (temporary->phase == PHASE_UNCERTAIN && temporary->recovery_from_phase == PHASE_PREPARED);
    case PHASE_GO_COMMITTED:
      return temporary->phase == PHASE_ACTIVATING ||
          (temporary->phase == PHASE_UNCERTAIN && temporary->recovery_from_phase == PHASE_GO_COMMITTED);
    case PHASE_ACTIVATING:
      return temporary->phase == PHASE_ROLLBACK_GO || temporary->phase == PHASE_COMMITTED ||
          (temporary->phase == PHASE_UNCERTAIN && temporary->recovery_from_phase == PHASE_ACTIVATING);
    case PHASE_ROLLBACK_GO:
      return temporary->phase == PHASE_ROLLED_BACK ||
          (temporary->phase == PHASE_UNCERTAIN && temporary->recovery_from_phase == PHASE_ROLLBACK_GO) ||
          (temporary->phase == PHASE_RECOVERING_ROLLBACK && temporary->recovery_from_phase == PHASE_ROLLBACK_GO);
    case PHASE_COMMITTED:
      return temporary->phase == PHASE_UNCERTAIN && temporary->recovery_from_phase == PHASE_COMMITTED;
    case PHASE_ROLLED_BACK:
      return temporary->phase == PHASE_UNCERTAIN && temporary->recovery_from_phase == PHASE_ROLLED_BACK;
    case PHASE_UNCERTAIN:
      if (base->recovery_from_phase == PHASE_PREPARED) return temporary->phase == PHASE_ROLLED_BACK;
      if (base->recovery_from_phase == PHASE_GO_COMMITTED || base->recovery_from_phase == PHASE_ACTIVATING)
        return temporary->phase == PHASE_COMMITTED || temporary->phase == PHASE_ROLLED_BACK;
      if (base->recovery_from_phase == PHASE_ROLLBACK_GO)
        return temporary->phase == PHASE_RECOVERING_ROLLBACK || temporary->phase == PHASE_ROLLED_BACK;
      if (base->recovery_from_phase == PHASE_COMMITTED) return temporary->phase == PHASE_COMMITTED;
      return base->recovery_from_phase == PHASE_ROLLED_BACK && temporary->phase == PHASE_ROLLED_BACK;
    case PHASE_RECOVERING_ROLLBACK:
      return temporary->phase == PHASE_ROLLED_BACK;
    default:
      return 0;
  }
}

static int has_suffix(const char *value, const char *suffix) {
  size_t value_size = strlen(value), suffix_size = strlen(suffix);
  return value_size >= suffix_size && strcmp(value + value_size - suffix_size, suffix) == 0;
}

static int reconcile_temporary(int root_fd, const DurableState *state, int remove_valid, int *found) {
  DIR *directory;
  struct dirent *entry;
  int duplicate_fd, result = 0, count = 0;
  char nonce_hex[65], state_prefix[128], activation_name[128], rollback_name[128], accepted_name[160] = {0};
  unsigned long long nonce_word = 0;
  hex32(state->nonce, nonce_hex);
  memcpy(&nonce_word, state->nonce, sizeof(nonce_word));
  if (snprintf(state_prefix, sizeof(state_prefix), "%s.%s.", STATE_NAME, nonce_hex) >= (int)sizeof(state_prefix) ||
      snprintf(activation_name, sizeof(activation_name), ".sp-release-v2.%llu.%llx.%u.tmp",
               (unsigned long long)state->epoch, nonce_word, ROLE_ACTIVATE) >= (int)sizeof(activation_name) ||
      snprintf(rollback_name, sizeof(rollback_name), ".sp-release-v2.%llu.%llx.%u.tmp",
               (unsigned long long)state->epoch, nonce_word, ROLE_ROLLBACK) >= (int)sizeof(rollback_name)) return ENAMETOOLONG;
  duplicate_fd = openat(root_fd, ".", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  if (duplicate_fd < 0) return errno;
  directory = fdopendir(duplicate_fd);
  if (directory == NULL) { close(duplicate_fd); return errno; }
  for (;;) {
    const char *name;
    int valid = 0;
    errno = 0;
    entry = readdir(directory);
    if (entry == NULL) {
      if (errno != 0 && result == 0) result = errno;
      break;
    }
    name = entry->d_name;
    if (strncmp(name, ".sp-release-v2.", 15) != 0 || !has_suffix(name, ".tmp")) continue;
    ++count;
    if (count > 1) { result = EPROTO; break; }
    if (strncmp(name, state_prefix, strlen(state_prefix)) == 0) {
      DurableState temporary;
      char expected_state_name[160];
      int present = 0;
      result = read_exact_control_file(root_fd, name, &temporary, sizeof(temporary), &present);
      valid = result == 0 && present && state_transition_temp_allowed(state, &temporary);
      if (valid) {
        result = state_temporary_name(expected_state_name, sizeof(expected_state_name), nonce_hex,
                                      temporary.phase);
        if (result != 0) {
          valid = 0;
        } else if (strcmp(name, expected_state_name) != 0) {
          result = EPROTO;
          valid = 0;
        }
      }
    } else if (strcmp(name, activation_name) == 0 || strcmp(name, rollback_name) == 0) {
      uint8_t digest[32];
      uint32_t role = strcmp(name, activation_name) == 0 ? ROLE_ACTIVATE : ROLE_ROLLBACK;
      const uint8_t *expected = role == ROLE_ACTIVATE ? state->payload_digest : state->previous_digest;
      int phase_allows = role == ROLE_ACTIVATE ?
          (state->phase == PHASE_GO_COMMITTED || state->phase == PHASE_ACTIVATING ||
           (state->phase == PHASE_UNCERTAIN &&
            (state->recovery_from_phase == PHASE_GO_COMMITTED || state->recovery_from_phase == PHASE_ACTIVATING))) :
          (state->prior_present && (state->phase == PHASE_ROLLBACK_GO || state->phase == PHASE_RECOVERING_ROLLBACK ||
           (state->phase == PHASE_UNCERTAIN && state->recovery_from_phase == PHASE_ROLLBACK_GO)));
      result = phase_allows ? hash_named_regular(root_fd, name, digest) : EPROTO;
      valid = result == 0 && bytes_equal(digest, expected, 32);
    }
    if (!valid) { if (result == 0) result = EPROTO; break; }
    if (strlen(name) >= sizeof(accepted_name)) {
      result = ENAMETOOLONG;
      break;
    }
    memcpy(accepted_name, name, strlen(name) + 1);
  }
  if (closedir(directory) != 0 && result == 0) result = errno == 0 ? EIO : errno;
  if (result == 0 && remove_valid && count == 1) {
    if (accepted_name[0] == '\0') result = EPROTO;
    else if (unlinkat(root_fd, accepted_name, 0) != 0 || fsync(root_fd) != 0)
      result = errno == 0 ? EIO : errno;
  }
  *found = count != 0;
  return result;
}

static int release_debris_present(int root_fd, int *present) {
  DIR *directory;
  struct dirent *entry;
  int duplicate_fd = openat(root_fd, ".", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC), result = 0;
  *present = 0;
  if (duplicate_fd < 0) return errno;
  directory = fdopendir(duplicate_fd);
  if (directory == NULL) { close(duplicate_fd); return errno; }
  errno = 0;
  while ((entry = readdir(directory)) != NULL) {
    if (strncmp(entry->d_name, ".sp-release-v2.", 15) == 0 && has_suffix(entry->d_name, ".tmp")) {
      *present = 1;
      break;
    }
  }
  if (entry == NULL && errno != 0) result = errno;
  closedir(directory);
  return result;
}

static int orphan_protocol_entry_present(int root_fd, int *present) {
  DIR *directory;
  struct dirent *entry;
  int duplicate_fd = openat(root_fd, ".", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC), result = 0;
  *present = 0;
  if (duplicate_fd < 0) return errno;
  directory = fdopendir(duplicate_fd);
  if (directory == NULL) { close(duplicate_fd); return errno; }
  errno = 0;
  while ((entry = readdir(directory)) != NULL) {
    if (strncmp(entry->d_name, ".sp-release-v2.nonce.", 21) == 0 ||
        (strncmp(entry->d_name, ".sp-release-v2.", 15) == 0 && has_suffix(entry->d_name, ".tmp"))) {
      *present = 1;
      break;
    }
  }
  if (entry == NULL && errno != 0) result = errno;
  closedir(directory);
  return result;
}

static int acquire_existing_locks(int root_fd, int selector_operation, int fds[3],
                                  FdIdentity leases[2]) {
  int result;
  FdIdentity selector_identity;
  fds[0] = fds[1] = fds[2] = -1;
  result = open_existing_control(root_fd, SELECTOR_LOCK_NAME, &fds[0], &selector_identity);
  if (result == 0 && selector_identity.size != 0) result = EPERM;
  if (result != 0) return result;
  result = bounded_flock(fds[0], selector_operation);
  if (result == 0) result = open_existing_control(root_fd, ACTIVATE_LEASE_NAME, &fds[1], &leases[0]);
  if (result == 0) result = bounded_flock(fds[1], LOCK_EX);
  if (result == 0) result = open_existing_control(root_fd, ROLLBACK_LEASE_NAME, &fds[2], &leases[1]);
  if (result == 0) result = bounded_flock(fds[2], LOCK_EX);
  if (result == 0 && (!lease_identity_semantics_valid(&leases[0]) ||
                      !lease_identity_semantics_valid(&leases[1]))) result = EPERM;
  if (result == 0 && leases[0].dev == leases[1].dev && leases[0].ino == leases[1].ino) result = EPERM;
  if (result != 0) {
    if (fds[2] >= 0) close(fds[2]);
    if (fds[1] >= 0) close(fds[1]);
    if (fds[0] >= 0) close(fds[0]);
    fds[0] = fds[1] = fds[2] = -1;
  }
  return result;
}

static void close_lock_set(int fds[3]) {
  if (fds[2] >= 0) close(fds[2]);
  if (fds[1] >= 0) close(fds[1]);
  if (fds[0] >= 0) close(fds[0]);
}

static int recovery_decision(const DurableState *state, uint32_t current_kind, uint32_t *terminal_phase,
                             int *restore_prior) {
  uint32_t phase = state->phase == PHASE_UNCERTAIN ? state->recovery_from_phase : state->phase;
  *restore_prior = 0;
  if (state->phase == PHASE_RECOVERING_ROLLBACK) {
    if (current_is_prior(state, current_kind)) { *terminal_phase = PHASE_ROLLED_BACK; return 0; }
    if (current_kind == CURRENT_PAYLOAD) { *terminal_phase = PHASE_ROLLED_BACK; *restore_prior = 1; return 0; }
    return EBADMSG;
  }
  if (state_is_terminal(state->phase)) return EALREADY;
  if (phase == PHASE_PREPARED) {
    if (!current_is_prior(state, current_kind)) return EBADMSG;
    *terminal_phase = PHASE_ROLLED_BACK;
    return 0;
  }
  if (phase == PHASE_GO_COMMITTED || phase == PHASE_ACTIVATING) {
    if (current_kind == CURRENT_PAYLOAD) *terminal_phase = PHASE_COMMITTED;
    else if (current_is_prior(state, current_kind)) *terminal_phase = PHASE_ROLLED_BACK;
    else return EBADMSG;
    return 0;
  }
  if (phase == PHASE_ROLLBACK_GO) {
    *terminal_phase = PHASE_ROLLED_BACK;
    if (current_is_prior(state, current_kind)) return 0;
    if (current_kind == CURRENT_PAYLOAD) { *restore_prior = 1; return 0; }
    return EBADMSG;
  }
  if (phase == PHASE_COMMITTED && state->phase == PHASE_UNCERTAIN) {
    if (current_kind != CURRENT_PAYLOAD) return EBADMSG;
    *terminal_phase = PHASE_COMMITTED;
    return 0;
  }
  if (phase == PHASE_ROLLED_BACK && state->phase == PHASE_UNCERTAIN) {
    if (!current_is_prior(state, current_kind)) return EBADMSG;
    *terminal_phase = PHASE_ROLLED_BACK;
    return 0;
  }
  return EBADMSG;
}

static int read_valid_locked_state(int root_fd, const FdIdentity leases[2], DurableState *state,
                                   uint8_t state_digest[32]) {
  int present = 0, result = read_exact_control_file(root_fd, STATE_NAME, state, sizeof(*state), &present);
  if (result != 0 || !present || !state_semantics_valid(state)) return result == 0 ? EPROTO : result;
  CC_SHA256(state, (CC_LONG)sizeof(*state), state_digest);
  if (!bytes_equal(&state->activation_lease_identity, &leases[0], sizeof(FdIdentity)) ||
      !bytes_equal(&state->rollback_lease_identity, &leases[1], sizeof(FdIdentity))) return EBADMSG;
  result = validate_nonce_journal(root_fd, &leases[0], &leases[1]);
  if (result == 0) result = validate_state_marker(root_fd, state);
  return result;
}

static int reap_probe_exact(pid_t process, int expected_exit) {
  int status;
  pid_t waited;
  do {
    waited = waitpid(process, &status, 0);
  } while (waited < 0 && errno == EINTR);
  if (waited != process || !WIFEXITED(status) || WEXITSTATUS(status) != expected_exit) return EPROTO;
  return 0;
}

static int probe_boundary(void) {
  pid_t process;
  posix_spawnattr_t attributes;
  char *arguments[] = {"/usr/bin/true", NULL};
  struct sockaddr_in address;
  int code, network_fd;
  errno = 0;
  process = fork();
  if (process == 0) _exit(121);
  if (process > 0) return reap_probe_exact(process, 121) == 0 ? 1 : 10;
  if (errno != EPERM) return 1;
  errno = 0;
  process = vfork();
  if (process == 0) _exit(122);
  if (process > 0) return reap_probe_exact(process, 122) == 0 ? 2 : 11;
  if (errno != EPERM) return 2;
  if (posix_spawnattr_init(&attributes) != 0) return 3;
  code = posix_spawn(&process, "/usr/bin/true", NULL, &attributes, arguments, environ);
  (void)posix_spawnattr_destroy(&attributes);
  if (code == 0) return reap_probe_exact(process, 0) == 0 ? 4 : 12;
  if (code != EPERM) return 4;
  /* ENOTDIR below is intentionally not presented as a Sandbox errno.  The
   * preceding sandbox_check is the evidence that process-exec is denied; the
   * actual execve call proves the API path cannot accidentally execute. */
  if (sandbox_check(getpid(), "process-exec", 0) == 0) return 5;
  errno = 0;
  if (execve("/dev/null/spspy-v2-never-exec", arguments, environ) != -1 || errno != ENOTDIR) return 6;
  network_fd = socket(AF_INET, SOCK_STREAM, 0);
  if (network_fd >= 0) {
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET; address.sin_port = htons(9); address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    errno = 0;
    code = connect(network_fd, (const struct sockaddr *)&address, sizeof(address));
    close(network_fd);
    if (code != -1 || errno != EPERM) return 7;
  } else if (errno != EPERM) return 8;
  errno = 0;
  process = setsid();
  if (process == -1 && errno != EPERM) return 9;
  return 0;
}

static int install_seatbelt(uint8_t profile_digest[32]) {
  char *error = NULL;
  CC_SHA256(k_profile, (CC_LONG)strlen(k_profile), profile_digest);
  if (sandbox_init(k_profile, 0, &error) != 0) {
    if (error != NULL) sandbox_free_error(error);
    return EPERM;
  }
  return probe_boundary() == 0 ? 0 : EPERM;
}

static int make_control_pair(int sockets[2]) {
  int enabled = 1;
  if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) != 0) return errno;
  if (setsockopt(sockets[0], SOL_SOCKET, SO_NOSIGPIPE, &enabled, sizeof(enabled)) != 0 ||
      setsockopt(sockets[1], SOL_SOCKET, SO_NOSIGPIPE, &enabled, sizeof(enabled)) != 0) {
    int result = errno;
    close(sockets[0]); close(sockets[1]);
    return result;
  }
  return 0;
}

static int atomic_select(int root_fd, int source_fd, const uint8_t expected[32], uint64_t epoch,
                         const uint8_t nonce[32], uint32_t role, uint8_t observed_digest[32], int recovery) {
  char temporary[128];
  unsigned long long nonce_word = 0;
  FdIdentity source_before, source_after;
  CC_SHA256_CTX context;
  uint8_t buffer[65536];
  uint64_t total = 0;
  ssize_t amount;
  int output_fd = -1, result = 0;
  if (fd_identity(root_fd, &source_before, 1, 1) != 0 || safe_existing_regular(root_fd, "current.payload", 0, 1) != 0 ||
      payload_source_identity(source_fd, &source_before, recovery) != 0 || lseek(source_fd, 0, SEEK_SET) < 0) return EPERM;
  memcpy(&nonce_word, nonce, sizeof(nonce_word));
  if (snprintf(temporary, sizeof(temporary), ".sp-release-v2.%llu.%llx.%u.tmp",
               (unsigned long long)epoch, nonce_word, role) >= (int)sizeof(temporary)) return ENAMETOOLONG;
  output_fd = openat(root_fd, temporary, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC, 0600);
  if (output_fd < 0) return errno;
  if (fchmod(output_fd, 0600) != 0 || safe_control_fd(output_fd) != 0) { result = EPERM; goto failure; }
  CC_SHA256_Init(&context);
  while ((amount = read(source_fd, buffer, sizeof(buffer))) != 0) {
    size_t offset = 0;
    if (amount < 0) { if (errno == EINTR) continue; result = errno; goto failure; }
    total += (uint64_t)amount;
    if (total > MAX_PAYLOAD_BYTES) { result = EFBIG; goto failure; }
    CC_SHA256_Update(&context, buffer, (CC_LONG)amount);
    while (offset < (size_t)amount) {
      ssize_t written = write(output_fd, buffer + offset, (size_t)amount - offset);
      if (written < 0) { if (errno == EINTR) continue; result = errno; goto failure; }
      if (written == 0) { result = EIO; goto failure; }
      offset += (size_t)written;
    }
  }
  if (payload_source_identity(source_fd, &source_after, recovery) != 0 || total != source_before.size ||
      !bytes_equal(&source_before, &source_after, sizeof(source_before))) { result = EBUSY; goto failure; }
  CC_SHA256_Final(observed_digest, &context);
  if (!bytes_equal(observed_digest, expected, 32)) { result = EBADMSG; goto failure; }
  if (fsync(output_fd) != 0) { result = errno; goto failure; }
  if (close(output_fd) != 0) { result = errno; output_fd = -1; goto failure; }
  output_fd = -1;
  if (recovery) recovery_crash(4);
  if (renameat(root_fd, temporary, root_fd, "current.payload") != 0) return errno;
  if (recovery) recovery_crash(5);
  if (fsync(root_fd) != 0) return errno;
  if (recovery) recovery_crash(6);
  return 0;
failure:
  if (output_fd >= 0) close(output_fd);
  (void)unlinkat(root_fd, temporary, 0);
  (void)fsync(root_fd);
  return result == 0 ? EIO : result;
}

static int atomic_restore_absence(int root_fd, const uint8_t payload_digest[32], uint8_t observed_digest[32],
                                  int recovery) {
  uint8_t current_digest[32];
  int result;
  memset(observed_digest, 0, 32);
  result = named_absent_stable(root_fd, "current.payload");
  if (result == 0) return 0;
  if (result != EEXIST) return result;
  result = hash_named_regular(root_fd, "current.payload", current_digest);
  if (result != 0) return result;
  if (!bytes_equal(current_digest, payload_digest, 32)) return EBADMSG;
  if (recovery) recovery_crash(4);
  if (unlinkat(root_fd, "current.payload", 0) != 0) return errno;
  if (recovery) recovery_crash(5);
  if (fsync(root_fd) != 0) return errno;
  if (recovery) recovery_crash(6);
  return named_absent_stable(root_fd, "current.payload");
}

static void fill_common_ready(Ready *ready, uint32_t role, const Transaction *transaction, const uint8_t profile_digest[32]) {
  memset(ready, 0, sizeof(*ready));
  ready->magic = V2_MAGIC; ready->version = V2_VERSION; ready->role = role; ready->prior_present = transaction->prior_present;
  ready->pid = (int32_t)getpid(); ready->ppid = (int32_t)getppid(); ready->epoch = transaction->epoch;
  memcpy(ready->nonce, transaction->nonce, 32); memcpy(ready->payload_digest, transaction->payload_digest, 32);
  memcpy(ready->previous_digest, transaction->previous_digest, 32); memcpy(ready->authority_digest, transaction->authority_digest, 32);
  memcpy(ready->trusted_root_digest, transaction->trusted_root_digest, 32); memcpy(ready->envelope_digest, transaction->envelope_digest, 32);
  memcpy(ready->helper_digest, transaction->helper_digest, 32); memcpy(ready->profile_digest, profile_digest, 32);
  ready->root_identity = transaction->root_identity; ready->payload_identity = transaction->payload_identity;
  ready->previous_identity = transaction->previous_identity;
  ready->lease_identity = role == ROLE_ACTIVATE ? transaction->activation_lease_identity : transaction->rollback_lease_identity;
}

static int go_valid(const Go *go, uint32_t role, const Transaction *transaction) {
  return go->magic == V2_MAGIC && go->version == V2_VERSION && go->role == role && go->reserved == 0 &&
      go->prior_present == transaction->prior_present && go->epoch == transaction->epoch &&
      bytes_equal(go->nonce, transaction->nonce, 32) && bytes_equal(go->payload_digest, transaction->payload_digest, 32) &&
      bytes_equal(go->previous_digest, transaction->previous_digest, 32) && bytes_equal(go->authority_digest, transaction->authority_digest, 32) &&
      bytes_equal(go->trusted_root_digest, transaction->trusted_root_digest, 32) && bytes_equal(go->envelope_digest, transaction->envelope_digest, 32) &&
      bytes_equal(go->helper_digest, transaction->helper_digest, 32);
}

static void worker(uint32_t role, int control_fd, int lease_fd, const Transaction *transaction, uint64_t deadline_ns) {
  struct sigaction default_action;
  Ready ready;
  Go go;
  Result result;
  uint8_t profile_digest[32];
  const uint8_t *expected = role == ROLE_ACTIVATE ? transaction->payload_digest : transaction->previous_digest;
  int operation;
  memset(&default_action, 0, sizeof(default_action));
  default_action.sa_handler = SIG_DFL;
  (void)sigaction(SIGTERM, &default_action, NULL);
  (void)sigaction(SIGINT, &default_action, NULL);
  if (SP_TEST_WORKER_BEFORE_READY_ROLE == (int)role) _exit(70);
  if (bounded_flock(lease_fd, LOCK_EX) != 0) _exit(79);
  if (install_seatbelt(profile_digest) != 0) _exit(80);
  fill_common_ready(&ready, role, transaction, profile_digest);
  if (fd_identity(transaction->root_fd, &ready.root_identity, 1, 1) != 0 ||
      fd_identity(transaction->payload_fd, &ready.payload_identity, 0, 0) != 0 ||
      (transaction->prior_present && fd_identity(transaction->previous_fd, &ready.previous_identity, 0, 0) != 0) ||
      (!transaction->prior_present && !identity_zero(&ready.previous_identity)) ||
      fd_identity(lease_fd, &ready.lease_identity, 0, 1) != 0 ||
      write_full(control_fd, &ready, sizeof(ready)) != 0) _exit(80);
  if (SP_TEST_WORKER_AFTER_READY_ROLE == (int)role) _exit(71);
  if (SP_TEST_WORKER_STALL_ROLE == (int)role) for (;;) pause();
  if (read_until(control_fd, &go, sizeof(go), deadline_ns) != 0 || !go_valid(&go, role, transaction)) _exit(81);
  memset(&result, 0, sizeof(result));
  result.magic = V2_MAGIC; result.version = V2_VERSION; result.role = role;
  result.prior_present = transaction->prior_present; result.epoch = transaction->epoch;
  memcpy(result.nonce, transaction->nonce, 32); memcpy(result.expected_digest, expected, 32);
  memcpy(result.authority_digest, transaction->authority_digest, 32); memcpy(result.trusted_root_digest, transaction->trusted_root_digest, 32);
  memcpy(result.envelope_digest, transaction->envelope_digest, 32); memcpy(result.helper_digest, transaction->helper_digest, 32);
  operation = SP_TEST_OPERATION_FAILURE_ROLE == (int)role ? EIO :
      (role == ROLE_ACTIVATE ?
       atomic_select(transaction->root_fd, transaction->payload_fd, expected, transaction->epoch,
                     transaction->nonce, role, result.observed_digest, 0) :
       (transaction->prior_present ?
        atomic_select(transaction->root_fd, transaction->previous_fd, expected, transaction->epoch,
                      transaction->nonce, role, result.observed_digest, 0) :
        atomic_restore_absence(transaction->root_fd, transaction->payload_digest, result.observed_digest, 0)));
  if (operation == 0 && SP_TEST_OPERATION_FAILURE_AFTER_SELECT_ROLE == (int)role) operation = EIO;
  result.status = operation == 0 ? RESULT_OK : RESULT_FAILED;
  result.error_number = operation;
  if (write_full(control_fd, &result, sizeof(result)) != 0) _exit(82);
  _exit(operation == 0 ? 0 : 83);
}

static int register_child(int kqueue_fd, Child *child) {
  struct kevent change;
  if (SP_TEST_REGISTER_FAILURE) return EINVAL;
  EV_SET(&change, (uintptr_t)child->pid, EVFILT_PROC, EV_ADD | EV_ENABLE | EV_CLEAR, NOTE_EXIT, 0, NULL);
  if (kevent(kqueue_fd, &change, 1, NULL, 0, NULL) != 0) return errno;
  child->registered = 1;
  return 0;
}

static int child_exited_unreaped(Child *child) {
  siginfo_t information;
  memset(&information, 0, sizeof(information));
  if (waitid(P_PID, (id_t)child->pid, &information, WEXITED | WNOHANG | WNOWAIT) != 0) return -1;
  return information.si_pid == child->pid ? 1 : 0;
}

static void consume_kqueue_notice(int kqueue_fd, Child *child, int maximum_ms) {
  struct kevent event;
  struct timespec timeout;
  int result;
  if (!child->registered || maximum_ms <= 0) return;
  timeout.tv_sec = maximum_ms / 1000;
  timeout.tv_nsec = (long)(maximum_ms % 1000) * 1000000L;
  result = kevent(kqueue_fd, NULL, 0, &event, 1, &timeout);
  (void)result; /* Notification only. waitid/waitpid remain authoritative. */
}

static int wait_unreaped_until(int kqueue_fd, Child *child, uint64_t deadline_ns) {
  for (;;) {
    int exited = child_exited_unreaped(child);
    uint64_t now = monotonic_ns();
    if (exited == 1) return 0;
    if (exited < 0) return errno == 0 ? ECHILD : errno;
    if (g_stop_requested || now == 0 || now >= deadline_ns) return ETIMEDOUT;
    consume_kqueue_notice(kqueue_fd, child, (int)((deadline_ns - now) / 1000000ULL > 50 ? 50 : (deadline_ns - now) / 1000000ULL));
  }
}

static int reap_expected_exit(Child *child, int expected_exit) {
  int status;
  if (child->reaped) return ECHILD;
  if (waitpid(child->pid, &status, 0) != child->pid) return errno == 0 ? ECHILD : errno;
  child->reaped = 1;
  if (!WIFEXITED(status) || WEXITSTATUS(status) != expected_exit) return EPROTO;
  return 0;
}

static int cleanup_child(int kqueue_fd, Child *child) {
  uint64_t deadline;
  int exited, status, sent_signal = 0;
  if (child->pid <= 1 || child->reaped) return 0;
  if (child->control_fd >= 0) { close(child->control_fd); child->control_fd = -1; }
  deadline = monotonic_ns() + (uint64_t)SP_CLEANUP_TIMEOUT_MS * 1000000ULL / 3ULL;
  if (wait_unreaped_until(kqueue_fd, child, deadline) != 0) {
    exited = child_exited_unreaped(child);
    if (exited == 0) { if (kill(child->pid, SIGTERM) == 0) sent_signal = SIGTERM; }
    deadline = monotonic_ns() + (uint64_t)SP_CLEANUP_TIMEOUT_MS * 1000000ULL / 3ULL;
    if (wait_unreaped_until(kqueue_fd, child, deadline) != 0) {
      exited = child_exited_unreaped(child);
      if (exited == 0) { if (kill(child->pid, SIGKILL) == 0) sent_signal = SIGKILL; }
      deadline = monotonic_ns() + (uint64_t)SP_CLEANUP_TIMEOUT_MS * 1000000ULL / 3ULL;
      (void)wait_unreaped_until(kqueue_fd, child, deadline);
    }
  }
  if (waitpid(child->pid, &status, 0) != child->pid) return errno == 0 ? ECHILD : errno;
  child->reaped = 1;
  if (WIFEXITED(status)) {
    int code = WEXITSTATUS(status);
    return (code == 0 || code == 70 || code == 71 || code == 79 || code == 80 || code == 81 || code == 82 || code == 83) ? 0 : EPROTO;
  }
  if (WIFSIGNALED(status) && sent_signal != 0 && WTERMSIG(status) == sent_signal) return 0;
  return EPROTO;
}

static int ready_valid(const Ready *ready, const Child *child, const Transaction *transaction) {
  uint8_t profile_digest[32];
  CC_SHA256(k_profile, (CC_LONG)strlen(k_profile), profile_digest);
  return ready->magic == V2_MAGIC && ready->version == V2_VERSION && ready->role == child->role && ready->reserved == 0 &&
      ready->prior_present == transaction->prior_present &&
      ready->pid == child->pid && ready->ppid == getpid() && ready->epoch == transaction->epoch &&
      bytes_equal(ready->nonce, transaction->nonce, 32) && bytes_equal(ready->payload_digest, transaction->payload_digest, 32) &&
      bytes_equal(ready->previous_digest, transaction->previous_digest, 32) && bytes_equal(ready->authority_digest, transaction->authority_digest, 32) &&
      bytes_equal(ready->trusted_root_digest, transaction->trusted_root_digest, 32) && bytes_equal(ready->envelope_digest, transaction->envelope_digest, 32) &&
      bytes_equal(ready->helper_digest, transaction->helper_digest, 32) && bytes_equal(ready->profile_digest, profile_digest, 32) &&
      same_root(&ready->root_identity, &transaction->root_identity) &&
      bytes_equal(&ready->payload_identity, &transaction->payload_identity, sizeof(FdIdentity)) &&
      bytes_equal(&ready->previous_identity, &transaction->previous_identity, sizeof(FdIdentity)) &&
      bytes_equal(&ready->lease_identity,
                  child->role == ROLE_ACTIVATE ? &transaction->activation_lease_identity : &transaction->rollback_lease_identity,
                  sizeof(FdIdentity));
}

static void make_go(Go *go, const Child *child, const Transaction *transaction) {
  memset(go, 0, sizeof(*go));
  go->magic = V2_MAGIC; go->version = V2_VERSION; go->role = child->role;
  go->prior_present = transaction->prior_present; go->epoch = transaction->epoch;
  memcpy(go->nonce, transaction->nonce, 32); memcpy(go->payload_digest, transaction->payload_digest, 32);
  memcpy(go->previous_digest, transaction->previous_digest, 32); memcpy(go->authority_digest, transaction->authority_digest, 32);
  memcpy(go->trusted_root_digest, transaction->trusted_root_digest, 32); memcpy(go->envelope_digest, transaction->envelope_digest, 32);
  memcpy(go->helper_digest, transaction->helper_digest, 32);
}

static int result_valid(const Result *result, const Child *child, const Transaction *transaction) {
  const uint8_t *expected = child->role == ROLE_ACTIVATE ? transaction->payload_digest : transaction->previous_digest;
  if (result->magic != V2_MAGIC || result->version != V2_VERSION || result->role != child->role || result->reserved != 0 ||
      result->prior_present != transaction->prior_present || result->epoch != transaction->epoch ||
      !bytes_equal(result->nonce, transaction->nonce, 32) || !bytes_equal(result->expected_digest, expected, 32) ||
      !bytes_equal(result->authority_digest, transaction->authority_digest, 32) ||
      !bytes_equal(result->trusted_root_digest, transaction->trusted_root_digest, 32) ||
      !bytes_equal(result->envelope_digest, transaction->envelope_digest, 32) ||
      !bytes_equal(result->helper_digest, transaction->helper_digest, 32)) return 0;
  if (result->status == RESULT_OK) return result->error_number == 0 && bytes_equal(result->observed_digest, expected, 32);
  return result->status == RESULT_FAILED && result->error_number > 0;
}

static int spawn_worker(uint32_t role, Child *child, const Transaction *transaction, uint64_t deadline_ns,
                        int kqueue_fd, int lock_fd, int inherited_control_fd, int lease_fd, int other_lease_fd) {
  int sockets[2];
  pid_t process;
  int result = make_control_pair(sockets);
  if (result != 0) { close(lease_fd); return result; }
  process = fork();
  if (process < 0) { result = errno; close(sockets[0]); close(sockets[1]); close(lease_fd); return result; }
  if (process == 0) {
    close(sockets[0]);
    if (inherited_control_fd >= 0) close(inherited_control_fd);
    if (other_lease_fd >= 0) close(other_lease_fd);
    close(kqueue_fd); close(lock_fd); close(transaction->helper_fd);
    close(STDOUT_FILENO); close(STDERR_FILENO);
    worker(role, sockets[1], lease_fd, transaction, deadline_ns);
  }
  close(lease_fd);
  close(sockets[1]);
  child->pid = process; child->control_fd = sockets[0]; child->role = role; child->started_ns = monotonic_ns();
  return register_child(kqueue_fd, child);
}

static void fill_state(DurableState *state, uint32_t phase, const Transaction *transaction, const Child *activation,
                       const Child *rollback, const uint8_t profile_digest[32]) {
  memset(state, 0, sizeof(*state));
  state->magic = V2_MAGIC; state->version = V2_VERSION; state->phase = phase; state->epoch = transaction->epoch;
  state->prior_present = transaction->prior_present;
  state->activation_pid = activation->pid; state->rollback_pid = rollback->pid;
  state->activation_started_ns = activation->started_ns; state->rollback_started_ns = rollback->started_ns;
  memcpy(state->nonce, transaction->nonce, 32); memcpy(state->payload_digest, transaction->payload_digest, 32);
  memcpy(state->previous_digest, transaction->previous_digest, 32); memcpy(state->authority_digest, transaction->authority_digest, 32);
  memcpy(state->trusted_root_digest, transaction->trusted_root_digest, 32); memcpy(state->envelope_digest, transaction->envelope_digest, 32);
  memcpy(state->helper_digest, transaction->helper_digest, 32); memcpy(state->profile_digest, profile_digest, 32);
  state->activation_lease_identity = transaction->activation_lease_identity;
  state->rollback_lease_identity = transaction->rollback_lease_identity;
}

static int name_exists(int root_fd, const char *name, int *exists) {
  struct stat observed;
  if (fstatat(root_fd, name, &observed, AT_SYMLINK_NOFOLLOW) == 0) { *exists = 1; return 0; }
  if (errno == ENOENT) { *exists = 0; return 0; }
  return errno;
}

static int inspect_mode(int root_fd) {
  DurableState state;
  FdIdentity selector_identity, leases[2];
  uint8_t state_digest[32] = {0}, current_digest[32] = {0};
  int fds[3] = {-1, -1, -1}, present = 0, current_exists = 0, lease_a = 0, lease_r = 0;
  int debris = 0, temp_found = 0, result, restore_prior = 0;
  uint32_t current_kind = CURRENT_UNKNOWN, terminal_phase = 0;
  const char *classification = "BLOCKED";
  memset(&state, 0, sizeof(state));

  result = open_existing_control(root_fd, SELECTOR_LOCK_NAME, &fds[0], &selector_identity);
  if (result == ENOENT) {
    if (name_exists(root_fd, STATE_NAME, &present) != 0 || name_exists(root_fd, "current.payload", &current_exists) != 0 ||
        name_exists(root_fd, ACTIVATE_LEASE_NAME, &lease_a) != 0 || name_exists(root_fd, ROLLBACK_LEASE_NAME, &lease_r) != 0 ||
        orphan_protocol_entry_present(root_fd, &debris) != 0 || present || current_exists || lease_a || lease_r || debris) {
      classification = debris ? "DEBRIS" : "BLOCKED";
      current_kind = current_exists ? CURRENT_UNKNOWN : CURRENT_ABSENT;
    } else {
      classification = "FRESH";
      current_kind = CURRENT_ABSENT;
    }
    print_reconciliation("SP_RELEASE_V3_INSPECT", "INSPECT", classification, state_digest, &state,
                         current_kind, current_digest);
    return 0;
  }
  if (result != 0 || selector_identity.size != 0 || bounded_flock(fds[0], LOCK_SH) != 0) {
    if (fds[0] >= 0) close(fds[0]);
    print_reconciliation("SP_RELEASE_V3_INSPECT", "INSPECT", "BUSY", state_digest, &state,
                         CURRENT_UNKNOWN, current_digest);
    return 0;
  }
  result = open_existing_control(root_fd, ACTIVATE_LEASE_NAME, &fds[1], &leases[0]);
  if (result == 0) result = open_existing_control(root_fd, ROLLBACK_LEASE_NAME, &fds[2], &leases[1]);
  if (result == 0 && (!lease_identity_semantics_valid(&leases[0]) ||
                      !lease_identity_semantics_valid(&leases[1]))) result = EPERM;
  if (result != 0) {
    (void)name_exists(root_fd, STATE_NAME, &present);
    (void)name_exists(root_fd, "current.payload", &current_exists);
    classification = (!present && !current_exists && result == ENOENT) ? "FRESH" : "BLOCKED";
    current_kind = current_exists ? CURRENT_UNKNOWN : CURRENT_ABSENT;
    close_lock_set(fds);
    print_reconciliation("SP_RELEASE_V3_INSPECT", "INSPECT", classification, state_digest, &state,
                         current_kind, current_digest);
    return 0;
  }
  if (bounded_flock(fds[1], LOCK_EX) != 0 || bounded_flock(fds[2], LOCK_EX) != 0) {
    close_lock_set(fds);
    print_reconciliation("SP_RELEASE_V3_INSPECT", "INSPECT", "ACTIVE", state_digest, &state,
                         CURRENT_UNKNOWN, current_digest);
    return 0;
  }
  result = read_exact_control_file(root_fd, STATE_NAME, &state, sizeof(state), &present);
  if (result != 0 || !present) {
    (void)name_exists(root_fd, "current.payload", &current_exists);
    (void)release_debris_present(root_fd, &debris);
    classification = (result != 0 || current_exists ||
                      validate_nonce_journal(root_fd, &leases[0], &leases[1]) != 0) ?
        "BLOCKED" : (debris ? "DEBRIS" : "FRESH");
    current_kind = current_exists ? CURRENT_UNKNOWN : CURRENT_ABSENT;
    memset(&state, 0, sizeof(state));
    close_lock_set(fds);
    print_reconciliation("SP_RELEASE_V3_INSPECT", "INSPECT", classification, state_digest, &state,
                         current_kind, current_digest);
    return 0;
  }
  CC_SHA256(&state, (CC_LONG)sizeof(state), state_digest);
  if (!state_semantics_valid(&state) ||
      !bytes_equal(&state.activation_lease_identity, &leases[0], sizeof(FdIdentity)) ||
      !bytes_equal(&state.rollback_lease_identity, &leases[1], sizeof(FdIdentity)) ||
      validate_nonce_journal(root_fd, &leases[0], &leases[1]) != 0 || validate_state_marker(root_fd, &state) != 0) {
    classification = "BLOCKED";
  } else if (reconcile_temporary(root_fd, &state, 0, &temp_found) != 0) {
    classification = "BLOCKED";
  } else if (temp_found) {
    classification = "DEBRIS";
  } else if (classify_current(root_fd, &state, &current_kind, current_digest) != 0 ||
             current_kind == CURRENT_UNKNOWN) {
    classification = "BLOCKED";
  } else if (state.phase == PHASE_COMMITTED) {
    classification = current_kind == CURRENT_PAYLOAD ? "TERMINAL_COMMITTED" : "BLOCKED";
  } else if (state.phase == PHASE_ROLLED_BACK) {
    classification = current_is_prior(&state, current_kind) ? "TERMINAL_ROLLED_BACK" : "BLOCKED";
  } else if (recovery_decision(&state, current_kind, &terminal_phase, &restore_prior) != 0) {
    classification = "BLOCKED";
  } else if (restore_prior) {
    classification = "RECOVERABLE_ROLLBACK_REQUIRED";
  } else {
    classification = terminal_phase == PHASE_COMMITTED ? "RECOVERABLE_COMMITTED" : "RECOVERABLE_ROLLED_BACK";
  }
  close_lock_set(fds);
  print_reconciliation("SP_RELEASE_V3_INSPECT", "INSPECT", classification, state_digest, &state,
                       current_kind, current_digest);
  return 0;
}

static int recovery_fd_hash(int fd, uint8_t digest[32]) {
  struct stat before, after;
  CC_SHA256_CTX context;
  uint8_t buffer[65536];
  uint64_t total = 0;
  ssize_t amount;
  if (fd < 0 || fstat(fd, &before) != 0 || !S_ISREG(before.st_mode) || before.st_uid != getuid() ||
      before.st_nlink != 0 || (before.st_mode & 0777) != 0600 || before.st_size <= 0 ||
      (uint64_t)before.st_size > MAX_PAYLOAD_BYTES || lseek(fd, 0, SEEK_SET) < 0) return EPERM;
  CC_SHA256_Init(&context);
  while ((amount = read(fd, buffer, sizeof(buffer))) != 0) {
    if (amount < 0) { if (errno == EINTR) continue; return errno; }
    total += (uint64_t)amount;
    if (total > MAX_PAYLOAD_BYTES) return EFBIG;
    CC_SHA256_Update(&context, buffer, (CC_LONG)amount);
  }
  if (fstat(fd, &after) != 0 || total != (uint64_t)before.st_size || before.st_dev != after.st_dev ||
      before.st_ino != after.st_ino || before.st_size != after.st_size || before.st_mode != after.st_mode ||
      before.st_uid != after.st_uid || before.st_nlink != after.st_nlink ||
      before.st_mtimespec.tv_sec != after.st_mtimespec.tv_sec || before.st_mtimespec.tv_nsec != after.st_mtimespec.tv_nsec ||
      before.st_ctimespec.tv_sec != after.st_ctimespec.tv_sec || before.st_ctimespec.tv_nsec != after.st_ctimespec.tv_nsec)
    return EBUSY;
  CC_SHA256_Final(digest, &context);
  return lseek(fd, 0, SEEK_SET) < 0 ? errno : 0;
}

static int recover_mode(int root_fd, int previous_fd, uint32_t provided_prior_present,
                        const uint8_t expected_state_digest[32]) {
  DurableState state;
  FdIdentity leases[2];
  uint8_t state_digest[32], current_digest[32], previous_digest[32], observed_digest[32];
  uint32_t current_kind = CURRENT_UNKNOWN, terminal_phase = 0;
  int fds[3], result, restore_prior = 0, temp_found = 0;
  char nonce_hex[65];
  const char *classification;
  result = acquire_existing_locks(root_fd, LOCK_EX, fds, leases);
  if (result != 0) goto blocked;
  result = read_valid_locked_state(root_fd, leases, &state, state_digest);
  if (result != 0 || !bytes_equal(state_digest, expected_state_digest, 32) ||
      provided_prior_present != state.prior_present) goto blocked_locked;
  if (state.prior_present) {
    if (recovery_fd_hash(previous_fd, previous_digest) != 0 ||
        !bytes_equal(previous_digest, state.previous_digest, 32)) goto blocked_locked;
  } else if (previous_fd != -1) goto blocked_locked;
  result = reconcile_temporary(root_fd, &state, 0, &temp_found);
  if (result != 0 || classify_current(root_fd, &state, &current_kind, current_digest) != 0 ||
      current_kind == CURRENT_UNKNOWN || recovery_decision(&state, current_kind, &terminal_phase, &restore_prior) != 0)
    goto blocked_locked;
  if (temp_found && reconcile_temporary(root_fd, &state, 1, &temp_found) != 0) goto blocked_locked;
  hex32(state.nonce, nonce_hex);
  if (restore_prior) {
    if (state.phase != PHASE_RECOVERING_ROLLBACK) {
      state.phase = PHASE_RECOVERING_ROLLBACK;
      state.recovery_from_phase = PHASE_ROLLBACK_GO;
      if (write_recovery_state(root_fd, &state, nonce_hex) != 0) goto uncertain_locked;
    }
    if (state.prior_present) {
      result = atomic_select(root_fd, previous_fd, state.previous_digest, state.epoch, state.nonce,
                             ROLE_ROLLBACK, observed_digest, 1);
    } else {
      result = atomic_restore_absence(root_fd, state.payload_digest, observed_digest, 1);
    }
    if (result != 0 || classify_current(root_fd, &state, &current_kind, current_digest) != 0 ||
        !current_is_prior(&state, current_kind)) goto uncertain_locked;
    terminal_phase = PHASE_ROLLED_BACK;
  }
  state.phase = terminal_phase;
  state.recovery_from_phase = 0;
  if (write_recovery_state(root_fd, &state, nonce_hex) != 0) goto uncertain_locked;
  CC_SHA256(&state, (CC_LONG)sizeof(state), state_digest);
  if (classify_current(root_fd, &state, &current_kind, current_digest) != 0 ||
      (terminal_phase == PHASE_COMMITTED ? current_kind != CURRENT_PAYLOAD : !current_is_prior(&state, current_kind)))
    goto uncertain_locked;
  classification = terminal_phase == PHASE_COMMITTED ? "RECOVERED_COMMITTED" : "RECOVERED_ROLLED_BACK";
  close_lock_set(fds);
  print_reconciliation("SP_RELEASE_V3_RECOVER", "RECOVER", classification, state_digest, &state,
                       current_kind, current_digest);
  return 0;

uncertain_locked:
  close_lock_set(fds);
  puts("SP_RELEASE_V3 RECOVERY_UNCERTAIN");
  return 20;
blocked_locked:
  close_lock_set(fds);
blocked:
  puts("SP_RELEASE_V3 RECOVERY_BLOCKED");
  return 76;
}

static int nonce_is_unused(int root_fd, const uint8_t nonce[32]) {
  char nonce_hex[65], name[128];
  struct stat observed;
  hex32(nonce, nonce_hex);
  if (snprintf(name, sizeof(name), ".sp-release-v2.nonce.%s", nonce_hex) >= (int)sizeof(name)) return ENAMETOOLONG;
  if (fstatat(root_fd, name, &observed, AT_SYMLINK_NOFOLLOW) == 0) return EEXIST;
  return errno == ENOENT ? 0 : errno;
}

static int preflight_mode(Transaction *transaction, int selector_fd) {
  DurableState old_state;
  int old_present = 0, initial_present = 0, lease_fds[2] = {-1, -1}, temp_found = 0, result;
  memset(&old_state, 0, sizeof(old_state));
  result = locked_selector_valid(transaction->root_fd, selector_fd);
  if (result == 0) result = read_exact_control_file(transaction->root_fd, STATE_NAME, &old_state,
                                                    sizeof(old_state), &initial_present);
  if (result == 0 && !initial_present) result = named_absent_stable(transaction->root_fd, "current.payload");
  if (result == 0) result = initial_present ? prepare_existing_lease_files(transaction, lease_fds) :
                                             prepare_lease_files(transaction, lease_fds);
  if (result == 0) result = validate_old_state(transaction, &old_state, &old_present);
  if (result == 0 && old_present &&
      (!bytes_equal(&old_state.activation_lease_identity, &transaction->activation_lease_identity, sizeof(FdIdentity)) ||
       !bytes_equal(&old_state.rollback_lease_identity, &transaction->rollback_lease_identity, sizeof(FdIdentity)) ||
       validate_state_marker(transaction->root_fd, &old_state) != 0 ||
       reconcile_temporary(transaction->root_fd, &old_state, 0, &temp_found) != 0 || temp_found)) result = EOWNERDEAD;
  if (result == 0 && !old_present &&
      (release_debris_present(transaction->root_fd, &temp_found) != 0 || temp_found)) result = EOWNERDEAD;
  if (result == 0) result = validate_nonce_journal(transaction->root_fd,
                                                   &transaction->activation_lease_identity,
                                                   &transaction->rollback_lease_identity);
  if (result == 0) result = nonce_is_unused(transaction->root_fd, transaction->nonce);
  if (lease_fds[1] >= 0) close(lease_fds[1]);
  if (lease_fds[0] >= 0) close(lease_fds[0]);
  if (result != 0) return 76;
  puts("SP_RELEASE_V3 PREFLIGHT_OK");
  return 0;
}

int main(int argc, char **argv) {
  Transaction transaction;
  DurableState state, old_state;
  Ready activation_ready, rollback_ready;
  Result worker_result;
  Go go;
  Child activation = {0}, rollback = {0};
  struct sigaction stop_action, ignore_action;
  uint8_t actual_helper_digest[32], actual_payload_digest[32], actual_previous_digest[32], profile_digest[32];
  uint64_t deadline_ns;
  int lock_fd = -1, kqueue_fd = -1, old_present = 0, state_started = 0, result = 64, code;
  int lease_fds[2] = {-1, -1}, temp_found = 0, preflight_present = 0;
  uint32_t last_durable_phase = 0;
  const char *nonce_hex;

  memset(&transaction, 0, sizeof(transaction)); memset(&state, 0, sizeof(state)); memset(&old_state, 0, sizeof(old_state));
  activation.control_fd = -1; rollback.control_fd = -1;
  if (argc == 12 && strcmp(argv[1], "--preflight") == 0) {
    if (parse_fd(argv[2], &transaction.root_fd) != 0 || parse_fd(argv[3], &lock_fd) != 0 ||
        parse_optional_fd(argv[4], &transaction.previous_fd) != 0 || parse_present(argv[5], &transaction.prior_present) != 0 ||
        parse_epoch(argv[6], &transaction.epoch) != 0 || parse_hex32(argv[7], transaction.nonce) != 0 ||
        parse_hex32(argv[8], transaction.payload_digest) != 0 || parse_hex32(argv[9], transaction.previous_digest) != 0 ||
        parse_fd(argv[10], &transaction.helper_fd) != 0 || parse_hex32(argv[11], transaction.helper_digest) != 0 ||
        lock_fd <= STDERR_FILENO || transaction.helper_fd <= STDERR_FILENO ||
        transaction.root_fd == lock_fd || transaction.root_fd == transaction.helper_fd || lock_fd == transaction.helper_fd ||
        (transaction.prior_present && (transaction.previous_fd == transaction.root_fd ||
         transaction.previous_fd == lock_fd || transaction.previous_fd == transaction.helper_fd)) ||
        (transaction.prior_present ? transaction.previous_fd < 0 : transaction.previous_fd != -1) ||
        bytes_zero(transaction.nonce, 32) || bytes_zero(transaction.payload_digest, 32) ||
        !prior_semantics_valid(transaction.prior_present, transaction.previous_digest) ||
        (transaction.prior_present && bytes_equal(transaction.payload_digest, transaction.previous_digest, 32)) ||
        bytes_zero(transaction.helper_digest, 32) || hash_bound_helper(argv[0], transaction.helper_fd, actual_helper_digest) != 0 ||
        !bytes_equal(actual_helper_digest, transaction.helper_digest, 32) ||
        fd_identity(transaction.root_fd, &transaction.root_identity, 1, 1) != 0 ||
        (transaction.prior_present &&
         (hash_fd(transaction.previous_fd, actual_previous_digest, &transaction.previous_identity) != 0 ||
          !bytes_equal(actual_previous_digest, transaction.previous_digest, 32)))) return 64;
    return preflight_mode(&transaction, lock_fd);
  }
  if (argc == 5 && strcmp(argv[1], "--inspect") == 0) {
    if (parse_fd(argv[2], &transaction.root_fd) != 0 || parse_fd(argv[3], &transaction.helper_fd) != 0 ||
        parse_hex32(argv[4], transaction.helper_digest) != 0 || transaction.helper_fd <= STDERR_FILENO ||
        transaction.helper_fd == transaction.root_fd || bytes_zero(transaction.helper_digest, 32) ||
        hash_bound_helper(argv[0], transaction.helper_fd, actual_helper_digest) != 0 ||
        !bytes_equal(actual_helper_digest, transaction.helper_digest, 32) ||
        fd_identity(transaction.root_fd, &transaction.root_identity, 1, 1) != 0) return 64;
    return inspect_mode(transaction.root_fd);
  }
  if (argc == 8 && strcmp(argv[1], "--recover") == 0) {
    uint8_t expected_state_digest[32];
    if (parse_fd(argv[2], &transaction.root_fd) != 0 || parse_optional_fd(argv[3], &transaction.previous_fd) != 0 ||
        parse_present(argv[4], &transaction.prior_present) != 0 || parse_hex32(argv[5], expected_state_digest) != 0 ||
        parse_fd(argv[6], &transaction.helper_fd) != 0 || parse_hex32(argv[7], transaction.helper_digest) != 0 ||
        transaction.helper_fd <= STDERR_FILENO || transaction.helper_fd == transaction.root_fd ||
        (transaction.prior_present && transaction.helper_fd == transaction.previous_fd) || bytes_zero(expected_state_digest, 32) ||
        bytes_zero(transaction.helper_digest, 32) ||
        (transaction.prior_present ? transaction.previous_fd < 0 : transaction.previous_fd != -1) ||
        hash_bound_helper(argv[0], transaction.helper_fd, actual_helper_digest) != 0 ||
        !bytes_equal(actual_helper_digest, transaction.helper_digest, 32) ||
        fd_identity(transaction.root_fd, &transaction.root_identity, 1, 1) != 0) return 64;
    return recover_mode(transaction.root_fd, transaction.previous_fd, transaction.prior_present, expected_state_digest);
  }
  if (argc != 16 || strcmp(argv[1], "--sealed-parent") != 0 || parse_fd(argv[2], &transaction.root_fd) != 0 ||
      parse_fd(argv[3], &lock_fd) != 0 || parse_fd(argv[4], &transaction.payload_fd) != 0 ||
      parse_optional_fd(argv[5], &transaction.previous_fd) != 0 || parse_present(argv[6], &transaction.prior_present) != 0 ||
      parse_epoch(argv[7], &transaction.epoch) != 0 || parse_hex32(argv[8], transaction.nonce) != 0 ||
      parse_hex32(argv[9], transaction.payload_digest) != 0 || parse_hex32(argv[10], transaction.previous_digest) != 0 ||
      parse_hex32(argv[11], transaction.authority_digest) != 0 || parse_hex32(argv[12], transaction.trusted_root_digest) != 0 ||
      parse_hex32(argv[13], transaction.envelope_digest) != 0 || parse_fd(argv[14], &transaction.helper_fd) != 0 ||
      parse_hex32(argv[15], transaction.helper_digest) != 0 || lock_fd <= STDERR_FILENO ||
      transaction.helper_fd <= STDERR_FILENO || transaction.helper_fd == transaction.root_fd ||
      transaction.helper_fd == transaction.payload_fd || (transaction.prior_present && transaction.helper_fd == transaction.previous_fd) ||
      transaction.helper_fd == lock_fd || transaction.root_fd == lock_fd || transaction.payload_fd == lock_fd ||
      transaction.root_fd == transaction.payload_fd || (transaction.prior_present &&
       (transaction.root_fd == transaction.previous_fd || transaction.payload_fd == transaction.previous_fd ||
        lock_fd == transaction.previous_fd)) ||
      bytes_zero(transaction.nonce, 32) ||
      bytes_zero(transaction.payload_digest, 32) || !prior_semantics_valid(transaction.prior_present, transaction.previous_digest) ||
      (transaction.prior_present ? transaction.previous_fd < 0 : transaction.previous_fd != -1) ||
      (transaction.prior_present && bytes_equal(transaction.payload_digest, transaction.previous_digest, 32)) ||
      bytes_zero(transaction.authority_digest, 32) || bytes_zero(transaction.trusted_root_digest, 32) ||
      bytes_zero(transaction.envelope_digest, 32) || bytes_zero(transaction.helper_digest, 32)) return 64;
  nonce_hex = argv[8];
  memset(&ignore_action, 0, sizeof(ignore_action)); ignore_action.sa_handler = SIG_IGN;
  memset(&stop_action, 0, sizeof(stop_action)); stop_action.sa_handler = stop_handler;
  if (sigaction(SIGPIPE, &ignore_action, NULL) != 0 || sigaction(SIGTERM, &stop_action, NULL) != 0 ||
      sigaction(SIGINT, &stop_action, NULL) != 0) return 64;
  if (hash_bound_helper(argv[0], transaction.helper_fd, actual_helper_digest) != 0 || !bytes_equal(actual_helper_digest, transaction.helper_digest, 32) ||
      fd_identity(transaction.root_fd, &transaction.root_identity, 1, 1) != 0 ||
      hash_fd(transaction.payload_fd, actual_payload_digest, &transaction.payload_identity) != 0 ||
      !bytes_equal(actual_payload_digest, transaction.payload_digest, 32) ||
      (transaction.prior_present &&
       (hash_fd(transaction.previous_fd, actual_previous_digest, &transaction.previous_identity) != 0 ||
        !bytes_equal(actual_previous_digest, transaction.previous_digest, 32))) ||
      (!transaction.prior_present && !identity_zero(&transaction.previous_identity))) return 64;

  code = read_exact_control_file(transaction.root_fd, STATE_NAME, &old_state, sizeof(old_state), &preflight_present);
  if (code == 0 && !preflight_present && transaction.prior_present) return 64;

  code = locked_selector_valid(transaction.root_fd, lock_fd);
  if (code != 0) return 75;
  code = prepare_existing_lease_files(&transaction, lease_fds);
  if (code != 0) { puts("SP_RELEASE_V3 RECOVERY_REQUIRED"); result = 76; goto done; }
  code = validate_old_state(&transaction, &old_state, &old_present);
  if (code != 0) {
    puts("SP_RELEASE_V3 RECOVERY_REQUIRED"); result = 76; goto done;
  }
  if (old_present && (!bytes_equal(&old_state.activation_lease_identity, &transaction.activation_lease_identity, sizeof(FdIdentity)) ||
      !bytes_equal(&old_state.rollback_lease_identity, &transaction.rollback_lease_identity, sizeof(FdIdentity)) ||
      validate_state_marker(transaction.root_fd, &old_state) != 0 ||
      reconcile_temporary(transaction.root_fd, &old_state, 0, &temp_found) != 0 || temp_found)) {
    puts("SP_RELEASE_V3 RECOVERY_REQUIRED"); result = 76; goto done;
  }
  if (!old_present && (release_debris_present(transaction.root_fd, &temp_found) != 0 || temp_found)) {
    puts("SP_RELEASE_V3 RECOVERY_REQUIRED"); result = 76; goto done;
  }
  code = create_nonce_marker(transaction.root_fd, &transaction, nonce_hex);
  if (code != 0) { puts("SP_RELEASE_V3 RECOVERY_REQUIRED"); result = 77; goto done; }
  kqueue_fd = kqueue();
  if (kqueue_fd < 0) { puts("SP_RELEASE_V2 UNCERTAIN"); result = 20; goto done; }
  deadline_ns = monotonic_ns() + (uint64_t)SP_TOTAL_TIMEOUT_MS * 1000000ULL;
  code = spawn_worker(ROLE_ACTIVATE, &activation, &transaction, deadline_ns, kqueue_fd, lock_fd, -1,
                      lease_fds[0], lease_fds[1]);
  lease_fds[0] = -1;
  if (code != 0) goto uncertain;
  if (read_until(activation.control_fd, &activation_ready, sizeof(activation_ready), deadline_ns) != 0 ||
      !ready_valid(&activation_ready, &activation, &transaction)) goto uncertain;
  code = spawn_worker(ROLE_ROLLBACK, &rollback, &transaction, deadline_ns, kqueue_fd, lock_fd, activation.control_fd,
                      lease_fds[1], -1);
  lease_fds[1] = -1;
  if (code != 0) goto uncertain;
  if (read_until(rollback.control_fd, &rollback_ready, sizeof(rollback_ready), deadline_ns) != 0 ||
      !ready_valid(&rollback_ready, &rollback, &transaction) ||
      !bytes_equal(activation_ready.profile_digest, rollback_ready.profile_digest, 32) ||
      named_identity_matches(transaction.root_fd, ACTIVATE_LEASE_NAME, &transaction.activation_lease_identity) != 0 ||
      named_identity_matches(transaction.root_fd, ROLLBACK_LEASE_NAME, &transaction.rollback_lease_identity) != 0) goto uncertain;
  memcpy(profile_digest, activation_ready.profile_digest, 32);

  fill_state(&state, PHASE_PREPARED, &transaction, &activation, &rollback, profile_digest);
  if (write_state(transaction.root_fd, &state, nonce_hex) != 0) goto uncertain;
  state_started = 1;
  last_durable_phase = PHASE_PREPARED;
  state.phase = PHASE_GO_COMMITTED;
  if (write_state(transaction.root_fd, &state, nonce_hex) != 0) goto uncertain;
  last_durable_phase = PHASE_GO_COMMITTED;
  make_go(&go, &activation, &transaction);
  if (write_full(activation.control_fd, &go, sizeof(go)) != 0) goto uncertain;
  state.phase = PHASE_ACTIVATING;
  if (write_state(transaction.root_fd, &state, nonce_hex) != 0) goto uncertain;
  last_durable_phase = PHASE_ACTIVATING;
  if (read_until(activation.control_fd, &worker_result, sizeof(worker_result), deadline_ns) != 0 ||
      !result_valid(&worker_result, &activation, &transaction) ||
      wait_unreaped_until(kqueue_fd, &activation, deadline_ns) != 0 ||
      reap_expected_exit(&activation, worker_result.status == RESULT_OK ? 0 : 83) != 0) goto uncertain;
  close(activation.control_fd); activation.control_fd = -1;
  if (worker_result.status == RESULT_OK) {
    state.phase = PHASE_COMMITTED;
    if (write_state(transaction.root_fd, &state, nonce_hex) != 0) goto uncertain;
    last_durable_phase = PHASE_COMMITTED;
    if (cleanup_child(kqueue_fd, &rollback) != 0) goto uncertain;
    puts("SP_RELEASE_V3 COMMITTED"); result = 0; goto done;
  }

  state.phase = PHASE_ROLLBACK_GO;
  if (write_state(transaction.root_fd, &state, nonce_hex) != 0) goto uncertain;
  last_durable_phase = PHASE_ROLLBACK_GO;
  make_go(&go, &rollback, &transaction);
  if (write_full(rollback.control_fd, &go, sizeof(go)) != 0 ||
      read_until(rollback.control_fd, &worker_result, sizeof(worker_result), deadline_ns) != 0 ||
      !result_valid(&worker_result, &rollback, &transaction) || worker_result.status != RESULT_OK ||
      wait_unreaped_until(kqueue_fd, &rollback, deadline_ns) != 0 || reap_expected_exit(&rollback, 0) != 0) goto uncertain;
  close(rollback.control_fd); rollback.control_fd = -1;
  state.phase = PHASE_ROLLED_BACK;
  if (write_state(transaction.root_fd, &state, nonce_hex) != 0) goto uncertain;
  last_durable_phase = PHASE_ROLLED_BACK;
  puts("SP_RELEASE_V3 ROLLED_BACK"); result = 10; goto done;

uncertain:
  if (state_started) {
    state.phase = PHASE_UNCERTAIN;
    state.recovery_from_phase = last_durable_phase;
    (void)write_state(transaction.root_fd, &state, nonce_hex);
  }
  (void)cleanup_child(kqueue_fd, &activation);
  (void)cleanup_child(kqueue_fd, &rollback);
  puts("SP_RELEASE_V3 UNCERTAIN"); result = 20;
done:
  if (activation.pid > 1 && !activation.reaped) (void)cleanup_child(kqueue_fd, &activation);
  if (rollback.pid > 1 && !rollback.reaped) (void)cleanup_child(kqueue_fd, &rollback);
  if (activation.control_fd >= 0) close(activation.control_fd);
  if (rollback.control_fd >= 0) close(rollback.control_fd);
  if (kqueue_fd >= 0) close(kqueue_fd);
  if (lease_fds[1] >= 0) close(lease_fds[1]);
  if (lease_fds[0] >= 0) close(lease_fds[0]);
  if (lock_fd >= 0) close(lock_fd);
  return result;
}
#pragma clang diagnostic pop
