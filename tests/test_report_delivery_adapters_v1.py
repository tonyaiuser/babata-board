import base64
import json
import os
import stat
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest import mock

from scripts import report_delivery_adapters_v1 as adapters
from scripts import report_delivery_outbox_v1 as outbox


def record(**extra):
    values = dict(repository="owner/repo", ref="refs/heads/topic", path="reports/x.png",
                  image_bytes=b"image", primary_payload_bytes=b"primary",
                  changed_handles=("a",), primary_handles=("a",))
    values.update(extra)
    return outbox.create_record(**values)


def canary_record(**extra):
    values = dict(repository="synthetic/report-delivery-canary",
                  ref="refs/heads/report-delivery-canary",
                  path="synthetic/report-delivery/canary.png")
    values.update(extra)
    return record(**values)


class FakeDelivery:
    def __init__(self, response=None): self.calls = []; self.response = response or {"status": 200, "ack": 1}
    def send(self, channel, payload, **kwargs): self.calls.append((channel, payload, kwargs)); return self.response


class FakeDedupe:
    def __init__(self, result=None): self.calls = []; self.result = result
    def apply(self, outbox_id, digest, handles):
        self.calls.append((outbox_id, digest, handles))
        return {"outbox_id": outbox_id, "digest": digest, "outcome": "applied"} if self.result is None else self.result


class FakeGithub:
    base = "a" * 40
    base_tree = "b" * 40
    blob = "c" * 40
    candidate_tree = "d" * 40
    candidate = "e" * 40
    old_blob = "f" * 40

    def __init__(self, image=b"image", *, existing=None, patch_status=200,
                 patch_raises=False, patch_applies=True, existing_blob_status=200,
                 candidate_parent=None, verify_blob=None, post_patch_blob=None,
                 target_path="reports/x.png"):
        self.image = image
        self.existing = existing
        self.patch_status = patch_status
        self.patch_raises = patch_raises
        self.patch_applies = patch_applies
        self.existing_blob_status = existing_blob_status
        self.candidate_parent = self.base if candidate_parent is None else candidate_parent
        self.verify_blob = image if verify_blob is None else verify_blob
        self.post_patch_blob = self.verify_blob if post_patch_blob is None else post_patch_blob
        self.target_path = target_path
        self.tip = self.base
        self.calls = []

    def request(self, method, path, body=None):
        self.calls.append((method, path, body))
        ref_path = "/repos/owner/repo/git/ref/heads/topic"
        if method == "GET" and path == ref_path:
            return {"status": 200, "body": {"object": {"sha": self.tip}}}
        if method == "GET" and path.endswith("/commits/" + self.base):
            return {"status": 200, "body": {"tree": {"sha": self.base_tree}, "parents": []}}
        if method == "GET" and path.endswith("/commits/" + self.candidate):
            return {"status": 200, "body": {"tree": {"sha": self.candidate_tree},
                                              "parents": [{"sha": self.candidate_parent}]}}
        if method == "GET" and ("/trees/" + self.base_tree) in path:
            entries = [] if self.existing is None else [{"path": self.target_path, "sha": self.old_blob}]
            return {"status": 200, "body": {"tree": entries}}
        if method == "GET" and ("/trees/" + self.candidate_tree) in path:
            return {"status": 200, "body": {"tree": [{"path": self.target_path, "sha": self.blob}]}}
        if method == "GET" and path.endswith("/blobs/" + self.old_blob):
            content = base64.b64encode(self.existing or b"").decode("ascii")
            return {"status": self.existing_blob_status, "body": {"encoding": "base64", "content": content}}
        if method == "GET" and path.endswith("/blobs/" + self.blob):
            blob_value = self.post_patch_blob if self.patch_calls else self.verify_blob
            return {"status": 200, "body": {"encoding": "base64",
                                              "content": base64.b64encode(blob_value).decode("ascii")}}
        if method == "POST" and path.endswith("/blobs"):
            return {"status": 201, "body": {"sha": self.blob}}
        if method == "POST" and path.endswith("/trees"):
            return {"status": 201, "body": {"sha": self.candidate_tree}}
        if method == "POST" and path.endswith("/commits"):
            return {"status": 201, "body": {"sha": self.candidate}}
        if method == "PATCH" and path == "/repos/owner/repo/git/refs/heads/topic":
            if self.patch_applies:
                self.tip = self.candidate
            if self.patch_raises:
                raise TimeoutError("response lost")
            return {"status": self.patch_status, "body": {}}
        return {"status": 500, "body": {}}

    @property
    def patch_calls(self):
        return [call for call in self.calls if call[0] == "PATCH"]


class AdapterStoreTests(unittest.TestCase):
    def setUp(self): self.temp = tempfile.TemporaryDirectory()
    def tearDown(self): self.temp.cleanup()
    @property
    def root(self): return self.temp.name + "/store"
    def test_initialize_permissions_and_runtime_no_repair(self):
        adapters.initialize_store(self.root)
        self.assertEqual(stat.S_IMODE(os.stat(self.root).st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(os.stat(self.root + "/.report-delivery.lock").st_mode), 0o600)
        os.chmod(self.root + "/receipts", 0o755)
        with self.assertRaises(adapters.StoreIntegrityError): adapters.open_transaction(self.root)

    def test_initialize_verifies_lock_binding_around_cleanup(self):
        adapters.initialize_store(self.root)
        verifier = adapters._verify_lock_binding
        with mock.patch.object(adapters, "_verify_lock_binding", wraps=verifier) as probe:
            adapters.initialize_store(self.root)
        self.assertGreaterEqual(probe.call_count, 11)

    def test_initialize_holds_first_created_lock_through_cleanup_fsync_and_unlock(self):
        events = []
        lockfd = None
        rootfd = None
        real_open, real_close = os.open, os.close
        real_mkdir, real_listdir = os.mkdir, os.listdir
        real_fsync, real_flock = os.fsync, adapters.fcntl.flock

        def tracked_open(path, flags, mode=0o777, *, dir_fd=None):
            nonlocal lockfd, rootfd
            fd = real_open(path, flags, mode, dir_fd=dir_fd)
            if dir_fd is None and os.fspath(path) == self.root:
                rootfd = fd
            if path == adapters._LOCK and dir_fd is not None:
                self.assertIsNone(lockfd)
                lockfd = fd
                events.append(("lock_open", fd, flags))
            return fd

        def tracked_close(fd):
            if fd == lockfd:
                events.append(("lock_close", fd))
            return real_close(fd)

        def tracked_mkdir(path, mode=0o777, *, dir_fd=None):
            if path == adapters._RECEIPTS and dir_fd == rootfd:
                events.append(("receipts_mkdir", lockfd))
            return real_mkdir(path, mode, dir_fd=dir_fd)

        def tracked_listdir(path):
            if path == rootfd:
                events.append(("cleanup_listdir", lockfd))
            return real_listdir(path)

        def tracked_fsync(fd):
            if fd == rootfd:
                events.append(("root_fsync", lockfd))
            return real_fsync(fd)

        def tracked_flock(fd, operation):
            if fd == lockfd:
                events.append(("unlock" if operation == adapters.fcntl.LOCK_UN else "lock", fd))
            return real_flock(fd, operation)

        with mock.patch.object(adapters.os, "open", side_effect=tracked_open), \
             mock.patch.object(adapters.os, "close", side_effect=tracked_close), \
             mock.patch.object(adapters.os, "mkdir", side_effect=tracked_mkdir), \
             mock.patch.object(adapters.os, "listdir", side_effect=tracked_listdir), \
             mock.patch.object(adapters.os, "fsync", side_effect=tracked_fsync), \
             mock.patch.object(adapters.fcntl, "flock", side_effect=tracked_flock):
            adapters.initialize_store(self.root)

        labels = [event[0] for event in events]
        flags = events[labels.index("lock_open")][2]
        required = (os.O_RDWR | os.O_CREAT | os.O_EXCL
                    | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
        self.assertEqual(flags & required, required)
        self.assertLess(labels.index("lock_open"), labels.index("lock"))
        self.assertLess(labels.index("lock"), labels.index("receipts_mkdir"))
        self.assertLess(labels.index("receipts_mkdir"), labels.index("cleanup_listdir"))
        self.assertLess(labels.index("cleanup_listdir"), labels.index("root_fsync"))
        self.assertLess(labels.index("root_fsync"), labels.index("unlock"))
        self.assertLess(labels.index("unlock"), labels.index("lock_close"))

    def test_initialize_fences_lock_and_root_retargets_before_any_cleanup(self):
        for identity in ("lock", "root"):
            for boundary in ("before_flock", "listdir", "temp_open", "before_unlink"):
                with self.subTest(identity=identity, boundary=boundary), tempfile.TemporaryDirectory() as temp:
                    root = str(Path(temp) / "store")
                    adapters.initialize_store(root)
                    stale = Path(root) / (".active.tmp." + "1" * 32)
                    stale.write_bytes(b"stale")
                    os.chmod(stale, 0o600)
                    lock = Path(root) / adapters._LOCK
                    displaced = Path(root + "-old")
                    old_lock = Path(root) / "old-boundary-lock"
                    attacked = False

                    def retarget():
                        nonlocal attacked
                        if attacked:
                            return
                        attacked = True
                        if identity == "lock":
                            lock.rename(old_lock)
                            lock.write_bytes(b"")
                            os.chmod(lock, 0o600)
                        else:
                            Path(root).rename(displaced)
                            Path(root).mkdir(mode=0o700)

                    real_flock = adapters.fcntl.flock
                    real_listdir = os.listdir
                    real_open = os.open
                    real_stat = os.stat
                    temp_stats = 0

                    def attack_flock(fd, operation):
                        if boundary == "before_flock" and operation & adapters.fcntl.LOCK_EX:
                            retarget()
                        return real_flock(fd, operation)

                    def attack_listdir(path):
                        result = real_listdir(path)
                        if boundary == "listdir":
                            retarget()
                        return result

                    def attack_open(path, flags, mode=0o777, *, dir_fd=None):
                        fd = real_open(path, flags, mode, dir_fd=dir_fd)
                        if boundary == "temp_open" and path == stale.name:
                            retarget()
                        return fd

                    def attack_stat(path, *args, **kwargs):
                        nonlocal temp_stats
                        result = real_stat(path, *args, **kwargs)
                        if boundary == "before_unlink" and path == stale.name:
                            temp_stats += 1
                            if temp_stats == 2:
                                retarget()
                        return result

                    with mock.patch.object(adapters.fcntl, "flock", side_effect=attack_flock), \
                         mock.patch.object(adapters.os, "listdir", side_effect=attack_listdir), \
                         mock.patch.object(adapters.os, "open", side_effect=attack_open), \
                         mock.patch.object(adapters.os, "stat", side_effect=attack_stat):
                        with self.assertRaises(adapters.StoreIntegrityError):
                            adapters.initialize_store(root)
                    stale_after = ((displaced if identity == "root" else Path(root)) / stale.name)
                    self.assertTrue(stale_after.exists())

    def test_initialize_lock_retarget_recreate_rejects_before_cleanup(self):
        adapters.initialize_store(self.root)
        lock = Path(self.root) / ".report-delivery.lock"
        displaced = Path(self.root) / "old-initialize-lock"
        stale = Path(self.root) / (".active.tmp." + "0" * 32)
        stale.write_bytes(b"stale")
        os.chmod(stale, 0o600)
        original_inode = lock.stat().st_ino
        real_flock = adapters.fcntl.flock
        retargeted = False

        def flock_then_retarget(fd, operation):
            nonlocal retargeted
            result = real_flock(fd, operation)
            if not retargeted and operation & adapters.fcntl.LOCK_EX:
                retargeted = True
                lock.rename(displaced)
                lock.write_bytes(b"")
                os.chmod(lock, 0o600)
            return result

        with mock.patch.object(adapters.fcntl, "flock", side_effect=flock_then_retarget):
            with self.assertRaises(adapters.StoreIntegrityError):
                adapters.initialize_store(self.root)
        self.assertTrue(stale.exists())
        self.assertEqual(displaced.stat().st_ino, original_inode)
        self.assertNotEqual(lock.stat().st_ino, original_inode)
        self.assertEqual(stat.S_IMODE(lock.stat().st_mode), 0o600)

    def test_runtime_cleanup_fences_lock_and_root_retargets(self):
        for identity in ("lock", "root"):
            for boundary in ("before_flock", "listdir", "temp_open", "before_unlink"):
                with self.subTest(identity=identity, boundary=boundary), tempfile.TemporaryDirectory() as temp:
                    root = str(Path(temp) / "store")
                    adapters.initialize_store(root)
                    stale = Path(root) / (".active.tmp." + "2" * 32)
                    stale.write_bytes(b"stale")
                    os.chmod(stale, 0o600)
                    lock = Path(root) / adapters._LOCK
                    displaced = Path(root + "-old")
                    old_lock = Path(root) / "old-runtime-lock"
                    attacked = False

                    def retarget():
                        nonlocal attacked
                        if attacked:
                            return
                        attacked = True
                        if identity == "lock":
                            lock.rename(old_lock)
                            lock.write_bytes(b"")
                            os.chmod(lock, 0o600)
                        else:
                            Path(root).rename(displaced)
                            Path(root).mkdir(mode=0o700)

                    real_flock = adapters.fcntl.flock
                    real_listdir = os.listdir
                    real_open = os.open
                    real_stat = os.stat
                    temp_stats = 0

                    def attack_flock(fd, operation):
                        if boundary == "before_flock" and operation & adapters.fcntl.LOCK_EX:
                            retarget()
                        return real_flock(fd, operation)

                    def attack_listdir(path):
                        result = real_listdir(path)
                        if boundary == "listdir":
                            retarget()
                        return result

                    def attack_open(path, flags, mode=0o777, *, dir_fd=None):
                        fd = real_open(path, flags, mode, dir_fd=dir_fd)
                        if boundary == "temp_open" and path == stale.name:
                            retarget()
                        return fd

                    def attack_stat(path, *args, **kwargs):
                        nonlocal temp_stats
                        result = real_stat(path, *args, **kwargs)
                        if boundary == "before_unlink" and path == stale.name:
                            temp_stats += 1
                            if temp_stats == 2:
                                retarget()
                        return result

                    with mock.patch.object(adapters.fcntl, "flock", side_effect=attack_flock), \
                         mock.patch.object(adapters.os, "listdir", side_effect=attack_listdir), \
                         mock.patch.object(adapters.os, "open", side_effect=attack_open), \
                         mock.patch.object(adapters.os, "stat", side_effect=attack_stat):
                        with self.assertRaises(adapters.StoreIntegrityError):
                            adapters.open_transaction(root)
                    stale_after = ((displaced if identity == "root" else Path(root)) / stale.name)
                    self.assertTrue(stale_after.exists())
    def test_symlink_and_hardlink_are_rejected(self):
        adapters.initialize_store(self.root)
        os.unlink(self.root + "/.report-delivery.lock")
        os.symlink("missing", self.root + "/.report-delivery.lock")
        with self.assertRaises(adapters.StoreIntegrityError): adapters.open_transaction(self.root)
        os.unlink(self.root + "/.report-delivery.lock")
        with open(self.root + "/.report-delivery.lock", "wb") as f: f.write(b"")
        os.link(self.root + "/.report-delivery.lock", self.root + "/second-lock")
        os.chmod(self.root + "/.report-delivery.lock", 0o600)
        with self.assertRaises(adapters.StoreIntegrityError): adapters.open_transaction(self.root)

    def test_root_same_inode_mode_change_during_open_is_rejected(self):
        adapters.initialize_store(self.root)
        real_open = os.open
        changed = False

        def open_then_chmod(path, flags, mode=0o777, *, dir_fd=None):
            nonlocal changed
            fd = real_open(path, flags, mode, dir_fd=dir_fd)
            if not changed and dir_fd is None and os.fspath(path) == self.root:
                changed = True
                os.chmod(self.root, 0o777)
            return fd

        with mock.patch.object(adapters.os, "open", side_effect=open_then_chmod):
            with self.assertRaises(adapters.StoreIntegrityError):
                adapters.open_transaction(self.root)

    def test_root_retarget_during_open_is_rejected(self):
        adapters.initialize_store(self.root)
        real_open = os.open
        old_root = self.root + "-old"
        changed = False

        def open_then_retarget(path, flags, mode=0o777, *, dir_fd=None):
            nonlocal changed
            fd = real_open(path, flags, mode, dir_fd=dir_fd)
            if not changed and dir_fd is None and os.fspath(path) == self.root:
                changed = True
                os.rename(self.root, old_root)
                os.mkdir(self.root, 0o700)
            return fd

        with mock.patch.object(adapters.os, "open", side_effect=open_then_retarget):
            with self.assertRaises(adapters.StoreIntegrityError):
                adapters.open_transaction(self.root)

    def test_lock_retarget_and_same_inode_mode_change_are_rejected(self):
        for attack in ("retarget", "chmod"):
            with self.subTest(attack=attack), tempfile.TemporaryDirectory() as temp:
                root = str(Path(temp) / "store")
                adapters.initialize_store(root)
                lock = Path(root) / ".report-delivery.lock"
                real_flock = adapters.fcntl.flock
                changed = False

                def flock_then_attack(fd, operation):
                    nonlocal changed
                    result = real_flock(fd, operation)
                    if not changed and operation & adapters.fcntl.LOCK_EX:
                        changed = True
                        if attack == "retarget":
                            lock.rename(lock.with_name("old-lock"))
                            lock.write_bytes(b"")
                            os.chmod(lock, 0o600)
                        else:
                            os.chmod(lock, 0o666)
                    return result

                with mock.patch.object(adapters.fcntl, "flock", side_effect=flock_then_attack):
                    with self.assertRaises(adapters.StoreIntegrityError):
                        adapters.open_transaction(root)
    def test_lock_busy_and_same_id_resume(self):
        adapters.initialize_store(self.root)
        one = adapters.open_transaction(self.root)
        try:
            with self.assertRaises(adapters.StoreBusy): adapters.open_transaction(self.root)
            first = one.ensure(record())
            again = one.ensure(record())
            self.assertEqual(first.record_sha256, again.record_sha256)
        finally: one.close()
    def test_different_pending_blocks(self):
        adapters.initialize_store(self.root)
        with adapters.open_transaction(self.root) as tx:
            tx.ensure(record())
            with self.assertRaises(adapters.PendingTransaction): tx.ensure(record(image_bytes=b"different"))
    def test_recovery_exact_bytes_and_atomic_commit(self):
        adapters.initialize_store(self.root)
        with adapters.open_transaction(self.root) as tx:
            tx.ensure(record())
            old = tx._active_bytes()
            newer = outbox.canonical_bytes(outbox.prepare_publication(record(), remote_base="a" * 40, remote_blob="b" * 40, remote_commit="c" * 40))
            self.assertIs(tx.recover_commit(expected_before=old, expected_after=newer), adapters.RecoveryResult.NOT_APPLIED)
            tx._commit_bytes(newer)
            self.assertIs(tx.recover_commit(expected_before=old, expected_after=newer), adapters.RecoveryResult.APPLIED)
            self.assertIs(tx.recover_commit(expected_before=b"bad", expected_after=b"other"), adapters.RecoveryResult.DIVERGED)
    def test_terminal_receipt_is_private_and_idempotent(self):
        adapters.initialize_store(self.root)
        r = record()
        with adapters.open_transaction(self.root) as tx:
            tx.ensure(r); tx.prepare(remote_base="a" * 40, remote_blob="b" * 40, remote_commit="c" * 40); tx.begin_publication()
            tx.mark_publication_published(); tx.begin_delivery(outbox.DeliveryChannel.PRIMARY); tx.confirm_delivery_sent(); tx.mark_dedupe_applied(("a",))
            receipt = tx.finalize()
            self.assertEqual(receipt.outcome, "complete")
            with open(self.root + "/receipts/" + r.outbox_id[5:] + ".json", "rb") as source: data = source.read()
            self.assertNotIn(b"image", data); self.assertNotIn(b"handles", data)
            obj = json.loads(data)
            self.assertEqual(obj["channel"], "primary")
            self.assertEqual(obj["delivered_count"], 1)
            self.assertEqual(tx.ensure(r), receipt)
    def test_delivery_unknown_never_retries_or_dedupes(self):
        adapters.initialize_store(self.root)
        with adapters.open_transaction(self.root) as tx:
            tx.ensure(record()); tx.prepare(remote_base="a" * 40, remote_blob="b" * 40, remote_commit="c" * 40); tx.begin_publication(); tx.mark_publication_published()
            sender = FakeDelivery({"status": 503, "ack": False})
            adapters.deliver(tx, sender); adapters.deliver(tx, sender)
            self.assertEqual(len(sender.calls), 1)
            self.assertEqual(tx.load_active().record.delivery.outcome, outbox.DeliveryOutcome.UNKNOWN)
            self.assertEqual(adapters.apply_dedupe(tx, FakeDedupe()), tx.load_active())
    def test_dedupe_persists_before_mark_and_rejects_digest_collision(self):
        adapters.initialize_store(self.root)
        with adapters.open_transaction(self.root) as tx:
            tx.ensure(record()); tx.prepare(remote_base="a" * 40, remote_blob="b" * 40, remote_commit="c" * 40); tx.begin_publication(); tx.mark_publication_published(); tx.begin_delivery(outbox.DeliveryChannel.PRIMARY); tx.confirm_delivery_sent()
            dedupe = FakeDedupe(); adapters.apply_dedupe(tx, dedupe)
            self.assertEqual(len(dedupe.calls), 1); self.assertEqual(tx.load_active().record.dedupe.outcome, outbox.DedupeOutcome.APPLIED)
        second = tempfile.TemporaryDirectory()
        try:
            root = second.name + "/store"; adapters.initialize_store(root)
            with adapters.open_transaction(root) as tx:
                tx.ensure(record()); tx.prepare(remote_base="a" * 40, remote_blob="b" * 40, remote_commit="c" * 40); tx.begin_publication(); tx.mark_publication_published(); tx.begin_delivery(outbox.DeliveryChannel.PRIMARY); tx.confirm_delivery_sent()
                with self.assertRaises(adapters.DedupeIntegrityError): adapters.apply_dedupe(tx, FakeDedupe({"outbox_id": record().outbox_id, "digest": "0" * 64}))
        finally: second.cleanup()
    def test_projection_and_canary_do_not_leak_payload(self):
        adapters.initialize_store(self.root)
        with adapters.open_transaction(self.root) as tx:
            snap = tx.ensure(record())
            encoded = json.dumps(adapters.project(snap), sort_keys=True)
            self.assertNotIn("primary", encoded); self.assertNotIn("aW1hZ2U", encoded)
        with self.assertRaises(adapters.AdapterError): adapters.controlled_canary(self.temp.name + "/canary-main", record(ref="refs/heads/main"))
    def test_fake_canary_runs_without_external_transport(self):
        base = os.path.realpath(self.temp.name)
        root = base + "/canary"
        policy = adapters.CanaryPolicy(canonical_root=root, allowed_temp_base=base)
        result = adapters.controlled_canary(root, canary_record(), policy=policy)
        self.assertEqual(result["state"], "complete")

    def test_github_policy_is_component_bounded_and_validated(self):
        policy = adapters.GithubPolicy("owner/repo", "refs/heads/topic", "reports/")
        self.assertTrue(policy.allows(record(path="reports/x.png").intent.target))
        self.assertTrue(policy.allows(record(path="reports").intent.target))
        self.assertFalse(policy.allows(record(path="reports2/x.png").intent.target))
        for prefix in ("", "../reports", "reports//x", "/reports", "reports\\x"):
            with self.subTest(prefix=prefix), self.assertRaises(ValueError):
                adapters.GithubPolicy("owner/repo", "refs/heads/topic", prefix)

    def test_ensure_validates_caller_before_store_lookup(self):
        adapters.initialize_store(self.root)
        forged = replace(record(), outbox_id="rdo1-" + "0" * 64)
        with adapters.open_transaction(self.root) as tx:
            with self.assertRaises(outbox.IntegrityError):
                tx.ensure(forged)
            self.assertIsNone(tx.load_active())

    def test_github_happy_path_uses_exact_ref_and_one_entry_nested_tree(self):
        adapters.initialize_store(self.root)
        target = record(path="reports/nested/x.png")
        github = FakeGithub(target_path=target.intent.target.path)
        policy = adapters.GithubPolicy("owner/repo", "refs/heads/topic", "reports")
        with adapters.open_transaction(self.root) as tx:
            tx.ensure(target)
            snap = adapters.publish_github(tx, github, ancestry=lambda ancestor, tip: ancestor == tip,
                                           policy=policy)
            self.assertIs(snap.record.publication.outcome, outbox.CasOutcome.PUBLISHED)
            self.assertEqual(snap.record.publication.remote_base, github.base)
            self.assertEqual(snap.record.publication.remote_blob, github.blob)
            self.assertEqual(snap.record.publication.remote_commit, github.candidate)
        self.assertIn(("GET", "/repos/owner/repo/git/ref/heads/topic", None), github.calls)
        self.assertEqual(len(github.patch_calls), 1)
        self.assertEqual(github.patch_calls[0][1], "/repos/owner/repo/git/refs/heads/topic")
        self.assertEqual(github.patch_calls[0][2], {"sha": github.candidate, "force": False})
        tree_posts = [call for call in github.calls if call[0] == "POST" and call[1].endswith("/trees")]
        self.assertEqual(tree_posts[0][2]["tree"], [{"path": "reports/nested/x.png", "mode": "100644", "type": "blob", "sha": github.blob}])
        commit_posts = [call for call in github.calls if call[0] == "POST" and call[1].endswith("/commits")]
        self.assertEqual(commit_posts[0][2]["parents"], [github.base])

    def test_existing_exact_blob_confirms_without_patch_and_different_blob_overwrites(self):
        policy = adapters.GithubPolicy("owner/repo", "refs/heads/topic", "reports")
        for existing, expect_patch in ((b"image", False), (b"old", True)):
            with self.subTest(existing=existing), tempfile.TemporaryDirectory() as temp:
                root = str(Path(temp) / "store")
                adapters.initialize_store(root)
                github = FakeGithub(existing=existing)
                with adapters.open_transaction(root) as tx:
                    tx.ensure(record())
                    snap = adapters.publish_github(tx, github, ancestry=lambda a, b: a == b, policy=policy)
                    self.assertIs(snap.record.publication.outcome, outbox.CasOutcome.PUBLISHED)
                self.assertEqual(bool(github.patch_calls), expect_patch)

    def test_existing_blob_lookup_failure_is_not_conflict(self):
        adapters.initialize_store(self.root)
        github = FakeGithub(existing=b"old", existing_blob_status=500)
        with adapters.open_transaction(self.root) as tx:
            tx.ensure(record())
            with self.assertRaises(adapters.TransportFailure):
                adapters.publish_github(tx, github, ancestry=lambda a, b: a == b,
                                        policy=adapters.GithubPolicy("owner/repo", "refs/heads/topic", "reports"))
            self.assertIs(tx.load_active().record.publication.outcome, outbox.CasOutcome.NOT_SENT)

    def test_candidate_parent_must_be_exact_base(self):
        adapters.initialize_store(self.root)
        github = FakeGithub(candidate_parent="9" * 40)
        with adapters.open_transaction(self.root) as tx:
            tx.ensure(record())
            with self.assertRaises(adapters.TransportFailure):
                adapters.publish_github(tx, github, ancestry=lambda a, b: a == b,
                                        policy=adapters.GithubPolicy("owner/repo", "refs/heads/topic", "reports"))
            self.assertEqual(github.patch_calls, [])

    def test_prepared_plan_survives_restart_without_rebuilding_objects(self):
        adapters.initialize_store(self.root)
        with adapters.open_transaction(self.root) as tx:
            tx.ensure(record())
            tx.prepare(remote_base=FakeGithub.base, remote_blob=FakeGithub.blob,
                       remote_commit=FakeGithub.candidate)
        github = FakeGithub()
        with adapters.open_transaction(self.root) as tx:
            snap = adapters.publish_github(tx, github, ancestry=lambda a, b: a == b,
                                           policy=adapters.GithubPolicy("owner/repo", "refs/heads/topic", "reports"))
            self.assertIs(snap.record.publication.outcome, outbox.CasOutcome.PUBLISHED)
        self.assertFalse(any(call[0] == "POST" for call in github.calls))
        self.assertEqual(len(github.patch_calls), 1)

    def test_patch_response_loss_is_unknown_then_explicit_reconcile_publishes(self):
        adapters.initialize_store(self.root)
        github = FakeGithub(patch_raises=True, patch_applies=True)
        policy = adapters.GithubPolicy("owner/repo", "refs/heads/topic", "reports")
        with adapters.open_transaction(self.root) as tx:
            tx.ensure(record())
            unknown = adapters.publish_github(tx, github, ancestry=lambda a, b: a == b, policy=policy)
            self.assertIs(unknown.record.publication.outcome, outbox.CasOutcome.UNKNOWN)
            self.assertFalse(outbox.fallback_eligible(unknown.record))
            published = adapters.reconcile_github(tx, github, ancestry=lambda a, b: a == b, policy=policy)
            self.assertIs(published.record.publication.outcome, outbox.CasOutcome.PUBLISHED)
        self.assertEqual(len(github.patch_calls), 1)

    def test_patch_5xx_never_retries_or_falls_back(self):
        adapters.initialize_store(self.root)
        github = FakeGithub(patch_status=503, patch_applies=False)
        policy = adapters.GithubPolicy("owner/repo", "refs/heads/topic", "reports")
        with adapters.open_transaction(self.root) as tx:
            tx.ensure(record(fallback_payload_bytes=b"fallback", fallback_handles=("a",)))
            first = adapters.publish_github(tx, github, ancestry=lambda a, b: a == b, policy=policy)
            second = adapters.publish_github(tx, github, ancestry=lambda a, b: a == b, policy=policy)
            self.assertIs(first.record.publication.outcome, outbox.CasOutcome.UNKNOWN)
            self.assertIs(second.record.publication.outcome, outbox.CasOutcome.UNKNOWN)
            self.assertFalse(outbox.fallback_eligible(second.record))
        self.assertEqual(len(github.patch_calls), 1)

    def test_patch_409_requires_authoritative_negative_evidence(self):
        policy = adapters.GithubPolicy("owner/repo", "refs/heads/topic", "reports")
        class ConflictGithub(FakeGithub):
            competitor = "9" * 40
            def request(self, method, path, body=None):
                response = super().request(method, path, body)
                if method == "PATCH":
                    self.tip = self.competitor
                return response
        for status in (409, 422):
            with self.subTest(status=status), tempfile.TemporaryDirectory() as temp:
                root = str(Path(temp) / "store"); adapters.initialize_store(root)
                github = ConflictGithub(patch_status=status, patch_applies=False)
                with adapters.open_transaction(root) as tx:
                    tx.ensure(record())
                    snap = adapters.publish_github(tx, github, ancestry=lambda a, b: a == b, policy=policy)
                    self.assertIs(snap.record.publication.outcome, outbox.CasOutcome.CONFLICT)
        with tempfile.TemporaryDirectory() as temp:
            root = str(Path(temp) / "store"); adapters.initialize_store(root)
            github = FakeGithub(patch_status=409, patch_applies=False)
            with adapters.open_transaction(root) as tx:
                tx.ensure(record())
                snap = adapters.publish_github(tx, github, ancestry=lambda a, b: a == b,
                                               policy=policy)
                self.assertIs(snap.record.publication.outcome, outbox.CasOutcome.UNKNOWN)
        class UncertainGithub(FakeGithub):
            def request(self, method, path, body=None):
                if method == "GET" and "/ref/" in path and self.patch_calls:
                    self.calls.append((method, path, body))
                    return {"status": 500, "body": {}}
                return super().request(method, path, body)
        with tempfile.TemporaryDirectory() as temp:
            root = str(Path(temp) / "store"); adapters.initialize_store(root)
            github = UncertainGithub(patch_status=409, patch_applies=False)
            with adapters.open_transaction(root) as tx:
                tx.ensure(record())
                snap = adapters.publish_github(tx, github, ancestry=lambda a, b: a == b, policy=policy)
                self.assertIs(snap.record.publication.outcome, outbox.CasOutcome.UNKNOWN)

    def test_patch_2xx_requires_descendant_and_exact_blob_verification(self):
        adapters.initialize_store(self.root)
        github = FakeGithub(post_patch_blob=b"wrong")
        with adapters.open_transaction(self.root) as tx:
            tx.ensure(record())
            snap = adapters.publish_github(tx, github, ancestry=lambda a, b: a == b,
                                           policy=adapters.GithubPolicy("owner/repo", "refs/heads/topic", "reports"))
            self.assertIs(snap.record.publication.outcome, outbox.CasOutcome.UNKNOWN)

    def test_recursive_tree_truncation_is_never_authoritative(self):
        policy = adapters.GithubPolicy("owner/repo", "refs/heads/topic", "reports")

        class TruncatedBaseGithub(FakeGithub):
            def request(self, method, path, body=None):
                response = super().request(method, path, body)
                if method == "GET" and ("/trees/" + self.base_tree) in path:
                    response["body"]["truncated"] = True
                return response

        with tempfile.TemporaryDirectory() as temp:
            root = str(Path(temp) / "store")
            adapters.initialize_store(root)
            github = TruncatedBaseGithub()
            with adapters.open_transaction(root) as tx:
                tx.ensure(record())
                with self.assertRaises(adapters.TransportFailure):
                    adapters.publish_github(tx, github, ancestry=lambda a, b: a == b,
                                            policy=policy)
            self.assertEqual(github.patch_calls, [])

        class TruncatedEvidenceGithub(FakeGithub):
            def request(self, method, path, body=None):
                response = super().request(method, path, body)
                if (method == "GET" and ("/trees/" + self.candidate_tree) in path
                        and self.patch_calls):
                    response["body"]["truncated"] = True
                return response

        with tempfile.TemporaryDirectory() as temp:
            root = str(Path(temp) / "store")
            adapters.initialize_store(root)
            github = TruncatedEvidenceGithub()
            with adapters.open_transaction(root) as tx:
                tx.ensure(record())
                snap = adapters.publish_github(tx, github, ancestry=lambda a, b: a == b,
                                               policy=policy)
                self.assertIs(snap.record.publication.outcome, outbox.CasOutcome.UNKNOWN)

    def test_base_churn_never_reaches_patch_or_durable_prepare(self):
        class ChurningGithub(FakeGithub):
            other = "9" * 40
            def __init__(self):
                super().__init__()
                self.ref_reads = 0
            def request(self, method, path, body=None):
                if method == "GET" and path == "/repos/owner/repo/git/ref/heads/topic":
                    self.calls.append((method, path, body))
                    self.ref_reads += 1
                    tip = self.base if self.ref_reads % 2 else self.other
                    return {"status": 200, "body": {"object": {"sha": tip}}}
                return super().request(method, path, body)

        adapters.initialize_store(self.root)
        github = ChurningGithub()
        with adapters.open_transaction(self.root) as tx:
            tx.ensure(record())
            with self.assertRaises(adapters.TransportFailure):
                adapters.publish_github(
                    tx, github, ancestry=lambda a, b: a == b,
                    policy=adapters.GithubPolicy("owner/repo", "refs/heads/topic", "reports"),
                )
            self.assertIsNone(tx.load_active().record.publication.remote_base)
        self.assertEqual(github.patch_calls, [])
        self.assertEqual(github.ref_reads, 6)

    def test_descendant_overwrite_or_removal_stays_unknown_and_blocks_fallback(self):
        class DescendantGithub(FakeGithub):
            descendant = "1" * 40
            descendant_tree = "2" * 40
            replacement_blob = "3" * 40
            def __init__(self, *, remove_path):
                super().__init__(patch_status=409, patch_applies=True)
                self.remove_path = remove_path
            def request(self, method, path, body=None):
                if method == "GET" and path.endswith("/commits/" + self.descendant):
                    self.calls.append((method, path, body))
                    return {"status": 200, "body": {"tree": {"sha": self.descendant_tree},
                                                     "parents": [{"sha": self.candidate}]}}
                if method == "GET" and ("/trees/" + self.descendant_tree) in path:
                    self.calls.append((method, path, body))
                    entries = [] if self.remove_path else [
                        {"path": self.target_path, "sha": self.replacement_blob}
                    ]
                    return {"status": 200, "body": {"tree": entries}}
                response = super().request(method, path, body)
                if method == "PATCH":
                    self.tip = self.descendant
                return response

        policy = adapters.GithubPolicy("owner/repo", "refs/heads/topic", "reports")
        for remove_path in (False, True):
            with self.subTest(remove_path=remove_path), tempfile.TemporaryDirectory() as temp:
                root = str(Path(temp) / "store")
                adapters.initialize_store(root)
                github = DescendantGithub(remove_path=remove_path)
                sender = FakeDelivery()
                with adapters.open_transaction(root) as tx:
                    tx.ensure(record(fallback_payload_bytes=b"fallback", fallback_handles=("a",)))
                    snap = adapters.publish_github(
                        tx, github,
                        ancestry=lambda ancestor, tip: (
                            ancestor == tip
                            or (ancestor == github.candidate and tip == github.descendant)
                        ),
                        policy=policy,
                    )
                    self.assertIs(snap.record.publication.outcome, outbox.CasOutcome.UNKNOWN)
                    self.assertFalse(outbox.fallback_eligible(snap.record))
                    self.assertEqual(adapters.deliver(tx, sender), snap)
                self.assertEqual(sender.calls, [])

    def test_active_commit_rename_effect_then_raise_is_recoverable(self):
        adapters.initialize_store(self.root)
        with adapters.open_transaction(self.root) as tx:
            tx.ensure(record())
            before = tx._active_bytes()
            after = outbox.canonical_bytes(outbox.prepare_publication(
                record(), remote_base="a" * 40, remote_blob="b" * 40, remote_commit="c" * 40))
            real_replace = os.replace
            def effect_then_raise(*args, **kwargs):
                real_replace(*args, **kwargs)
                raise OSError("after rename")
            with mock.patch.object(tx.fs, "replace", side_effect=effect_then_raise):
                with self.assertRaises(adapters.StoreCommitUncertain):
                    tx._commit_bytes(after)
            self.assertIs(tx.recover_commit(expected_before=before, expected_after=after),
                          adapters.RecoveryResult.APPLIED)

    def test_active_commit_effect_then_evidence_failure_is_store_uncertain(self):
        adapters.initialize_store(self.root)
        with adapters.open_transaction(self.root) as tx:
            tx.ensure(record())
            before = tx._active_bytes()
            after = outbox.canonical_bytes(outbox.prepare_publication(
                record(), remote_base="a" * 40, remote_blob="b" * 40, remote_commit="c" * 40))
            real_replace = os.replace
            real_active_bytes = tx._active_bytes
            evidence_reads = 0

            def effect_then_raise(*args, **kwargs):
                real_replace(*args, **kwargs)
                raise OSError("after rename")

            def before_then_evidence_failure():
                nonlocal evidence_reads
                evidence_reads += 1
                if evidence_reads == 1:
                    return real_active_bytes()
                raise OSError("evidence unavailable")

            with mock.patch.object(tx, "_active_bytes", side_effect=before_then_evidence_failure), \
                 mock.patch.object(tx.fs, "replace", side_effect=effect_then_raise):
                with self.assertRaises(adapters.StoreCommitUncertain) as caught:
                    tx._commit_bytes(after)
            self.assertEqual(caught.exception.before_sha, adapters._sha(before))
            self.assertIsNone(caught.exception.after_sha)
            self.assertEqual(real_active_bytes(), after)

    def test_active_commit_rename_failure_before_effect_is_store_uncertain(self):
        adapters.initialize_store(self.root)
        with adapters.open_transaction(self.root) as tx:
            tx.ensure(record())
            before = tx._active_bytes()
            after = outbox.canonical_bytes(outbox.prepare_publication(
                record(), remote_base="a" * 40, remote_blob="b" * 40, remote_commit="c" * 40))
            with mock.patch.object(tx.fs, "replace", side_effect=OSError("rename rejected")):
                with self.assertRaises(adapters.StoreCommitUncertain) as caught:
                    tx._commit_bytes(after)
            self.assertEqual(caught.exception.before_sha, adapters._sha(before))
            self.assertEqual(caught.exception.after_sha, adapters._sha(before))
            self.assertEqual(tx._active_bytes(), before)

    def test_active_commit_file_and_directory_fsync_fault_boundaries(self):
        for boundary in ("file", "directory"):
            with self.subTest(boundary=boundary), tempfile.TemporaryDirectory() as temp:
                root = str(Path(temp) / "store")
                adapters.initialize_store(root)
                with adapters.open_transaction(root) as tx:
                    tx.ensure(record())
                    before = tx._active_bytes()
                    after = outbox.canonical_bytes(outbox.prepare_publication(
                        record(), remote_base="a" * 40, remote_blob="b" * 40,
                        remote_commit="c" * 40))
                    real_fsync = os.fsync
                    faulted = False

                    def fail_boundary(fd):
                        nonlocal faulted
                        if not faulted and ((boundary == "directory" and fd == tx.dfd)
                                            or (boundary == "file" and fd != tx.dfd)):
                            faulted = True
                            raise OSError(boundary + " fsync failed")
                        return real_fsync(fd)

                    with mock.patch.object(tx.fs, "fsync", side_effect=fail_boundary):
                        expected = (adapters.StoreCommitUncertain if boundary == "directory"
                                    else OSError)
                        with self.assertRaises(expected):
                            tx._commit_bytes(after)
                    if boundary == "directory":
                        self.assertEqual(tx._active_bytes(), after)
                    else:
                        self.assertEqual(tx._active_bytes(), before)

    def test_receipt_rename_effect_then_raise_recovers_on_restart(self):
        adapters.initialize_store(self.root)
        r = record()
        with adapters.open_transaction(self.root) as tx:
            tx.ensure(r); tx.prepare(remote_base="a" * 40, remote_blob="b" * 40, remote_commit="c" * 40)
            tx.begin_publication(); tx.mark_publication_published(); tx.begin_delivery(outbox.DeliveryChannel.PRIMARY)
            tx.confirm_delivery_sent(); tx.mark_dedupe_applied(("a",))
            real_replace = os.replace
            def effect_then_raise(*args, **kwargs):
                real_replace(*args, **kwargs)
                raise OSError("after receipt rename")
            with mock.patch.object(tx.fs, "replace", side_effect=effect_then_raise):
                with self.assertRaises(adapters.StoreCommitUncertain):
                    tx.finalize()
        with adapters.open_transaction(self.root) as tx:
            receipt = tx.finalize()
            self.assertEqual(receipt.outcome, "complete")
            self.assertEqual(tx.ensure(r), receipt)

    def test_receipt_recovery_fences_retarget_before_replace_and_unlink(self):
        for identity in ("lock", "root"):
            for mutation in ("replace", "unlink"):
                with self.subTest(identity=identity, mutation=mutation), tempfile.TemporaryDirectory() as temp:
                    root = str(Path(temp) / "store")
                    adapters.initialize_store(root)
                    prepared = outbox.prepare_publication(
                        record(), remote_base="a" * 40, remote_blob="b" * 40,
                        remote_commit="c" * 40,
                    )
                    terminal = outbox.mark_publication_conflict(outbox.begin_publication(prepared))
                    payload = adapters._receipt_bytes(
                        terminal, outbox.record_sha256(terminal), "terminal_conflict"
                    )
                    receipt_dir = Path(root) / "receipts"
                    suffix = terminal.outbox_id[5:]
                    temp_path = receipt_dir / (".receipt.tmp." + suffix)
                    final_path = receipt_dir / (suffix + ".json")
                    temp_path.write_bytes(payload)
                    os.chmod(temp_path, 0o600)
                    if mutation == "unlink":
                        final_path.write_bytes(payload)
                        os.chmod(final_path, 0o600)
                    lock = Path(root) / adapters._LOCK
                    old_lock = Path(root) / "old-recovery-lock"
                    displaced = Path(root + "-old")
                    attacked = False

                    def retarget():
                        nonlocal attacked
                        if attacked:
                            return
                        attacked = True
                        if identity == "lock":
                            lock.rename(old_lock)
                            lock.write_bytes(b"")
                            os.chmod(lock, 0o600)
                        else:
                            Path(root).rename(displaced)
                            Path(root).mkdir(mode=0o700)

                    real_read_checked = adapters._read_checked

                    def attack_before_mutation(fs, dfd, name, mode, uid, limit):
                        try:
                            value = real_read_checked(fs, dfd, name, mode, uid, limit)
                        except FileNotFoundError:
                            if mutation == "replace" and name == final_path.name:
                                retarget()
                            raise
                        if mutation == "unlink" and name == final_path.name:
                            retarget()
                        return value

                    with mock.patch.object(adapters, "_read_checked", side_effect=attack_before_mutation):
                        with self.assertRaises(adapters.StoreIntegrityError):
                            adapters.open_transaction(root)
                    preserved = ((displaced if identity == "root" else Path(root)) / "receipts")
                    self.assertTrue((preserved / temp_path.name).exists())
                    self.assertEqual((preserved / final_path.name).exists(), mutation == "unlink")

    def test_receipt_recovery_fences_retarget_inside_listdir(self):
        for identity in ("lock", "root"):
            with self.subTest(identity=identity), tempfile.TemporaryDirectory() as temp:
                root = str(Path(temp) / "store")
                adapters.initialize_store(root)
                prepared = outbox.prepare_publication(
                    record(), remote_base="a" * 40, remote_blob="b" * 40,
                    remote_commit="c" * 40,
                )
                terminal = outbox.mark_publication_conflict(outbox.begin_publication(prepared))
                payload = adapters._receipt_bytes(
                    terminal, outbox.record_sha256(terminal), "terminal_conflict"
                )
                temp_path = (Path(root) / "receipts"
                             / (".receipt.tmp." + terminal.outbox_id[5:]))
                temp_path.write_bytes(payload)
                os.chmod(temp_path, 0o600)
                lock = Path(root) / adapters._LOCK
                old_lock = Path(root) / "old-listdir-lock"
                displaced = Path(root + "-old")
                real_listdir = os.listdir
                listdir_calls = 0

                def attack_receipt_listdir(path):
                    nonlocal listdir_calls
                    result = real_listdir(path)
                    listdir_calls += 1
                    if listdir_calls == 2:
                        if identity == "lock":
                            lock.rename(old_lock)
                            lock.write_bytes(b"")
                            os.chmod(lock, 0o600)
                        else:
                            Path(root).rename(displaced)
                            Path(root).mkdir(mode=0o700)
                    return result

                with mock.patch.object(adapters.os, "listdir", side_effect=attack_receipt_listdir):
                    with self.assertRaises(adapters.StoreIntegrityError):
                        adapters.open_transaction(root)
                preserved_root = displaced if identity == "root" else Path(root)
                self.assertTrue((preserved_root / "receipts" / temp_path.name).exists())

    def test_runtime_cleanup_directory_fsync_precedes_unlock(self):
        adapters.initialize_store(self.root)
        stale = Path(self.root) / (".active.tmp." + "3" * 32)
        stale.write_bytes(b"stale")
        os.chmod(stale, 0o600)
        events = []
        real_fsync = os.fsync
        real_flock = adapters.fcntl.flock

        def track_fsync(fd):
            events.append(("fsync", fd))
            return real_fsync(fd)

        def track_flock(fd, operation):
            if operation == adapters.fcntl.LOCK_UN:
                events.append(("unlock", fd))
            return real_flock(fd, operation)

        with mock.patch.object(adapters.os, "fsync", side_effect=track_fsync), \
             mock.patch.object(adapters.fcntl, "flock", side_effect=track_flock):
            tx = adapters.open_transaction(self.root)
            tx.close()
        labels = [event[0] for event in events]
        self.assertIn("fsync", labels)
        self.assertLess(max(index for index, label in enumerate(labels) if label == "fsync"),
                        labels.index("unlock"))

    def test_finalize_active_unlink_effect_then_evidence_failure_is_uncertain(self):
        adapters.initialize_store(self.root)
        with adapters.open_transaction(self.root) as tx:
            tx.ensure(record())
            tx.prepare(remote_base="a" * 40, remote_blob="b" * 40, remote_commit="c" * 40)
            tx.begin_publication()
            terminal = tx.mark_publication_conflict()
            real_unlink = os.unlink
            real_active_bytes = tx._active_bytes
            unlink_effected = False

            def effect_then_raise(path, *args, **kwargs):
                nonlocal unlink_effected
                if path == adapters._ACTIVE and kwargs.get("dir_fd") == tx.dfd:
                    real_unlink(path, *args, **kwargs)
                    unlink_effected = True
                    raise OSError("after active unlink")
                return real_unlink(path, *args, **kwargs)

            def fail_only_after_effect():
                if unlink_effected:
                    raise OSError("active evidence unavailable")
                return real_active_bytes()

            with mock.patch.object(tx.fs, "unlink", side_effect=effect_then_raise), \
                 mock.patch.object(tx, "_active_bytes", side_effect=fail_only_after_effect):
                with self.assertRaises(adapters.StoreCommitUncertain) as caught:
                    tx.finalize()
            self.assertEqual(caught.exception.before_sha, terminal.record_sha256)
            self.assertIsNone(caught.exception.after_sha)
            self.assertFalse((Path(self.root) / "active.json").exists())

    def test_finalize_active_unlink_failure_before_effect_is_uncertain(self):
        adapters.initialize_store(self.root)
        with adapters.open_transaction(self.root) as tx:
            tx.ensure(record())
            tx.prepare(remote_base="a" * 40, remote_blob="b" * 40, remote_commit="c" * 40)
            tx.begin_publication()
            terminal = tx.mark_publication_conflict()
            real_unlink = os.unlink

            def fail_before_effect(path, *args, **kwargs):
                if path == adapters._ACTIVE and kwargs.get("dir_fd") == tx.dfd:
                    raise OSError("before active unlink")
                return real_unlink(path, *args, **kwargs)

            with mock.patch.object(tx.fs, "unlink", side_effect=fail_before_effect):
                with self.assertRaises(adapters.StoreCommitUncertain) as caught:
                    tx.finalize()
            self.assertEqual(caught.exception.before_sha, terminal.record_sha256)
            self.assertEqual(caught.exception.after_sha, terminal.record_sha256)
            self.assertTrue((Path(self.root) / "active.json").exists())

    def test_exact_stale_receipt_temp_is_promoted_and_mismatch_blocks(self):
        r = record()
        adapters.initialize_store(self.root)
        with adapters.open_transaction(self.root) as tx:
            tx.ensure(r); tx.prepare(remote_base="a" * 40, remote_blob="b" * 40, remote_commit="c" * 40)
            tx.begin_publication(); tx.mark_publication_published(); tx.begin_delivery(outbox.DeliveryChannel.PRIMARY)
            tx.confirm_delivery_sent(); terminal = tx.mark_dedupe_applied(("a",))
            payload = adapters._receipt_bytes(terminal.record, terminal.record_sha256, "complete")
        temp_name = self.root + "/receipts/.receipt.tmp." + r.outbox_id[5:]
        with open(temp_name, "wb") as target: target.write(payload)
        os.chmod(temp_name, 0o600)
        with adapters.open_transaction(self.root) as tx:
            receipt = tx.ensure(r)
            self.assertIsInstance(receipt, adapters.FinalReceipt)
        self.assertFalse(os.path.exists(temp_name))
        final_name = self.root + "/receipts/" + r.outbox_id[5:] + ".json"
        bad = json.loads(payload); bad["terminal_record_sha256"] = "0" * 64
        with open(temp_name, "wb") as target: target.write(payload)
        os.chmod(temp_name, 0o600)
        with open(final_name, "wb") as target: target.write(adapters._canonical_json(bad))
        os.chmod(final_name, 0o600)
        with self.assertRaises(adapters.StoreIntegrityError):
            adapters.open_transaction(self.root)

    def test_receipt_loader_rejects_duplicate_and_noncanonical_json(self):
        adapters.initialize_store(self.root)
        r = record()
        with adapters.open_transaction(self.root) as tx:
            tx.ensure(r); tx.prepare(remote_base="a" * 40, remote_blob="b" * 40, remote_commit="c" * 40)
            tx.begin_publication(); tx.mark_publication_conflict(); receipt = tx.finalize()
        name = self.root + "/receipts/" + r.outbox_id[5:] + ".json"
        original = Path(name).read_bytes()
        for malformed in (b" " + original, original.replace(b'{', b'{"schema":"duplicate",', 1)):
            with self.subTest(kind=malformed[:10]):
                Path(name).write_bytes(malformed); os.chmod(name, 0o600)
                with adapters.open_transaction(self.root) as tx:
                    with self.assertRaises(adapters.StoreIntegrityError):
                        tx.ensure(r)
        self.assertEqual(receipt.outcome, "terminal_conflict")

    def test_final_receipt_projection_preserves_real_terminal_fields(self):
        adapters.initialize_store(self.root)
        with adapters.open_transaction(self.root) as tx:
            tx.ensure(record()); tx.prepare(remote_base="a" * 40, remote_blob="b" * 40, remote_commit="c" * 40)
            tx.begin_publication(); tx.mark_publication_published(); tx.begin_delivery(outbox.DeliveryChannel.PRIMARY)
            tx.confirm_delivery_sent(); tx.mark_dedupe_applied(("a",)); receipt = tx.finalize()
        view = adapters.project(receipt, error_class="transport_failure")
        self.assertEqual(view["publication_outcome"], "published")
        self.assertEqual(view["delivery_outcome"], "sent")
        self.assertEqual(view["dedupe_outcome"], "applied")
        self.assertEqual(view["channel"], "primary")
        self.assertEqual(view["delivered_count"], 1)
        self.assertEqual(view["error_class"], "transport_failure")
        self.assertEqual(adapters.project(receipt, error_class="github_conflict")["error_class"],
                         "github_conflict")
        for invalid in ("", "Secret", "secret.value", "x" * 65, b"transport_failure"):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                adapters.project(receipt, error_class=invalid)

    def test_delivery_ack_must_be_exact_integer_count(self):
        for ack, sent in ((True, False), (0, False), (2, True)):
            with self.subTest(ack=ack), tempfile.TemporaryDirectory() as temp:
                root = str(Path(temp) / "store"); adapters.initialize_store(root)
                r = record(changed_handles=("a", "b"), primary_handles=("a", "b"))
                with adapters.open_transaction(root) as tx:
                    tx.ensure(r); tx.prepare(remote_base="a" * 40, remote_blob="b" * 40, remote_commit="c" * 40)
                    tx.begin_publication(); tx.mark_publication_published()
                    snap = adapters.deliver(tx, FakeDelivery({"status": 200, "ack": ack}))
                    self.assertEqual(snap.record.delivery.outcome is outbox.DeliveryOutcome.SENT, sent)

    def test_fallback_delivery_requires_conflict_and_never_switches(self):
        adapters.initialize_store(self.root)
        r = record(fallback_payload_bytes=b"fallback", fallback_handles=("a",))
        with adapters.open_transaction(self.root) as tx:
            tx.ensure(r); tx.prepare(remote_base="a" * 40, remote_blob="b" * 40, remote_commit="c" * 40)
            tx.begin_publication(); tx.mark_publication_conflict()
            sender = FakeDelivery({"status": 503, "ack": 1})
            first = adapters.deliver(tx, sender); second = adapters.deliver(tx, sender)
            self.assertIs(first.record.delivery.channel, outbox.DeliveryChannel.FALLBACK)
            self.assertIs(first.record.delivery.outcome, outbox.DeliveryOutcome.UNKNOWN)
            self.assertEqual(first, second); self.assertEqual(len(sender.calls), 1)
            dedupe = FakeDedupe()
            self.assertEqual(adapters.apply_dedupe(tx, dedupe), tx.load_active())
            self.assertEqual(dedupe.calls, [])

    def test_dedupe_is_strict_idempotent_and_recovers_raise_after_persist(self):
        adapters.initialize_store(self.root)
        with adapters.open_transaction(self.root) as tx:
            tx.ensure(record()); tx.prepare(remote_base="a" * 40, remote_blob="b" * 40, remote_commit="c" * 40)
            tx.begin_publication(); tx.mark_publication_published(); tx.begin_delivery(outbox.DeliveryChannel.PRIMARY)
            tx.confirm_delivery_sent()
            malformed = FakeDedupe()
            malformed.result = {"outbox_id": record().outbox_id, "digest": "0" * 64,
                                "outcome": "applied", "extra": True}
            with self.assertRaises(adapters.DedupeIntegrityError): adapters.apply_dedupe(tx, malformed)
            class DurableDedupe:
                def __init__(self): self.saved = None; self.effects = 0; self.calls = 0
                def apply(self, outbox_id, digest, handles):
                    self.calls += 1
                    if self.saved is None:
                        self.saved = {"outbox_id": outbox_id, "digest": digest, "outcome": "unchanged"}
                        self.effects += 1
                        raise OSError("ack lost")
                    return self.saved
            durable = DurableDedupe()
            with self.assertRaises(OSError): adapters.apply_dedupe(tx, durable)
            applied = adapters.apply_dedupe(tx, durable)
            self.assertIs(applied.record.dedupe.outcome, outbox.DedupeOutcome.APPLIED)
            again = adapters.apply_dedupe(tx, durable)
            self.assertEqual(applied, again)
            self.assertEqual(durable.effects, 1)
            self.assertEqual(durable.calls, 2)

    def test_canary_requires_exact_target_and_fresh_nonprod_root(self):
        base = os.path.realpath(self.temp.name)
        root = base + "/canary-bound"
        policy = adapters.CanaryPolicy(canonical_root=root, allowed_temp_base=base)
        with self.assertRaises(adapters.AdapterError):
            adapters.controlled_canary(root, record(), policy=policy)
        with self.assertRaises(adapters.AdapterError):
            adapters.controlled_canary(base + "/canary-other", canary_record(), policy=policy)
        existing = base + "/canary-existing"; os.mkdir(existing)
        existing_policy = adapters.CanaryPolicy(canonical_root=existing, allowed_temp_base=base)
        with self.assertRaises(adapters.AdapterError):
            adapters.controlled_canary(existing, canary_record(), policy=existing_policy)
        with self.assertRaises(ValueError):
            adapters.CanaryPolicy(canonical_root=base + "/production-state/canary",
                                  allowed_temp_base=base)

        target = base + "/symlink-target"
        linked = base + "/canary-linked"
        os.symlink(target, linked)
        linked_policy = adapters.CanaryPolicy(canonical_root=target, allowed_temp_base=base)
        with self.assertRaises(adapters.AdapterError):
            adapters.controlled_canary(linked, canary_record(), policy=linked_policy)

    def test_canary_rejects_root_rebind_after_fresh_creation(self):
        base = os.path.realpath(self.temp.name)
        root = base + "/canary-rebind"
        displaced = base + "/canary-rebind-old"
        policy = adapters.CanaryPolicy(canonical_root=root, allowed_temp_base=base)
        real_publish = adapters.publish_github
        rebound = False

        def rebind_then_publish(*args, **kwargs):
            nonlocal rebound
            if not rebound:
                rebound = True
                os.rename(root, displaced)
                os.mkdir(root, 0o700)
            return real_publish(*args, **kwargs)

        with mock.patch.object(adapters, "publish_github", side_effect=rebind_then_publish):
            with self.assertRaises(adapters.AdapterError):
                adapters.controlled_canary(root, canary_record(), policy=policy)

    def test_active_named_identity_change_during_read_is_rejected(self):
        adapters.initialize_store(self.root)
        with adapters.open_transaction(self.root) as tx:
            tx.ensure(record())
            active = Path(self.root) / "active.json"
            old = Path(self.root) / "old-active.json"
            original = active.read_bytes()
            real_read = os.read
            raced = False
            def replace_during_read(fd, count):
                nonlocal raced
                if not raced:
                    raced = True
                    active.replace(old)
                    active.write_bytes(original)
                    os.chmod(active, 0o600)
                return real_read(fd, count)
            with mock.patch.object(tx.fs, "read", side_effect=replace_during_read):
                with self.assertRaises(adapters.StoreIntegrityError):
                    tx.load_active()

    def test_exact_final_and_stale_receipt_temp_is_noop(self):
        adapters.initialize_store(self.root)
        r = record()
        with adapters.open_transaction(self.root) as tx:
            tx.ensure(r); tx.prepare(remote_base="a" * 40, remote_blob="b" * 40, remote_commit="c" * 40)
            tx.begin_publication(); tx.mark_publication_conflict(); receipt = tx.finalize()
        final = Path(self.root) / "receipts" / (r.outbox_id[5:] + ".json")
        temp = Path(self.root) / "receipts" / (".receipt.tmp." + r.outbox_id[5:])
        temp.write_bytes(final.read_bytes()); os.chmod(temp, 0o600)
        with adapters.open_transaction(self.root) as tx:
            self.assertEqual(tx.ensure(r), receipt)
        self.assertFalse(temp.exists())

    def test_receipt_symlink_and_hardlink_are_rejected(self):
        adapters.initialize_store(self.root)
        r = record()
        with adapters.open_transaction(self.root) as tx:
            tx.ensure(r); tx.prepare(remote_base="a" * 40, remote_blob="b" * 40, remote_commit="c" * 40)
            tx.begin_publication(); tx.mark_publication_conflict(); tx.finalize()
        final = Path(self.root) / "receipts" / (r.outbox_id[5:] + ".json")
        second = final.with_name("second.json"); os.link(final, second)
        with adapters.open_transaction(self.root) as tx:
            with self.assertRaises(adapters.StoreIntegrityError): tx.ensure(r)
        second.unlink(); data = final.read_bytes(); final.unlink()
        target = final.with_name("target.json"); target.write_bytes(data); os.chmod(target, 0o600)
        final.symlink_to(target.name)
        with adapters.open_transaction(self.root) as tx:
            with self.assertRaises(adapters.StoreIntegrityError): tx.ensure(r)


if __name__ == "__main__": unittest.main()
