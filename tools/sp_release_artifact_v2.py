"""Strict consumer and recoverable CAS for trusted reverse producer v2.

Authority is supplied out of band through :class:`ExpectedAuthority`.  Values
inside an artifact, receipt, attestation predicate, or sealed envelope never
become expected verification flags.  Candidate bytes are parsed as bounded
data only and are never extracted, imported, or executed.
"""
from __future__ import annotations

import base64
import dataclasses
import errno
import fcntl
import hashlib
import io
import json
import os
import re
import secrets
import selectors
import stat
import subprocess
import tarfile
import tempfile
import time
import unicodedata
import zipfile

HEX64 = re.compile(r"^[0-9a-f]{64}$")
OID40 = re.compile(r"^[0-9a-f]{40}$")
REPOSITORY = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
GIT_REF = re.compile(r"^refs/(?:heads|tags)/[A-Za-z0-9._/-]+$")
SAFE_COMPONENT = re.compile(r"^[A-Za-z0-9._:@+-]+$")
RECEIPT_SCHEMA = "spspy.trusted-reverse-producer-v2.receipt"
POLICY_SCHEMA = "spspy.trusted-reverse-producer-v2.release-policy"
ENVELOPE_SCHEMA = "spspy-isolated-release-envelope/v2"
CAS_COMMIT_SCHEMA = "spspy-isolated-release-cas-commit/v2"
PREDICATE_TYPE = "https://slsa.dev/provenance/v1"
SLSA_BUILD_TYPE = "https://slsa-framework.github.io/github-actions-buildtypes/workflow/v1"
HOSTED_BUILDER = "https://github.com/actions/runner/github-hosted"
MAX_TAR_BYTES = 280 * 1024 * 1024
MAX_ENTRY_BYTES = 64 * 1024 * 1024
MAX_PAYLOAD_BYTES = 256 * 1024 * 1024
MAX_ENTRIES = 4096
MAX_PATH_BYTES = 240
MAX_JSON_BYTES = 2 * 1024 * 1024
MAX_BUNDLE_BYTES = 8 * 1024 * 1024
MAX_ENVELOPE_BYTES = 64 * 1024 * 1024
MAX_GH_OUTPUT_BYTES = 1024 * 1024
CAS_LOCK_TIMEOUT_SECONDS = 5.0
CAS_LOCK_RETRY_SECONDS = 0.01
FINALIZE_JOB = "finalize-without-candidate"
CAS_RELEASE_FILES = frozenset({
    "payload.tar", "envelope.json", "trusted-root.jsonl", "release-policy.json",
    "r1-receipt.json", "r2-receipt.json", "r1-tar-bundle.jsonl", "r1-receipt-bundle.jsonl",
    "r2-tar-bundle.jsonl", "r2-receipt-bundle.jsonl",
})

# Use the versioned real file, not Homebrew's mutable /opt/homebrew/bin symlink.
# Upgrades therefore fail closed until path, version, and bytes are re-sealed.
GH_EXECUTABLE = "/opt/homebrew/Cellar/gh/2.87.3/bin/gh"
GH_VERSION = "gh version 2.87.3 (2026-02-23)"
GH_EXECUTABLE_SHA256 = "67b51ba8ca861e0fcd4749d47eba740e8db8c799a8b18645833e904e09f7fb70"

ARCHIVE_CONTRACT = {
    "end_of_archive_blocks": 2,
    "format": "ustar-v1",
    "gid": 0,
    "mode": "0600",
    "mtime": 0,
    "ordering": "utf-8-bytewise",
    "regular_files_only": True,
    "uid": 0,
}
INVENTORY_CONTRACT = {
    "digest": "sha256",
    "field_separator": "nul",
    "fields": ["kind", "utf8_path", "content_sha256_hex", "size_decimal"],
    "format": "spspy-file-inventory-v1",
    "kind": "file",
    "ordering": "utf-8-bytewise",
    "record_separator": "lf",
}


class ArtifactError(RuntimeError):
    pass


def _canonical(value):
    try:
        return (json.dumps(value, sort_keys=True, ensure_ascii=False, allow_nan=False, separators=(",", ":")) + "\n").encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ArtifactError("value is not canonical JSON") from exc


def _sha(data):
    if not isinstance(data, bytes):
        raise ArtifactError("digest input must be bytes")
    return hashlib.sha256(data).hexdigest()


def _string(value, label):
    if not isinstance(value, str) or not value:
        raise ArtifactError("%s must be a non-empty string" % label)
    return value


def _sha256(value, label):
    value = _string(value, label)
    if not HEX64.fullmatch(value):
        raise ArtifactError("%s must be lowercase SHA-256" % label)
    return value


def _oid(value, label):
    value = _string(value, label)
    if not OID40.fullmatch(value):
        raise ArtifactError("%s must be a 40-hex Git OID" % label)
    return value


def _repository(value, label):
    value = _string(value, label)
    if not REPOSITORY.fullmatch(value):
        raise ArtifactError("%s must be owner/repository" % label)
    return value


def _git_ref(value, label):
    value = _string(value, label)
    if not GIT_REF.fullmatch(value) or ".." in value or "//" in value:
        raise ArtifactError("%s must be an unambiguous full Git ref" % label)
    return value


def _positive_int(value, label):
    if type(value) is not int or value <= 0:
        raise ArtifactError("%s must be a positive integer" % label)
    return value


def _workflow_path(value, label):
    value = _string(value, label)
    if (not value.startswith(".github/workflows/") or "\\" in value or ".." in value or
            any(ord(character) < 32 or ord(character) == 127 for character in value)):
        raise ArtifactError("%s is unsafe" % label)
    return value


def _policy_path(value):
    value = _string(value, "policy path")
    if value != ".github/reverse_producer_v2/policy.json":
        raise ArtifactError("policy path differs from trusted producer contract")
    return value


def _json_bytes(raw, label, maximum=MAX_JSON_BYTES):
    if not isinstance(raw, bytes) or not raw or len(raw) > maximum:
        raise ArtifactError("%s is absent or exceeds byte cap" % label)
    try:
        return json.loads(raw.decode("utf-8"), parse_constant=lambda _value: (_ for _ in ()).throw(ValueError("non-finite JSON")))
    except (UnicodeError, json.JSONDecodeError, ValueError) as exc:
        raise ArtifactError("%s is not strict UTF-8 JSON" % label) from exc


def _exact_keys(value, expected, label):
    if not isinstance(value, dict) or set(value) != set(expected):
        raise ArtifactError("%s keys differ from contract" % label)
    return value


def _base64(value, label):
    if not isinstance(value, str):
        raise ArtifactError("%s is not base64 text" % label)
    try:
        return base64.b64decode(value, validate=True)
    except (ValueError, TypeError) as exc:
        raise ArtifactError("%s base64 is invalid" % label) from exc


def _jsonl(raw, label):
    if not isinstance(raw, bytes) or not raw or len(raw) > MAX_BUNDLE_BYTES:
        raise ArtifactError("%s is absent or exceeds byte cap" % label)
    values = []
    for line in raw.splitlines():
        if not line:
            continue
        value = _json_bytes(line, label + " record", MAX_BUNDLE_BYTES)
        if not isinstance(value, dict):
            raise ArtifactError("%s record is not an object" % label)
        values.append(value)
    if not values:
        raise ArtifactError("%s has no records" % label)
    return values


@dataclasses.dataclass(frozen=True)
class ExpectedAuthority:
    """External release authority for exactly one artifact/run/job."""
    candidate_repository_id: int
    candidate_repository: str
    candidate_commit: str
    candidate_tree: str
    candidate_ref: str
    candidate_input_tree_sha256: str
    caller_repository_id: int
    caller_repository: str
    caller_commit: str
    caller_ref: str
    caller_workflow_id: int
    caller_workflow_path: str
    signer_repository_id: int
    signer_repository: str
    signer_workflow_path: str
    signer_ref: str
    signer_commit: str
    signer_blob: str
    signer_workflow_sha256: str
    policy_path: str
    policy_blob: str
    policy_sha256: str
    trusted_root_sha256: str
    runner_label: str
    runner_os: str
    runner_image: str
    run_id: int
    run_attempt: int
    artifact_id: int
    artifact_name: str
    job_id: int
    job_name: str
    receipt_artifact_name: str

    def checked(self):
        for field in ("candidate_repository_id", "caller_repository_id", "caller_workflow_id", "signer_repository_id",
                      "run_id", "run_attempt", "artifact_id", "job_id"):
            _positive_int(getattr(self, field), field)
        _repository(self.candidate_repository, "candidate repository")
        _repository(self.caller_repository, "caller repository")
        _repository(self.signer_repository, "signer repository")
        for field in ("candidate_commit", "candidate_tree", "caller_commit", "signer_commit", "signer_blob", "policy_blob"):
            _oid(getattr(self, field), field)
        _git_ref(self.candidate_ref, "candidate ref")
        _git_ref(self.caller_ref, "caller ref")
        _git_ref(self.signer_ref, "signer ref")
        _workflow_path(self.caller_workflow_path, "caller workflow path")
        _workflow_path(self.signer_workflow_path, "signer workflow path")
        _policy_path(self.policy_path)
        for field in ("candidate_input_tree_sha256", "signer_workflow_sha256", "policy_sha256", "trusted_root_sha256"):
            _sha256(getattr(self, field), field)
        for field in ("runner_label", "runner_os", "runner_image", "artifact_name", "job_name", "receipt_artifact_name"):
            value = _string(getattr(self, field), field)
            if any(ord(character) < 32 or ord(character) == 127 for character in value):
                raise ArtifactError("%s contains control characters" % field)
        if self.runner_label != "macos-14" or self.runner_os != "macOS":
            raise ArtifactError("runner authority differs from hosted macOS contract")
        if self.caller_ref != "refs/heads/main" or self.signer_ref != "refs/heads/main":
            raise ArtifactError("caller and signer authority must be pinned to main")
        if (self.candidate_repository_id != self.caller_repository_id or
                self.candidate_repository != self.caller_repository):
            raise ArtifactError("current producer requires candidate and caller repository identity to match")
        if (self.artifact_name != "canonical-reverse-%d-%d" % (self.run_id, self.run_attempt) or
                self.receipt_artifact_name != "raw-reverse-%d-%d" % (self.run_id, self.run_attempt)):
            raise ArtifactError("artifact names differ from the current producer contract")
        return self

    @property
    def signer_workflow_identity(self):
        return "%s/%s@%s" % (self.signer_repository, self.signer_workflow_path, self.signer_ref)

    @property
    def signer_uri(self):
        return "https://github.com/%s/%s@%s" % (self.signer_repository, self.signer_workflow_path, self.signer_ref)

    @property
    def caller_uri(self):
        return "https://github.com/%s" % self.caller_repository

    @property
    def caller_workflow_uri(self):
        return "https://github.com/%s/%s@%s" % (self.caller_repository, self.caller_workflow_path, self.caller_ref)

    @property
    def invocation_uri(self):
        return "https://github.com/%s/actions/runs/%d/attempts/%d" % (self.caller_repository, self.run_id, self.run_attempt)


def _stable_authority(authority):
    authority = authority.checked()
    omitted = {"run_id", "run_attempt", "artifact_id", "artifact_name", "job_id", "receipt_artifact_name"}
    return {field.name: getattr(authority, field.name) for field in dataclasses.fields(authority) if field.name not in omitted}


def _independent_authorities(r1, r2):
    r1 = r1.checked()
    r2 = r2.checked()
    if _stable_authority(r1) != _stable_authority(r2):
        raise ArtifactError("R1/R2 external authority differs")
    if r1.run_id == r2.run_id or r1.artifact_id == r2.artifact_id or r1.job_id == r2.job_id:
        raise ArtifactError("R1/R2 authority is not independent")
    return r1, r2


def _trusted_root(raw, authority):
    authority.checked()
    if _sha(raw) != authority.trusted_root_sha256:
        raise ArtifactError("external TUF root digest differs")
    _jsonl(raw, "external TUF root")


def _load_policy(raw, authority):
    authority.checked()
    if _sha(raw) != authority.policy_sha256:
        raise ArtifactError("external release policy digest differs")
    policy = _json_bytes(raw, "release policy", 64 * 1024)
    _exact_keys(policy, {"schema", "version", "archive", "inventory", "limits", "paths"}, "release policy")
    if (policy["schema"] != POLICY_SCHEMA or policy["version"] != 1 or policy["archive"] != ARCHIVE_CONTRACT or
            policy["inventory"] != INVENTORY_CONTRACT):
        raise ArtifactError("release policy schema/archive differs")
    limits = _exact_keys(policy["limits"], {"max_entries", "max_file_bytes", "max_payload_bytes", "max_path_bytes"}, "release policy limits")
    maxima = {"max_entries": MAX_ENTRIES, "max_file_bytes": MAX_ENTRY_BYTES, "max_payload_bytes": MAX_PAYLOAD_BYTES,
              "max_path_bytes": MAX_PATH_BYTES}
    if any(type(limits[key]) is not int or limits[key] <= 0 or limits[key] > maxima[key] for key in limits):
        raise ArtifactError("release policy limit is invalid")
    paths = _exact_keys(policy["paths"], {"allowed_files", "allowed_prefixes", "required_files", "required_prefixes"}, "release policy paths")
    for key in ("allowed_files", "required_files"):
        values = paths[key]
        if not isinstance(values, list) or any(not isinstance(value, str) for value in values):
            raise ArtifactError("release policy path inventory is invalid")
        for value in values:
            _canonical_path(value)
        if len(values) != len(set(values)) or len(values) != len({value.casefold() for value in values}):
            raise ArtifactError("release policy path inventory collides")
    for key in ("allowed_prefixes", "required_prefixes"):
        values = paths[key]
        if not isinstance(values, list) or any(not isinstance(value, str) or not value.endswith("/") for value in values):
            raise ArtifactError("release policy prefix inventory is invalid")
        for value in values:
            _canonical_path(value[:-1])
        if len(values) != len(set(values)) or len(values) != len({value.casefold() for value in values}):
            raise ArtifactError("release policy prefix inventory collides")
    if not set(paths["required_files"]).issubset(paths["allowed_files"]):
        raise ArtifactError("release policy required files are not allowed")
    if not set(paths["required_prefixes"]).issubset(paths["allowed_prefixes"]):
        raise ArtifactError("release policy required prefixes are not allowed")
    if not paths["allowed_files"] and not paths["allowed_prefixes"]:
        raise ArtifactError("release policy allows no paths")
    return policy


def _canonical_path(value):
    if not isinstance(value, str) or not value or "\\" in value or value.startswith("/") or value.endswith("/"):
        raise ArtifactError("USTAR member path is unsafe")
    if unicodedata.normalize("NFC", value) != value:
        raise ArtifactError("USTAR member path is not NFC")
    try:
        encoded = value.encode("ascii", "strict")
    except UnicodeEncodeError as exc:
        raise ArtifactError("USTAR member path is not canonical ASCII") from exc
    if len(encoded) > MAX_PATH_BYTES or any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise ArtifactError("USTAR member path exceeds contract")
    if any(part in ("", ".", "..") for part in value.split("/")) or ".git" in value.split("/"):
        raise ArtifactError("USTAR member path has forbidden component")
    return value


def _ustar_split(path):
    encoded = path.encode("ascii")
    if len(encoded) <= 100:
        return encoded, b""
    # This is TarInfo._posix_split_name's first-feasible component split.
    # Both producer jobs use stdlib USTAR_FORMAT, so a last-feasible split is
    # semantically equivalent but byte-incompatible and must be rejected.
    for position, byte in enumerate(encoded):
        if byte != 47:
            continue
        prefix, name = encoded[:position], encoded[position + 1:]
        if prefix and name and len(prefix) <= 155 and len(name) <= 100:
            return name, prefix
    raise ArtifactError("USTAR member path has no canonical name/prefix split")


def _nul_ascii(field, label, *, width, allow_empty=False):
    if not isinstance(field, bytes) or len(field) != width:
        raise ArtifactError("USTAR %s field width differs" % label)
    try:
        index = field.index(0)
    except ValueError as exc:
        # POSIX USTAR permits the terminator to be omitted only when the fixed
        # width field is completely occupied.
        index = len(field)
    if any(field[index:]):
        raise ArtifactError("USTAR %s has bytes after NUL" % label)
    raw = field[:index]
    if not raw and not allow_empty:
        raise ArtifactError("USTAR %s is empty" % label)
    try:
        return raw.decode("ascii", "strict")
    except UnicodeDecodeError as exc:
        raise ArtifactError("USTAR %s is not ASCII" % label) from exc


def _fixed_octal(field, label):
    if len(field) < 2 or field[-1:] != b"\0" or any(byte < 48 or byte > 55 for byte in field[:-1]):
        raise ArtifactError("USTAR %s is not fixed canonical octal" % label)
    value = int(field[:-1], 8)
    if field != ("%0*o" % (len(field) - 1, value)).encode("ascii") + b"\0":
        raise ArtifactError("USTAR %s has ambiguous octal width" % label)
    return value


def _register_path(name, names, folded_components):
    if name in names:
        raise ArtifactError("duplicate USTAR member")
    parts = name.split("/")
    for index in range(1, len(parts) + 1):
        component = "/".join(parts[:index])
        folded = component.casefold()
        prior = folded_components.get(folded)
        if prior is not None and prior != component:
            raise ArtifactError("USTAR component case-fold collision")
        folded_components[folded] = component
    if any("/".join(parts[:index]) in names for index in range(1, len(parts))):
        raise ArtifactError("USTAR member is below a regular-file ancestor")
    if any(existing.startswith(name + "/") for existing in names):
        raise ArtifactError("USTAR regular file conflicts with descendant")
    names.add(name)


def _parse_header(header):
    if len(header) != 512 or header[257:263] != b"ustar\0" or header[263:265] != b"00":
        raise ArtifactError("archive is not strict USTAR")
    if header[156:157] != b"0":
        raise ArtifactError("USTAR typeflag must be ASCII zero regular file")
    if any(header[157:257]) or any(header[265:329]) or any(header[500:512]):
        raise ArtifactError("USTAR link/owner/padding metadata is non-zero")
    checksum = header[148:156]
    if checksum[6:] != b"\0 " or any(byte < 48 or byte > 55 for byte in checksum[:6]):
        raise ArtifactError("USTAR checksum field is not canonical")
    if int(checksum[:6], 8) != sum(header[:148] + b" " * 8 + header[156:]):
        raise ArtifactError("USTAR header checksum differs")
    mode = _fixed_octal(header[100:108], "mode")
    uid = _fixed_octal(header[108:116], "uid")
    gid = _fixed_octal(header[116:124], "gid")
    size = _fixed_octal(header[124:136], "size")
    mtime = _fixed_octal(header[136:148], "mtime")
    if header[329:337] != b"\0" * 8 or header[337:345] != b"\0" * 8:
        raise ArtifactError("USTAR device fields are not canonical zero")
    if mode != 0o600 or uid != 0 or gid != 0 or mtime != 0 or size > MAX_ENTRY_BYTES:
        raise ArtifactError("USTAR metadata is outside canonical contract")
    name = _nul_ascii(header[:100], "name", width=100)
    prefix = _nul_ascii(header[345:500], "prefix", width=155, allow_empty=True)
    path = _canonical_path(prefix + "/" + name if prefix else name)
    expected_name, expected_prefix = _ustar_split(path)
    if name.encode("ascii") != expected_name or prefix.encode("ascii") != expected_prefix:
        raise ArtifactError("USTAR name/prefix representation differs")
    return path, size


def _rebuild_ustar(entries):
    stream = io.BytesIO()
    strict_length = 1024
    with tarfile.open(fileobj=stream, mode="w", format=tarfile.USTAR_FORMAT, encoding="utf-8") as archive:
        for path, data in entries:
            item = tarfile.TarInfo(path)
            item.type = tarfile.REGTYPE
            item.size = len(data)
            item.mode = 0o600
            item.uid = item.gid = item.mtime = 0
            item.uname = item.gname = ""
            archive.addfile(item, io.BytesIO(data))
            strict_length += 512 + ((len(data) + 511) // 512) * 512
    return stream.getvalue()[:strict_length]


def parse_canonical_ustar(raw, policy=None):
    """Parse and byte-rebuild the sole accepted canonical USTAR encoding."""
    if (not isinstance(raw, bytes) or len(raw) < 1024 or len(raw) > MAX_TAR_BYTES or len(raw) % 512 or
            raw[-1024:] != b"\0" * 1024):
        raise ArtifactError("USTAR framing differs")
    entries = []
    names = set()
    folded_components = {}
    position = 0
    previous = None
    total = 0
    while position < len(raw):
        header = raw[position:position + 512]
        if header == b"\0" * 512:
            if position + 1024 != len(raw) or raw[position:] != b"\0" * 1024:
                raise ArtifactError("USTAR must end in exactly two zero blocks")
            break
        path, size = _parse_header(header)
        encoded = path.encode("utf-8")
        if previous is not None and encoded <= previous:
            raise ArtifactError("USTAR entries are not strict UTF-8 byte order")
        previous = encoded
        _register_path(path, names, folded_components)
        start = position + 512
        end = start + size
        padded = start + ((size + 511) // 512) * 512
        if padded > len(raw) or any(raw[end:padded]):
            raise ArtifactError("USTAR payload or zero padding is invalid")
        data = raw[start:end]
        entries.append((path, data))
        if len(entries) > MAX_ENTRIES:
            raise ArtifactError("USTAR entry count exceeds ceiling")
        total += size
        if total > MAX_TAR_BYTES:
            raise ArtifactError("USTAR expanded bytes exceed ceiling")
        position = padded
    else:
        raise ArtifactError("USTAR has no exact end marker")
    if not entries or _rebuild_ustar(entries) != raw:
        raise ArtifactError("USTAR bytes are not canonical producer bytes")
    files = dict(entries)
    if policy is not None:
        _enforce_policy(files, policy)
    return files


# Backward import name retained for callers; semantics are now stricter.
parse_hostile_tar = parse_canonical_ustar


def _enforce_policy(files, policy):
    limits = policy["limits"]
    paths = policy["paths"]
    allowed_files = set(paths["allowed_files"])
    allowed_prefixes = tuple(paths["allowed_prefixes"])
    if len(files) > limits["max_entries"] or sum(len(data) for data in files.values()) > limits["max_payload_bytes"]:
        raise ArtifactError("canonical release exceeds policy inventory limits")
    for name, data in files.items():
        if len(name.encode("utf-8")) > limits["max_path_bytes"] or len(data) > limits["max_file_bytes"]:
            raise ArtifactError("canonical release entry exceeds policy limit")
        if name not in allowed_files and not any(name.startswith(prefix) for prefix in allowed_prefixes):
            raise ArtifactError("canonical release path is outside policy")
    if not set(paths["required_files"]).issubset(files):
        raise ArtifactError("canonical release required file is absent")
    if any(not any(name.startswith(prefix) for name in files) for prefix in paths["required_prefixes"]):
        raise ArtifactError("canonical release required prefix is absent")


def unpack_github_artifact(raw):
    if not isinstance(raw, bytes) or not raw or len(raw) > MAX_TAR_BYTES:
        raise ArtifactError("GitHub artifact transport exceeds cap")
    try:
        archive = zipfile.ZipFile(io.BytesIO(raw), "r")
    except (zipfile.BadZipFile, OSError) as exc:
        raise ArtifactError("GitHub artifact is not ZIP transport") from exc
    with archive:
        if archive.comment or len(archive.infolist()) != 2:
            raise ArtifactError("GitHub ZIP inventory differs")
        values = {}
        for info in archive.infolist():
            name = info.filename
            mode = (info.external_attr >> 16) & 0o177777
            maximum = MAX_TAR_BYTES if name == "canonical-reverse.tar" else MAX_JSON_BYTES
            if (name not in {"canonical-reverse.tar", "canonical-reverse-receipt.json"} or name in values or info.is_dir() or
                    stat.S_IFMT(mode) not in (0, stat.S_IFREG) or info.file_size < 1 or info.file_size > MAX_TAR_BYTES or
                    info.file_size > maximum or info.flag_bits & 0x1 or
                    info.compress_size < 1 or info.compress_size > len(raw) or info.file_size > info.compress_size * 1000 + 1024 * 1024):
                raise ArtifactError("GitHub ZIP member is unsafe")
            try:
                with archive.open(info, "r") as stream:
                    data = stream.read(info.file_size + 1)
            except (OSError, RuntimeError, EOFError, zipfile.BadZipFile) as exc:
                raise ArtifactError("GitHub ZIP member cannot be read safely") from exc
            if len(data) != info.file_size:
                raise ArtifactError("GitHub ZIP member changed during read")
            values[name] = data
    if set(values) != {"canonical-reverse.tar", "canonical-reverse-receipt.json"}:
        raise ArtifactError("GitHub ZIP must contain exact canonical pair")
    return values["canonical-reverse.tar"], values["canonical-reverse-receipt.json"]


def _inventory_sha256(files):
    digest = hashlib.sha256()
    for name, data in sorted(files.items(), key=lambda item: item[0].encode("utf-8")):
        digest.update(b"file\0" + name.encode("utf-8") + b"\0")
        digest.update(_sha(data).encode("ascii") + b"\0" + str(len(data)).encode("ascii") + b"\n")
    return digest.hexdigest()


def _validate_provenance(value, authority):
    value = _exact_keys(value, {"schema", "source", "signer", "candidate", "run", "artifact", "runner", "tools", "cache", "test_matrix"}, "receipt provenance")
    if value["schema"] != "spspy.trusted-reverse-producer-v2.binding":
        raise ArtifactError("receipt provenance schema differs")
    source = _exact_keys(value["source"], {"id", "repository", "commit", "ref"}, "receipt source")
    if source != {"id": str(authority.caller_repository_id), "repository": authority.caller_repository,
                  "commit": authority.caller_commit, "ref": authority.caller_ref}:
        raise ArtifactError("receipt caller source differs from external authority")
    candidate = _exact_keys(value["candidate"], {"commit", "ref", "tree"}, "receipt candidate")
    if candidate != {"commit": authority.candidate_commit, "ref": authority.candidate_ref, "tree": authority.candidate_tree}:
        raise ArtifactError("receipt candidate differs from external authority")
    signer = _exact_keys(value["signer"], {"repository", "workflow_path", "workflow_ref", "commit", "blob"}, "receipt signer")
    if signer != {"repository": authority.signer_repository, "workflow_path": authority.signer_workflow_path,
                  "workflow_ref": authority.signer_workflow_identity, "commit": authority.signer_commit, "blob": authority.signer_blob}:
        raise ArtifactError("receipt signer differs from external authority")
    run = _exact_keys(value["run"], {"id", "attempt", "finalize_job", "prepare_result"}, "receipt run")
    if (run != {"id": str(authority.run_id), "attempt": str(authority.run_attempt), "finalize_job": FINALIZE_JOB,
                "prepare_result": "success"}):
        raise ArtifactError("receipt run differs from external authority")
    if _exact_keys(value["artifact"], {"name"}, "receipt artifact") != {"name": authority.receipt_artifact_name}:
        raise ArtifactError("receipt artifact name differs from external authority")
    runner = _exact_keys(value["runner"], {"os", "image"}, "receipt runner")
    if runner != {"os": authority.runner_os, "image": authority.runner_image}:
        raise ArtifactError("receipt runner differs from external authority")
    if value["cache"] != {"shared": False, "enabled": False}:
        raise ArtifactError("receipt cache boundary differs")
    if (not isinstance(value["tools"], dict) or not value["tools"] or
            any(not isinstance(key, str) or not isinstance(item, str) or not item for key, item in value["tools"].items())):
        raise ArtifactError("receipt tools evidence is invalid")
    if not isinstance(value["test_matrix"], dict) or not value["test_matrix"]:
        raise ArtifactError("receipt test matrix evidence is invalid")
    return value


def _bounded_digest_object(value, label):
    value = _exact_keys(value, {"bytes", "sha256"}, label)
    if type(value["bytes"]) is not int or value["bytes"] < 0:
        raise ArtifactError("%s byte count is invalid" % label)
    _sha256(value["sha256"], label + " digest")
    return value


def _validate_receipt(receipt_bytes, payload, files, policy, authority):
    """Validate the producer's version-1 nested canonical receipt contract."""
    authority.checked()
    receipt = _json_bytes(receipt_bytes, "canonical receipt")
    if _canonical(receipt) != receipt_bytes:
        raise ArtifactError("canonical receipt bytes are not canonical JSON")
    required = {"canonical", "canonicalization", "candidate_inventory", "payload", "provenance", "raw",
                "release_policy", "source_receipt", "schema", "version"}
    _exact_keys(receipt, required, "canonical receipt")
    if receipt["schema"] != RECEIPT_SCHEMA or receipt["version"] != 1:
        raise ArtifactError("canonical receipt schema/version differs")
    canonical = _bounded_digest_object(receipt["canonical"], "receipt canonical")
    if canonical != {"bytes": len(payload), "sha256": _sha(payload)}:
        raise ArtifactError("canonical receipt does not bind tar bytes")
    if receipt["canonicalization"] != ARCHIVE_CONTRACT:
        raise ArtifactError("canonicalization is not producer ustar-v1")
    inventory = _exact_keys(receipt["candidate_inventory"], {"bytes", "commit", "entries", "format", "sha256", "tree"},
                            "candidate inventory")
    if (type(inventory["bytes"]) is not int or inventory["bytes"] < 0 or
            type(inventory["entries"]) is not int or inventory["entries"] <= 0):
        raise ArtifactError("candidate inventory counts are invalid")
    if inventory.get("sha256") != authority.candidate_input_tree_sha256:
        raise ArtifactError("candidate inventory differs from external authority")
    if (inventory["commit"] != authority.candidate_commit or inventory["tree"] != authority.candidate_tree or
            inventory["format"] != INVENTORY_CONTRACT["format"] or inventory["entries"] != len(files) or
            inventory["bytes"] != sum(len(data) for data in files.values())):
        raise ArtifactError("candidate inventory entry count differs")
    if inventory["sha256"] != _inventory_sha256(files):
        raise ArtifactError("candidate inventory does not bind canonical files")
    payload_object = receipt["payload"]
    _exact_keys(payload_object, {"bytes", "entries", "input_tree_sha256", "sha256"}, "receipt payload")
    if (type(payload_object["bytes"]) is not int or type(payload_object["entries"]) is not int or
            payload_object["bytes"] < 0 or payload_object["entries"] <= 0 or
            payload_object["bytes"] != sum(len(data) for data in files.values()) or payload_object["entries"] != len(files) or
            payload_object["input_tree_sha256"] != authority.candidate_input_tree_sha256 or
            payload_object["sha256"] != authority.candidate_input_tree_sha256):
        raise ArtifactError("receipt payload inventory differs")
    _validate_provenance(receipt["provenance"], authority)
    _bounded_digest_object(receipt["raw"], "receipt raw")
    _bounded_digest_object(receipt["source_receipt"], "receipt source receipt")
    release_policy = _exact_keys(receipt["release_policy"], {"blob", "sha256"}, "receipt release policy")
    if release_policy["blob"] != policy or release_policy["sha256"] != authority.policy_sha256:
        raise ArtifactError("receipt release policy differs from external authority")
    return receipt


class GitHubAdapter:
    """Read-only GitHub API boundary. Jobs must use the attempt-specific endpoint."""
    def repository_metadata(self, *, repository):
        raise NotImplementedError

    def artifact_metadata(self, *, repository, artifact_id):
        raise NotImplementedError

    def download_artifact(self, *, repository, artifact_id):
        raise NotImplementedError

    def workflow_run(self, *, repository, run_id):
        raise NotImplementedError

    def jobs_for_run_attempt(self, *, repository, run_id, run_attempt):
        raise NotImplementedError

    def git_blob(self, *, repository, commit, path):
        """Return ``{"oid": <40hex>, "bytes": <raw blob bytes>}``."""
        raise NotImplementedError


def _metadata_digest(metadata):
    digest = metadata.get("digest") if isinstance(metadata, dict) else None
    if not isinstance(digest, str) or not digest.startswith("sha256:"):
        raise ArtifactError("artifact metadata has no SHA-256 digest")
    return _sha256(digest[7:], "artifact metadata digest")


def _git_blob_oid(data):
    if not isinstance(data, bytes):
        raise ArtifactError("Git blob content must be bytes")
    framed = b"blob " + str(len(data)).encode("ascii") + b"\0" + data
    return hashlib.sha1(framed).hexdigest()


def _verify_repository_and_blobs(adapter, authority, trusted_policy_bytes):
    for repository, repository_id in ((authority.candidate_repository, authority.candidate_repository_id),
                                      (authority.caller_repository, authority.caller_repository_id),
                                      (authority.signer_repository, authority.signer_repository_id)):
        metadata = adapter.repository_metadata(repository=repository)
        if not isinstance(metadata, dict) or metadata.get("id") != repository_id or metadata.get("full_name") != repository:
            raise ArtifactError("GitHub repository identity differs")
    workflow = adapter.git_blob(repository=authority.signer_repository, commit=authority.signer_commit,
                                path=authority.signer_workflow_path)
    if (not isinstance(workflow, dict) or workflow.get("oid") != authority.signer_blob or
            not isinstance(workflow.get("bytes"), bytes) or _git_blob_oid(workflow["bytes"]) != authority.signer_blob or
            _sha(workflow["bytes"]) != authority.signer_workflow_sha256):
        raise ArtifactError("signer workflow blob/bytes differ")
    policy = adapter.git_blob(repository=authority.signer_repository, commit=authority.signer_commit, path=authority.policy_path)
    if (not isinstance(policy, dict) or policy.get("oid") != authority.policy_blob or policy.get("bytes") != trusted_policy_bytes or
            _git_blob_oid(trusted_policy_bytes) != authority.policy_blob or
            _sha(policy.get("bytes", b"")) != authority.policy_sha256):
        raise ArtifactError("release policy Git blob differs")


def _verify_rest(adapter, authority):
    metadata = adapter.artifact_metadata(repository=authority.caller_repository, artifact_id=authority.artifact_id)
    required = {"id", "name", "size_in_bytes", "expired", "workflow_run", "digest"}
    if (not isinstance(metadata, dict) or not required.issubset(metadata) or
            metadata.get("id") != authority.artifact_id or metadata.get("name") != authority.artifact_name or
            metadata.get("expired") is not False or type(metadata.get("size_in_bytes")) is not int or
            metadata["size_in_bytes"] <= 0 or metadata["size_in_bytes"] > MAX_TAR_BYTES):
        raise ArtifactError("GitHub artifact metadata differs")
    workflow_artifact = metadata.get("workflow_run")
    expected_branch = authority.caller_ref[len("refs/heads/"):] if authority.caller_ref.startswith("refs/heads/") else authority.caller_ref
    expected_artifact_run = {"id": authority.run_id, "repository_id": authority.caller_repository_id,
                             "head_repository_id": authority.caller_repository_id, "head_branch": expected_branch,
                             "head_sha": authority.caller_commit}
    if not isinstance(workflow_artifact, dict) or any(workflow_artifact.get(key) != value for key, value in expected_artifact_run.items()):
        raise ArtifactError("artifact workflow run linkage differs")
    run = adapter.workflow_run(repository=authority.caller_repository, run_id=authority.run_id)
    if (not isinstance(run, dict) or run.get("id") != authority.run_id or run.get("run_attempt") != authority.run_attempt or
            run.get("head_sha") != authority.caller_commit or run.get("head_branch") != expected_branch or
            run.get("event") != "workflow_dispatch" or run.get("status") != "completed" or run.get("conclusion") != "success" or
            run.get("workflow_id") != authority.caller_workflow_id or run.get("path") != authority.caller_workflow_path or
            not isinstance(run.get("repository"), dict) or run["repository"].get("id") != authority.caller_repository_id or
            run["repository"].get("full_name") != authority.caller_repository or
            not isinstance(run.get("head_repository"), dict) or run["head_repository"].get("id") != authority.caller_repository_id or
            run["head_repository"].get("full_name") != authority.caller_repository):
        raise ArtifactError("GitHub workflow run differs")
    jobs = adapter.jobs_for_run_attempt(repository=authority.caller_repository, run_id=authority.run_id,
                                        run_attempt=authority.run_attempt)
    if not isinstance(jobs, list):
        raise ArtifactError("attempt-specific jobs response is invalid")
    matches = [job for job in jobs if isinstance(job, dict) and job.get("id") == authority.job_id and job.get("name") == authority.job_name]
    if len(matches) != 1:
        raise ArtifactError("exact finalize job is absent or ambiguous")
    job = matches[0]
    if (job.get("run_id") != authority.run_id or job.get("run_attempt") != authority.run_attempt or
            job.get("head_sha") != authority.caller_commit or job.get("head_branch") != expected_branch or
            job.get("status") != "completed" or job.get("conclusion") != "success" or
            not isinstance(job.get("labels"), list) or authority.runner_label not in job["labels"] or
            type(job.get("runner_id")) is not int or job["runner_id"] <= 0 or
            not isinstance(job.get("runner_name"), str) or not job["runner_name"] or job.get("runner_group_name") != "GitHub Actions"):
        raise ArtifactError("attempt-specific finalize job differs")
    return metadata, run, job


def _certificate_expected(certificate, authority):
    expected = {"issuer": "https://token.actions.githubusercontent.com", "sourceRepositoryURI": authority.caller_uri,
                "sourceRepositoryDigest": authority.caller_commit, "sourceRepositoryRef": authority.caller_ref,
                "sourceRepositoryIdentifier": str(authority.caller_repository_id),
                "buildSignerURI": authority.signer_uri, "buildSignerDigest": authority.signer_commit,
                "buildConfigURI": authority.caller_workflow_uri, "buildConfigDigest": authority.caller_commit,
                "githubWorkflowTrigger": "workflow_dispatch", "githubWorkflowSHA": authority.caller_commit,
                "githubWorkflowRepository": authority.caller_repository, "githubWorkflowRef": authority.caller_ref,
                "buildTrigger": "workflow_dispatch",
                "runnerEnvironment": "github-hosted", "runInvocationURI": authority.invocation_uri,
                "subjectAlternativeName": authority.signer_uri}
    if not isinstance(certificate, dict) or any(certificate.get(key) != value for key, value in expected.items()):
        raise ArtifactError("verified certificate authority differs")
    return {key: certificate[key] for key in sorted(expected)}


def _default_slsa(statement, authority, subject_name, subject_sha256):
    if (not isinstance(statement, dict) or statement.get("_type") != "https://in-toto.io/Statement/v1" or
            statement.get("predicateType") != PREDICATE_TYPE):
        raise ArtifactError("attestation statement predicate type differs")
    subjects = statement.get("subject")
    if (not isinstance(subjects, list) or not any(isinstance(subject, dict) and subject.get("name") == subject_name and
            isinstance(subject.get("digest"), dict) and subject["digest"].get("sha256") == subject_sha256 for subject in subjects)):
        raise ArtifactError("attestation statement does not bind subject")
    predicate = statement.get("predicate")
    if not isinstance(predicate, dict):
        raise ArtifactError("default SLSA predicate is absent")
    definition = predicate.get("buildDefinition")
    details = predicate.get("runDetails")
    if not isinstance(definition, dict) or definition.get("buildType") != SLSA_BUILD_TYPE or not isinstance(details, dict):
        raise ArtifactError("default GitHub Actions SLSA shape differs")
    external = definition.get("externalParameters")
    workflow = external.get("workflow") if isinstance(external, dict) else None
    if (not isinstance(workflow, dict) or workflow.get("ref") != authority.caller_ref or
            workflow.get("repository") != authority.caller_uri or workflow.get("path") not in
            (authority.caller_workflow_path, "/" + authority.caller_workflow_path)):
        raise ArtifactError("default SLSA caller workflow differs")
    dependencies = definition.get("resolvedDependencies")
    expected_uri = "git+https://github.com/%s@%s" % (authority.caller_repository, authority.caller_ref)
    if (not isinstance(dependencies, list) or not any(isinstance(item, dict) and item.get("uri") == expected_uri and
            isinstance(item.get("digest"), dict) and item["digest"].get("gitCommit") == authority.caller_commit for item in dependencies)):
        raise ArtifactError("default SLSA dependency differs")
    internal = definition.get("internalParameters")
    github = internal.get("github") if isinstance(internal, dict) else None
    if (not isinstance(github, dict) or github.get("event_name") != "workflow_dispatch" or
            github.get("repository_id") != str(authority.caller_repository_id)):
        raise ArtifactError("default SLSA internal caller identity differs")
    builder = details.get("builder")
    metadata = details.get("metadata")
    if (not isinstance(builder, dict) or builder.get("id") != HOSTED_BUILDER or not isinstance(metadata, dict) or
            metadata.get("invocationId") != authority.invocation_uri):
        raise ArtifactError("default SLSA run details differ")


def _parse_gh_output(stdout, authority, subject_name, subject_sha256):
    values = _json_bytes(stdout, "gh verification output", MAX_GH_OUTPUT_BYTES)
    if not isinstance(values, list) or not values:
        raise ArtifactError("gh verification returned no attestations")
    normalized = []
    for value in values:
        if (not isinstance(value, dict) or not isinstance(value.get("attestation"), dict) or
                not isinstance(value["attestation"].get("bundle"), dict)):
            raise ArtifactError("gh verification item lacks attestation")
        result = value.get("verificationResult")
        if (not isinstance(result, dict) or
                result.get("mediaType") != "application/vnd.dev.sigstore.verificationresult+json;version=0.1"):
            raise ArtifactError("gh verificationResult is absent")
        signature = result.get("signature")
        certificate = signature.get("certificate") if isinstance(signature, dict) else None
        certificate = _certificate_expected(certificate, authority)
        timestamps = result.get("verifiedTimestamps")
        if not isinstance(timestamps, list) or not timestamps or any(not isinstance(item, dict) or not item for item in timestamps):
            raise ArtifactError("gh verified timestamps are absent")
        _default_slsa(result.get("statement"), authority, subject_name, subject_sha256)
        normalized.append({"certificate": certificate, "subject": subject_name, "sha256": subject_sha256,
                           "timestamp_count": len(timestamps)})
    return normalized


def _hash_regular_executable(path):
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise ArtifactError("trusted gh executable is unavailable") from exc
    try:
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or stat.S_IMODE(before.st_mode) != 0o555 or
                before.st_nlink != 1 or before.st_uid != os.getuid()):
            raise ArtifactError("trusted gh executable metadata is unsafe")
        digest = hashlib.sha256()
        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            digest.update(chunk)
        after = os.fstat(fd)
        before_identity = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns,
                           stat.S_IMODE(before.st_mode), before.st_uid, before.st_nlink)
        after_identity = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns,
                          stat.S_IMODE(after.st_mode), after.st_uid, after.st_nlink)
        if before_identity != after_identity:
            raise ArtifactError("trusted gh executable changed during hash")
        return before_identity + (digest.hexdigest(),)
    finally:
        os.close(fd)


def _bounded_subprocess(argv, cwd, timeout_seconds):
    if (not isinstance(argv, list) or not argv or any(not isinstance(item, str) or not item for item in argv) or
            type(timeout_seconds) is not int or timeout_seconds <= 0 or timeout_seconds > 120):
        raise ArtifactError("trusted gh process arguments are invalid")
    environment = {"HOME": cwd, "GH_CONFIG_DIR": cwd, "GH_PROMPT_DISABLED": "1", "GH_NO_UPDATE_NOTIFIER": "1",
                   "LANG": "C", "LC_ALL": "C", "NO_COLOR": "1", "PAGER": "cat", "PATH": "", "TERM": "dumb"}
    # Credentials, when required for a private repository, are supplied only by
    # the host process.  No config file or repository value becomes an env var.
    if os.environ.get("GH_TOKEN"):
        environment["GH_TOKEN"] = os.environ["GH_TOKEN"]
    try:
        process = subprocess.Popen(argv, cwd=cwd, env=environment, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, shell=False, start_new_session=True)
    except OSError as exc:
        raise ArtifactError("trusted gh process failed") from exc
    selector = selectors.DefaultSelector()
    outputs = {"stdout": bytearray(), "stderr": bytearray()}
    streams = {process.stdout: "stdout", process.stderr: "stderr"}
    deadline = time.monotonic() + timeout_seconds
    try:
        for stream, label in streams.items():
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, label)
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ArtifactError("trusted gh process timed out")
            for key, _mask in selector.select(min(remaining, 0.25)):
                try:
                    chunk = os.read(key.fileobj.fileno(), 65536)
                except BlockingIOError:
                    continue
                if not chunk:
                    selector.unregister(key.fileobj)
                    key.fileobj.close()
                    continue
                output = outputs[key.data]
                output.extend(chunk)
                if len(output) > MAX_GH_OUTPUT_BYTES:
                    raise ArtifactError("trusted gh output exceeded cap")
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise ArtifactError("trusted gh process timed out")
        returncode = process.wait(timeout=remaining)
        return returncode, bytes(outputs["stdout"]), bytes(outputs["stderr"])
    except subprocess.TimeoutExpired as exc:
        raise ArtifactError("trusted gh process timed out") from exc
    finally:
        if process.poll() is None:
            process.kill()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            pass
        for stream in streams:
            if not stream.closed:
                stream.close()
        selector.close()


def _production_gh(argv, *, cwd, timeout_seconds):
    if not isinstance(argv, list) or not argv or argv[0] != GH_EXECUTABLE:
        raise ArtifactError("gh argv does not use fixed absolute executable")
    before = _hash_regular_executable(GH_EXECUTABLE)
    if before[-1] != GH_EXECUTABLE_SHA256:
        raise ArtifactError("trusted gh executable digest differs")
    version = _bounded_subprocess([GH_EXECUTABLE, "--version"], cwd, 5)
    if version[0] != 0 or version[1].decode("utf-8", "replace").splitlines()[0] != GH_VERSION:
        raise ArtifactError("trusted gh version differs")
    result = _bounded_subprocess(argv, cwd, timeout_seconds)
    after = _hash_regular_executable(GH_EXECUTABLE)
    if after != before:
        raise ArtifactError("trusted gh executable changed across invocation")
    return result


def _call_gh(runner, argv, cwd, timeout_seconds):
    result = runner(argv, cwd=cwd, timeout_seconds=timeout_seconds)
    if not isinstance(result, tuple) or len(result) != 3:
        raise ArtifactError("gh runner returned invalid shape")
    code, stdout, stderr = result
    if (type(code) is not int or not isinstance(stdout, bytes) or not isinstance(stderr, bytes) or
            len(stdout) > MAX_GH_OUTPUT_BYTES or len(stderr) > MAX_GH_OUTPUT_BYTES):
        raise ArtifactError("gh runner crossed output boundary")
    return code, stdout, stderr


def _write_private(path, data):
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    fd = os.open(path, flags, 0o600)
    try:
        offset = 0
        while offset < len(data):
            written = os.write(fd, data[offset:])
            if written <= 0:
                raise ArtifactError("private evidence write made no progress")
            offset += written
        os.fsync(fd)
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600 or
                info.st_uid != os.getuid() or info.st_nlink != 1 or info.st_size != len(data)):
            raise ArtifactError("private evidence file metadata differs")
    finally:
        os.close(fd)


def _read_private(path, maximum, *, normalize_mode=False):
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_CLOEXEC", 0)
    fd = os.open(path, flags)
    try:
        if normalize_mode:
            os.fchmod(fd, 0o600)
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or stat.S_IMODE(before.st_mode) != 0o600 or
                before.st_uid != os.getuid() or before.st_nlink != 1 or before.st_size < 1 or before.st_size > maximum):
            raise ArtifactError("private evidence file metadata is unsafe")
        chunks = []
        remaining = before.st_size
        while remaining:
            chunk = os.read(fd, min(65536, remaining))
            if not chunk:
                raise ArtifactError("private evidence file truncated")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(fd, 1):
            raise ArtifactError("private evidence file grew during read")
        after = os.fstat(fd)
        identity = lambda item: (item.st_dev, item.st_ino, item.st_size, item.st_mtime_ns, item.st_ctime_ns,
                                 stat.S_IMODE(item.st_mode), item.st_uid, item.st_nlink)
        if identity(before) != identity(after):
            raise ArtifactError("private evidence file changed during read")
        return b"".join(chunks)
    finally:
        os.close(fd)


def _verification_argv(*, subject_path, bundle_path, root_path, authority):
    authority.checked()
    # gh 2.87.3 makes --cert-identity, --signer-repo, and
    # --signer-workflow mutually exclusive.  Use the strongest exact SAN
    # selector here; parsed verified-certificate fields independently enforce
    # the signer repository, workflow path/ref, and commit.
    return [GH_EXECUTABLE, "attestation", "verify", subject_path, "-R", authority.caller_repository,
            "--cert-identity", authority.signer_uri,
            "--signer-digest", authority.signer_commit, "--source-digest", authority.caller_commit,
            "--source-ref", authority.caller_ref,
            "--cert-oidc-issuer", "https://token.actions.githubusercontent.com",
            "--deny-self-hosted-runners", "--predicate-type", PREDICATE_TYPE,
            "--bundle", bundle_path, "--custom-trusted-root", root_path, "--format", "json"]


def _verify_subject(*, subject_path, bundle_path, root_path, authority, subject_name, subject_sha256, runner, cwd):
    argv = _verification_argv(subject_path=subject_path, bundle_path=bundle_path, root_path=root_path,
                              authority=authority)
    code, stdout, _stderr = _call_gh(runner, argv, cwd, 120)
    if code != 0:
        raise ArtifactError("gh attestation verify rejected subject")
    return _parse_gh_output(stdout, authority, subject_name, subject_sha256)


def _download_and_verify(subject_name, subject_bytes, trusted_root_bytes, authority, runner):
    with tempfile.TemporaryDirectory(prefix="spspy-attestation-v2-") as directory:
        if stat.S_IMODE(os.stat(directory, follow_symlinks=False).st_mode) != 0o700:
            raise ArtifactError("attestation temporary directory mode differs")
        subject_path = os.path.join(directory, subject_name)
        _write_private(subject_path, subject_bytes)
        before = set(os.listdir(directory))
        code, _stdout, _stderr = _call_gh(runner, [GH_EXECUTABLE, "attestation", "download", subject_path,
                                                  "-R", authority.caller_repository,
                                                  "--predicate-type", PREDICATE_TYPE], directory, 60)
        if code != 0:
            raise ArtifactError("gh attestation download rejected subject")
        expected_name = "sha256:%s.jsonl" % _sha(subject_bytes)
        if set(os.listdir(directory)) - before != {expected_name}:
            raise ArtifactError("gh download did not create the sole expected bundle")
        bundle_path = os.path.join(directory, expected_name)
        bundle = _read_private(bundle_path, MAX_BUNDLE_BYTES, normalize_mode=True)
        if _read_private(subject_path, len(subject_bytes)) != subject_bytes:
            raise ArtifactError("gh changed the attestation subject")
        _jsonl(bundle, "downloaded attestation bundle")
        root_path = os.path.join(directory, "trusted-root.jsonl")
        _write_private(root_path, trusted_root_bytes)
        claims = _verify_subject(subject_path=subject_path, bundle_path=bundle_path, root_path=root_path,
                                 authority=authority, subject_name=subject_name, subject_sha256=_sha(subject_bytes),
                                 runner=runner, cwd=directory)
        return bundle, claims


def _verify_bundle_offline(subject_name, subject_bytes, bundle, trusted_root_bytes, authority, runner, directory):
    _jsonl(bundle, "offline attestation bundle")
    subject_path = os.path.join(directory, subject_name)
    bundle_path = os.path.join(directory, subject_name + ".bundle.jsonl")
    root_path = os.path.join(directory, "trusted-root.jsonl")
    _write_private(subject_path, subject_bytes)
    _write_private(bundle_path, bundle)
    if not os.path.exists(root_path):
        _write_private(root_path, trusted_root_bytes)
    elif _read_private(root_path, len(trusted_root_bytes)) != trusted_root_bytes:
        raise ArtifactError("offline trusted root changed between subjects")
    return _verify_subject(subject_path=subject_path, bundle_path=bundle_path, root_path=root_path,
                           authority=authority, subject_name=subject_name, subject_sha256=_sha(subject_bytes),
                           runner=runner, cwd=directory)


@dataclasses.dataclass(frozen=True)
class VerifiedArtifact:
    payload: bytes
    receipt_bytes: bytes
    receipt: dict
    authority: ExpectedAuthority
    transport_sha256: str
    tar_bundle: bytes
    receipt_bundle: bytes
    rest_evidence: dict


@dataclasses.dataclass(frozen=True)
class OfflineVerifiedEnvelope:
    """Convenience result only; CAS never treats its type as authority."""
    envelope_sha256: str
    payload_sha256: str
    r1_receipt_sha256: str
    r2_receipt_sha256: str


_ACTIVATION_PROOF_TOKEN = object()


class ActivationReverifyResult:
    """Opaque result minted only by a fresh full activation re-verification."""
    __slots__ = ("_authority_digest", "_envelope_digest", "_payload_digest", "_trusted_root_digest", "_locked")

    def __new__(cls, token, *, authority_digest, envelope_digest, payload_digest, trusted_root_digest):
        if token is not _ACTIVATION_PROOF_TOKEN:
            raise ArtifactError("activation proof cannot be constructed directly")
        instance = super().__new__(cls)
        object.__setattr__(instance, "_authority_digest", _sha256(authority_digest, "activation authority digest"))
        object.__setattr__(instance, "_envelope_digest", _sha256(envelope_digest, "activation envelope digest"))
        object.__setattr__(instance, "_payload_digest", _sha256(payload_digest, "activation payload digest"))
        object.__setattr__(instance, "_trusted_root_digest", _sha256(trusted_root_digest, "activation trusted root digest"))
        object.__setattr__(instance, "_locked", True)
        return instance

    def __setattr__(self, _name, _value):
        raise AttributeError("activation proof is immutable")

    @property
    def authority_digest(self):
        return self._authority_digest

    @property
    def envelope_digest(self):
        return self._envelope_digest

    @property
    def payload_digest(self):
        return self._payload_digest

    @property
    def trusted_root_digest(self):
        return self._trusted_root_digest


def verify_artifact(*, adapter, authority, trusted_root_bytes, trusted_policy_bytes, gh_runner=None):
    authority = authority.checked()
    runner = _production_gh if gh_runner is None else gh_runner
    _trusted_root(trusted_root_bytes, authority)
    policy = _load_policy(trusted_policy_bytes, authority)
    _verify_repository_and_blobs(adapter, authority, trusted_policy_bytes)
    metadata, run, job = _verify_rest(adapter, authority)
    raw = adapter.download_artifact(repository=authority.caller_repository, artifact_id=authority.artifact_id)
    if (not isinstance(raw, bytes) or type(metadata.get("size_in_bytes")) is not int or len(raw) != metadata["size_in_bytes"] or
            _sha(raw) != _metadata_digest(metadata)):
        raise ArtifactError("artifact transport bytes differ from REST digest")
    payload, receipt_bytes = unpack_github_artifact(raw)
    files = parse_canonical_ustar(payload, policy)
    receipt = _validate_receipt(receipt_bytes, payload, files, policy, authority)
    tar_bundle, _ = _download_and_verify("canonical-reverse.tar", payload, trusted_root_bytes, authority, runner)
    receipt_bundle, _ = _download_and_verify("canonical-reverse-receipt.json", receipt_bytes, trusted_root_bytes, authority, runner)
    rest_evidence = {"artifact": {"id": metadata["id"], "name": metadata["name"], "digest": metadata["digest"],
                                  "size_in_bytes": metadata["size_in_bytes"],
                                  "workflow_run": {key: metadata["workflow_run"].get(key) for key in
                                                   ("id", "repository_id", "head_repository_id", "head_branch", "head_sha")}},
                     "run": {key: run.get(key) for key in ("id", "run_attempt", "head_sha", "head_branch", "workflow_id", "path")},
                     "job": {key: job.get(key) for key in ("id", "name", "run_id", "run_attempt", "head_sha", "head_branch",
                                                                  "conclusion", "labels", "runner_id", "runner_name", "runner_group_name")}}
    return VerifiedArtifact(payload=payload, receipt_bytes=receipt_bytes, receipt=receipt, authority=authority,
                            transport_sha256=_sha(raw), tar_bundle=tar_bundle, receipt_bundle=receipt_bundle,
                            rest_evidence=rest_evidence)


def _stable_receipt(receipt):
    return _canonical({"candidate_inventory": receipt["candidate_inventory"], "payload": receipt["payload"],
                       "release_policy": receipt["release_policy"], "canonical": receipt["canonical"],
                       "canonicalization": receipt["canonicalization"]})


def seal_receipt_pair(r1, r2):
    if not isinstance(r1, VerifiedArtifact) or not isinstance(r2, VerifiedArtifact):
        raise ArtifactError("R1/R2 must be online verified artifacts")
    _independent_authorities(r1.authority, r2.authority)
    if r1.payload != r2.payload or _stable_receipt(r1.receipt) != _stable_receipt(r2.receipt):
        raise ArtifactError("R1/R2 canonical payload semantics differ")
    envelope = {"schema": ENVELOPE_SCHEMA, "payload_sha256": _sha(r1.payload),
                "r1": {"transport_sha256": r1.transport_sha256, "receipt": base64.b64encode(r1.receipt_bytes).decode("ascii"),
                       "tar_bundle": base64.b64encode(r1.tar_bundle).decode("ascii"),
                       "receipt_bundle": base64.b64encode(r1.receipt_bundle).decode("ascii"), "rest": r1.rest_evidence},
                "r2": {"transport_sha256": r2.transport_sha256, "receipt": base64.b64encode(r2.receipt_bytes).decode("ascii"),
                       "tar_bundle": base64.b64encode(r2.tar_bundle).decode("ascii"),
                       "receipt_bundle": base64.b64encode(r2.receipt_bundle).decode("ascii"), "rest": r2.rest_evidence}}
    raw = _canonical(envelope)
    index = _canonical({"schema": "spspy-isolated-release-evidence-index/v2", "envelope_sha256": _sha(raw),
                        "payload_sha256": _sha(r1.payload)})
    return raw, index


def _envelope_item(envelope, label):
    item = _exact_keys(envelope[label], {"transport_sha256", "receipt", "tar_bundle", "receipt_bundle", "rest"}, label)
    transport_sha256 = _sha256(item["transport_sha256"], label + " transport digest")
    return (_base64(item["receipt"], label + " receipt"), _base64(item["tar_bundle"], label + " tar bundle"),
            _base64(item["receipt_bundle"], label + " receipt bundle"), item["rest"], transport_sha256)


def _expected_rest_evidence(rest, authority, transport_sha256):
    if not isinstance(rest, dict) or set(rest) != {"artifact", "run", "job"}:
        raise ArtifactError("sealed REST evidence shape differs")
    artifact = rest["artifact"]
    run = rest["run"]
    job = rest["job"]
    _exact_keys(artifact, {"id", "name", "digest", "size_in_bytes", "workflow_run"}, "sealed artifact evidence")
    _exact_keys(run, {"id", "run_attempt", "head_sha", "head_branch", "workflow_id", "path"}, "sealed run evidence")
    _exact_keys(job, {"id", "name", "run_id", "run_attempt", "head_sha", "head_branch", "conclusion", "labels",
                      "runner_id", "runner_name", "runner_group_name"}, "sealed job evidence")
    branch = authority.caller_ref[len("refs/heads/"):] if authority.caller_ref.startswith("refs/heads/") else authority.caller_ref
    workflow_run = _exact_keys(artifact["workflow_run"],
                               {"id", "repository_id", "head_repository_id", "head_branch", "head_sha"},
                               "sealed artifact workflow run")
    expected_workflow_run = {"id": authority.run_id, "repository_id": authority.caller_repository_id,
                             "head_repository_id": authority.caller_repository_id, "head_branch": branch,
                             "head_sha": authority.caller_commit}
    if (artifact["id"] != authority.artifact_id or artifact["name"] != authority.artifact_name or
            artifact["digest"] != "sha256:" + transport_sha256 or
            type(artifact["size_in_bytes"]) is not int or artifact["size_in_bytes"] <= 0 or
            artifact["size_in_bytes"] > MAX_TAR_BYTES or workflow_run != expected_workflow_run or
            run != {"id": authority.run_id, "run_attempt": authority.run_attempt, "head_sha": authority.caller_commit,
                    "head_branch": branch, "workflow_id": authority.caller_workflow_id,
                    "path": authority.caller_workflow_path} or
            job["id"] != authority.job_id or job["name"] != authority.job_name or job["run_id"] != authority.run_id or
            job["run_attempt"] != authority.run_attempt or job["head_sha"] != authority.caller_commit or
            job["head_branch"] != branch or job["conclusion"] != "success" or
            not isinstance(job["labels"], list) or authority.runner_label not in job["labels"] or
            type(job["runner_id"]) is not int or job["runner_id"] <= 0 or
            not isinstance(job["runner_name"], str) or not job["runner_name"] or
            job["runner_group_name"] != "GitHub Actions"):
        raise ArtifactError("sealed REST evidence differs from external authority")


def _offline_verify_internal(*, envelope_bytes, payload, trusted_root_bytes, trusted_policy_bytes, r1_authority, r2_authority,
                             gh_runner=None):
    r1_authority, r2_authority = _independent_authorities(r1_authority, r2_authority)
    runner = _production_gh if gh_runner is None else gh_runner
    for authority in (r1_authority, r2_authority):
        _trusted_root(trusted_root_bytes, authority)
    policy = _load_policy(trusted_policy_bytes, r1_authority)
    if _sha(trusted_policy_bytes) != r2_authority.policy_sha256:
        raise ArtifactError("R2 external policy digest differs")
    files = parse_canonical_ustar(payload, policy)
    envelope = _json_bytes(envelope_bytes, "release envelope", MAX_ENVELOPE_BYTES)
    if _canonical(envelope) != envelope_bytes:
        raise ArtifactError("release envelope bytes are not canonical JSON")
    _exact_keys(envelope, {"schema", "payload_sha256", "r1", "r2"}, "release envelope")
    if envelope["schema"] != ENVELOPE_SCHEMA or envelope["payload_sha256"] != _sha(payload):
        raise ArtifactError("release envelope payload differs")
    decoded = {}
    for label, authority in (("r1", r1_authority), ("r2", r2_authority)):
        receipt_bytes, tar_bundle, receipt_bundle, rest, transport_sha256 = _envelope_item(envelope, label)
        _expected_rest_evidence(rest, authority, transport_sha256)
        receipt = _validate_receipt(receipt_bytes, payload, files, policy, authority)
        with tempfile.TemporaryDirectory(prefix="spspy-offline-v2-") as directory:
            _verify_bundle_offline("canonical-reverse.tar", payload, tar_bundle, trusted_root_bytes, authority, runner, directory)
            _verify_bundle_offline("canonical-reverse-receipt.json", receipt_bytes, receipt_bundle, trusted_root_bytes,
                                   authority, runner, directory)
        decoded[label] = (receipt_bytes, tar_bundle, receipt_bundle, receipt)
    if _stable_receipt(decoded["r1"][3]) != _stable_receipt(decoded["r2"][3]):
        raise ArtifactError("offline R1/R2 receipt semantics differ")
    result = OfflineVerifiedEnvelope(envelope_sha256=_sha(envelope_bytes), payload_sha256=_sha(payload),
                                     r1_receipt_sha256=_sha(decoded["r1"][0]), r2_receipt_sha256=_sha(decoded["r2"][0]))
    return result, decoded


def offline_verify_to_seal(**kwargs):
    return _offline_verify_internal(**kwargs)[0]


def offline_verify_envelope(**kwargs):
    _offline_verify_internal(**kwargs)
    return True


def reverify_for_activation(*, envelope_bytes, payload, trusted_root_bytes, trusted_policy_bytes, r1_authority,
                            r2_authority, gh_runner=None):
    """Fresh activation gate; no authority is read from the envelope.

    Native activation must call this entry with its external R1/R2 authorities
    immediately before READY and bind the returned digests into durable state.
    """
    r1_authority, r2_authority = _independent_authorities(r1_authority, r2_authority)
    _offline_verify_internal(envelope_bytes=envelope_bytes, payload=payload, trusted_root_bytes=trusted_root_bytes,
                             trusted_policy_bytes=trusted_policy_bytes, r1_authority=r1_authority,
                             r2_authority=r2_authority, gh_runner=gh_runner)
    authority_bytes = _canonical({"r1": dataclasses.asdict(r1_authority), "r2": dataclasses.asdict(r2_authority)})
    return ActivationReverifyResult(_ACTIVATION_PROOF_TOKEN, authority_digest=_sha(authority_bytes),
                                    envelope_digest=_sha(envelope_bytes), payload_digest=_sha(payload),
                                    trusted_root_digest=_sha(trusted_root_bytes))


def _acquire_cas_lock(fd):
    """Acquire the CAS lock without permitting an unbounded process stall."""
    deadline = time.monotonic() + CAS_LOCK_TIMEOUT_SECONDS
    while True:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return
        except OSError as exc:
            if exc.errno not in (errno.EACCES, errno.EAGAIN):
                raise ArtifactError("CAS lock acquisition failed") from exc
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ArtifactError("CAS lock is busy after bounded wait") from exc
            time.sleep(min(CAS_LOCK_RETRY_SECONDS, remaining))


class RepositoryCAS:
    """Transactional release store; every store call repeats offline verification."""
    def __init__(self, root):
        flags = os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_CLOEXEC", 0)
        self.root = os.open(os.fspath(root), flags)
        try:
            self._check_dir_fd(self.root, "CAS root")
        except BaseException:
            os.close(self.root)
            self.root = None
            raise

    @staticmethod
    def _check_dir_fd(fd, label):
        info = os.fstat(fd)
        if (not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o700 or info.st_uid != os.getuid() or
                info.st_nlink < 2):
            raise ArtifactError("%s metadata is unsafe" % label)

    def close(self):
        if self.root is not None:
            os.close(self.root)
            self.root = None

    def __enter__(self):
        return self

    def __exit__(self, *unused):
        self.close()

    def _child_dir(self, parent_fd, name, create=False):
        if not SAFE_COMPONENT.fullmatch(name):
            raise ArtifactError("CAS directory name is unsafe")
        if create:
            try:
                os.mkdir(name, 0o700, dir_fd=parent_fd)
            except FileExistsError:
                pass
        flags = os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_CLOEXEC", 0)
        fd = os.open(name, flags, dir_fd=parent_fd)
        try:
            self._check_dir_fd(fd, "CAS child directory")
        except BaseException:
            os.close(fd)
            raise
        return fd

    @staticmethod
    def _read_file(parent_fd, name, maximum=MAX_TAR_BYTES):
        if not SAFE_COMPONENT.fullmatch(name):
            raise ArtifactError("CAS file name is unsafe")
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_CLOEXEC", 0)
        fd = os.open(name, flags, dir_fd=parent_fd)
        try:
            before = os.fstat(fd)
            if (not stat.S_ISREG(before.st_mode) or stat.S_IMODE(before.st_mode) != 0o600 or before.st_uid != os.getuid() or
                    before.st_nlink != 1 or before.st_size < 0 or before.st_size > maximum):
                raise ArtifactError("CAS file metadata is unsafe")
            chunks = []
            remaining = before.st_size
            while remaining:
                chunk = os.read(fd, min(65536, remaining))
                if not chunk:
                    raise ArtifactError("CAS file truncated")
                chunks.append(chunk)
                remaining -= len(chunk)
            if os.read(fd, 1):
                raise ArtifactError("CAS file grew during read")
            after = os.fstat(fd)
            identity = lambda item: (item.st_dev, item.st_ino, item.st_size, item.st_mtime_ns, item.st_ctime_ns,
                                     stat.S_IMODE(item.st_mode), item.st_uid, item.st_nlink)
            if identity(before) != identity(after):
                raise ArtifactError("CAS file changed during read")
            return b"".join(chunks)
        finally:
            os.close(fd)

    @staticmethod
    def _write_file(parent_fd, name, data):
        if not SAFE_COMPONENT.fullmatch(name) or not isinstance(data, bytes):
            raise ArtifactError("CAS write is invalid")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_CLOEXEC", 0)
        fd = os.open(name, flags, 0o600, dir_fd=parent_fd)
        try:
            offset = 0
            while offset < len(data):
                written = os.write(fd, data[offset:])
                if written <= 0:
                    raise ArtifactError("CAS write made no progress")
                offset += written
            os.fsync(fd)
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600 or info.st_uid != os.getuid() or
                    info.st_nlink != 1 or info.st_size != len(data)):
                raise ArtifactError("new CAS file metadata differs")
        finally:
            os.close(fd)

    def _remove_transaction(self, transactions_fd, name):
        transaction_fd = self._child_dir(transactions_fd, name)
        try:
            for entry in os.listdir(transaction_fd):
                self._read_file(transaction_fd, entry)
                os.unlink(entry, dir_fd=transaction_fd)
            os.fsync(transaction_fd)
        finally:
            os.close(transaction_fd)
        os.rmdir(name, dir_fd=transactions_fd)
        os.fsync(transactions_fd)

    def _validate_committed_dir(self, releases_fd, digest, expected_digests=None):
        release_fd = self._child_dir(releases_fd, digest)
        try:
            commit_bytes = self._read_file(release_fd, "commit.json", MAX_JSON_BYTES)
            commit = _json_bytes(commit_bytes, "CAS commit marker")
            if _canonical(commit) != commit_bytes:
                raise ArtifactError("CAS commit marker is not canonical JSON")
            _exact_keys(commit, {"schema", "payload_sha256", "files"}, "CAS commit marker")
            if (commit["schema"] != CAS_COMMIT_SCHEMA or commit["payload_sha256"] != digest or
                    not isinstance(commit["files"], dict) or set(commit["files"]) != CAS_RELEASE_FILES):
                raise ArtifactError("CAS commit marker differs")
            if set(os.listdir(release_fd)) != set(commit["files"]) | {"commit.json"}:
                raise ArtifactError("CAS committed inventory differs")
            for name, expected in commit["files"].items():
                _sha256(expected, "CAS file digest")
                if _sha(self._read_file(release_fd, name)) != expected:
                    raise ArtifactError("CAS committed file digest differs")
            if expected_digests is not None and commit["files"] != expected_digests:
                raise ArtifactError("CAS idempotent release differs")
            return commit["files"]
        finally:
            os.close(release_fd)

    def _recover(self, transactions_fd, releases_fd, current_digest, expected_digests):
        for name in sorted(os.listdir(transactions_fd)):
            match = re.fullmatch(r"txn-([0-9a-f]{64})-[0-9a-f]{16}", name)
            if match is None:
                raise ArtifactError("unknown CAS transaction entry")
            transaction_digest = match.group(1)
            transaction_fd = self._child_dir(transactions_fd, name)
            try:
                entries = set(os.listdir(transaction_fd))
                if "commit.json" not in entries:
                    committed = None
                else:
                    marker_bytes = self._read_file(transaction_fd, "commit.json", MAX_JSON_BYTES)
                    marker = _json_bytes(marker_bytes, "recovery marker")
                    if _canonical(marker) != marker_bytes:
                        raise ArtifactError("recovery marker is not canonical JSON")
                    _exact_keys(marker, {"schema", "payload_sha256", "files"}, "recovery marker")
                    if (marker["schema"] != CAS_COMMIT_SCHEMA or marker.get("payload_sha256") != transaction_digest or
                            not isinstance(marker.get("files"), dict) or set(marker["files"]) != CAS_RELEASE_FILES):
                        raise ArtifactError("recovery marker is invalid")
                    if entries != set(marker["files"]) | {"commit.json"}:
                        raise ArtifactError("recovery transaction inventory differs")
                    for file_name, digest in marker["files"].items():
                        if _sha(self._read_file(transaction_fd, file_name)) != _sha256(digest, "recovery file digest"):
                            raise ArtifactError("recovery transaction digest differs")
                    committed = marker
            finally:
                os.close(transaction_fd)
            if committed is None:
                self._remove_transaction(transactions_fd, name)
                continue
            digest = committed["payload_sha256"]
            # A durable transaction is only publishable in the store call that
            # just reverified those exact bytes and authorities.  Other sealed
            # transactions remain pending for their own fully verified call.
            if digest != current_digest:
                continue
            if committed["files"] != expected_digests:
                raise ArtifactError("recovery transaction differs from freshly verified release")
            try:
                os.rename(name, digest, src_dir_fd=transactions_fd, dst_dir_fd=releases_fd)
                os.fsync(releases_fd)
                os.fsync(transactions_fd)
            except OSError as exc:
                if exc.errno not in (errno.EEXIST, errno.ENOTEMPTY):
                    raise
                self._validate_committed_dir(releases_fd, digest, committed["files"])
                self._remove_transaction(transactions_fd, name)

    def store_release(self, *, envelope_bytes, payload, trusted_root_bytes, trusted_policy_bytes, r1_authority,
                      r2_authority, gh_runner=None):
        # No CAS child is created before full external-authority offline proof.
        if self.root is None:
            raise ArtifactError("CAS is closed")
        _result, decoded = _offline_verify_internal(envelope_bytes=envelope_bytes, payload=payload,
                                                     trusted_root_bytes=trusted_root_bytes,
                                                     trusted_policy_bytes=trusted_policy_bytes,
                                                     r1_authority=r1_authority, r2_authority=r2_authority,
                                                     gh_runner=gh_runner)
        digest = _sha(payload)
        files = {"payload.tar": payload, "envelope.json": envelope_bytes, "trusted-root.jsonl": trusted_root_bytes,
                 "release-policy.json": trusted_policy_bytes, "r1-receipt.json": decoded["r1"][0],
                 "r2-receipt.json": decoded["r2"][0], "r1-tar-bundle.jsonl": decoded["r1"][1],
                 "r1-receipt-bundle.jsonl": decoded["r1"][2], "r2-tar-bundle.jsonl": decoded["r2"][1],
                 "r2-receipt-bundle.jsonl": decoded["r2"][2]}
        expected_digests = {name: _sha(data) for name, data in files.items()}
        if set(expected_digests) != CAS_RELEASE_FILES:
            raise ArtifactError("CAS release inventory differs from implementation contract")
        acquired = False
        transactions_fd = None
        releases_fd = None
        try:
            _acquire_cas_lock(self.root)
            acquired = True
            self._check_dir_fd(self.root, "CAS root")
            transactions_fd = self._child_dir(self.root, ".transactions", create=True)
            releases_fd = self._child_dir(self.root, "releases", create=True)
            self._recover(transactions_fd, releases_fd, digest, expected_digests)
            try:
                self._validate_committed_dir(releases_fd, digest, expected_digests)
                return digest
            except FileNotFoundError:
                pass
            transaction_name = "txn-%s-%s" % (digest, secrets.token_hex(8))
            os.mkdir(transaction_name, 0o700, dir_fd=transactions_fd)
            transaction_fd = self._child_dir(transactions_fd, transaction_name)
            try:
                for name, data in sorted(files.items()):
                    self._write_file(transaction_fd, name, data)
                marker = _canonical({"schema": CAS_COMMIT_SCHEMA, "payload_sha256": digest, "files": expected_digests})
                self._write_file(transaction_fd, "commit.json", marker)
                os.fsync(transaction_fd)
            finally:
                os.close(transaction_fd)
            try:
                os.rename(transaction_name, digest, src_dir_fd=transactions_fd, dst_dir_fd=releases_fd)
            except OSError as exc:
                if exc.errno not in (errno.EEXIST, errno.ENOTEMPTY):
                    raise
                self._validate_committed_dir(releases_fd, digest, expected_digests)
                self._remove_transaction(transactions_fd, transaction_name)
            os.fsync(releases_fd)
            os.fsync(transactions_fd)
            os.fsync(self.root)
            self._validate_committed_dir(releases_fd, digest, expected_digests)
            self._check_dir_fd(self.root, "CAS root")
            return digest
        finally:
            try:
                if transactions_fd is not None:
                    os.close(transactions_fd)
            finally:
                try:
                    if releases_fd is not None:
                        os.close(releases_fd)
                finally:
                    if acquired:
                        try:
                            fcntl.flock(self.root, fcntl.LOCK_UN)
                        except OSError as exc:
                            # Closing is the kernel-level fallback release if
                            # an explicit unlock unexpectedly fails.
                            self.close()
                            raise ArtifactError("CAS lock release failed") from exc
