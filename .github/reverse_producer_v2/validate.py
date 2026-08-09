#!/usr/bin/env python3
"""Streaming, fail-closed finalizer for the trusted reverse producer v2.

This module intentionally uses only the Python standard library.  It consumes an
untrusted *uncompressed tar* from Job A, stages regular files without extracting
them into a destination tree, and writes a deterministic canonical tar plus a
canonical JSON receipt.  Nothing in this file imports, executes, or trusts a
candidate checkout.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import re
import selectors
import stat
import subprocess
import tarfile
import tempfile
import time
import unicodedata
from dataclasses import dataclass
from pathlib import Path
from typing import Any, BinaryIO, Callable, Mapping, Optional, Sequence


RECEIPT_SCHEMA = "spspy.trusted-reverse-producer-v2.receipt"
BINDING_SCHEMA = "spspy.trusted-reverse-producer-v2.binding"
VERSION = 1
CHUNK_SIZE = 1024 * 1024
MAX_RAW_ARCHIVE_BYTES = 128 * 1024 * 1024
MAX_MEMBER_COUNT = 10_000
MAX_MEMBER_BYTES = 64 * 1024 * 1024
MAX_TOTAL_MEMBER_BYTES = 512 * 1024 * 1024
MAX_PATH_BYTES = 1024
GIT_INSPECTION_TIMEOUT_SECONDS = 300
GIT_STDERR_BYTES = 64 * 1024
SHA40 = re.compile(r"^[0-9a-f]{40}$")
GIT_OBJECT = re.compile(r"^[0-9a-f]{40}$")
TRUSTED_REPOSITORY = "tonyaiuser/babata-board"
TRUSTED_WORKFLOW_PATH = ".github/workflows/trusted-reverse-producer-v2.yml"
TRUSTED_WORKFLOW_REF = TRUSTED_REPOSITORY + "/" + TRUSTED_WORKFLOW_PATH + "@refs/heads/main"
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


class ValidationError(RuntimeError):
    """Raised for input that cannot safely cross the Job A -> Job B boundary."""


@dataclass(frozen=True)
class _Entry:
    name: str
    kind: str
    size: int
    sha256: str
    staged_path: Optional[Path]


@dataclass(frozen=True)
class _ReleasePolicy:
    blob: dict[str, Any]
    sha256: str
    allowed_files: frozenset[str]
    allowed_prefixes: tuple[str, ...]
    required_files: frozenset[str]
    required_prefixes: tuple[str, ...]
    limits: dict[str, int]


@dataclass(frozen=True)
class _GitLeaf:
    name: str
    mode: str
    object_id: str
    size: int


class _CountingReader:
    """A tarfile-compatible reader that hashes and caps raw input bytes."""

    def __init__(self, source: BinaryIO, limit: int) -> None:
        self._source = source
        self._limit = limit
        self.count = 0
        self.digest = hashlib.sha256()

    def read(self, size: int = -1) -> bytes:
        remaining = self._limit - self.count
        if remaining < 0:
            raise ValidationError("raw archive exceeds byte limit")
        # Ask for one additional byte so an exact-limit input is allowed while a
        # longer input fails on this same read rather than after it was accepted.
        request = remaining + 1 if size is None or size < 0 else min(size, remaining + 1)
        data = self._source.read(request)
        if data is None:
            data = b""
        if not isinstance(data, bytes):
            raise ValidationError("archive reader returned non-bytes")
        self.count += len(data)
        if self.count > self._limit:
            raise ValidationError("raw archive exceeds byte limit")
        self.digest.update(data)
        return data


def _fail(message: str) -> None:
    raise ValidationError(message)


def _canonical_name(name: str) -> str:
    if not isinstance(name, str) or not name:
        _fail("empty member name")
    if "\x00" in name or "\\" in name:
        _fail("member name contains a forbidden separator")
    if any(ord(character) < 0x20 or ord(character) == 0x7F for character in name):
        _fail("member name contains an ASCII control character")
    if name.startswith("/"):
        _fail("absolute member name")
    if not name or name.endswith("/"):
        _fail("empty or ambiguous member name")
    if unicodedata.normalize("NFC", name) != name:
        _fail("member name is not NFC normalized")
    encoded = name.encode("utf-8", "strict")
    if len(encoded) > MAX_PATH_BYTES:
        _fail("member name exceeds byte limit")
    parts = name.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        _fail("member name contains dot, dotdot, or duplicate separators")
    return name


def _canonical_ustar_fields(path: str) -> tuple[str, str]:
    """Return the one accepted USTAR name/prefix representation for a path."""
    encoded = path.encode("ascii", "strict")
    if len(encoded) <= 100:
        return path, ""
    # Match TarInfo._posix_split_name exactly: scan components from the left
    # and accept the first split whose prefix/name fit the USTAR fields.
    components = path.split("/")
    for index in range(1, len(components)):
        prefix = "/".join(components[:index])
        name = "/".join(components[index:])
        if len(prefix.encode("ascii")) <= 155 and len(name.encode("ascii")) <= 100:
            return name, prefix
    _fail("member name cannot be represented by strict USTAR")


def _read_exact(reader: _CountingReader, size: int, label: str) -> bytes:
    chunks = []
    remaining = size
    while remaining:
        chunk = reader.read(remaining)
        if not chunk:
            _fail(f"truncated USTAR {label}")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _ustar_ascii_field(field: bytes, label: str, *, allow_empty: bool, full_width: int) -> str:
    if len(field) != full_width:
        _fail(f"USTAR {label} field width differs")
    if b"\0" in field:
        raw, trailing = field.split(b"\0", 1)
        if any(trailing):
            _fail(f"USTAR {label} contains data after NUL")
    else:
        # POSIX USTAR permits name and prefix to omit a terminator only when
        # their fixed-width field is completely occupied.  Python tarfile uses
        # this representation for exact 100-byte names and 155-byte prefixes.
        raw = field
    if not raw and not allow_empty:
        _fail(f"USTAR {label} is empty")
    try:
        return raw.decode("ascii", "strict")
    except UnicodeDecodeError as exc:
        raise ValidationError(f"USTAR {label} is not ASCII") from exc


def _octal_field(field: bytes, label: str, *, allow_empty_zero: bool = False) -> int:
    if allow_empty_zero and field == b"\0" * len(field):
        return 0
    if len(field) < 2 or field[-1:] != b"\0" or not field[:-1] or any(byte < ord("0") or byte > ord("7") for byte in field[:-1]):
        _fail(f"USTAR {label} is not canonical octal")
    return int(field[:-1], 8)


def _verify_ustar_header(header: bytes) -> tuple[str, int]:
    if len(header) != 512:
        _fail("USTAR header is not 512 bytes")
    if header[257:263] != b"ustar\0" or header[263:265] != b"00":
        _fail("raw archive is not strict USTAR")
    if header[500:512] != b"\0" * 12:
        _fail("USTAR header padding is not zero")
    stored_checksum = header[148:156]
    if len(stored_checksum) != 8 or stored_checksum[6:] != b"\0 " or any(byte < ord("0") or byte > ord("7") for byte in stored_checksum[:6]):
        _fail("USTAR checksum field is not canonical")
    expected_checksum = sum(header[:148] + b" " * 8 + header[156:])
    if int(stored_checksum[:6], 8) != expected_checksum:
        _fail("USTAR header checksum mismatch")
    if _octal_field(header[100:108], "mode") != 0o600:
        _fail("raw USTAR mode must be 0600")
    if _octal_field(header[108:116], "uid") != 0 or _octal_field(header[116:124], "gid") != 0:
        _fail("raw USTAR uid or gid must be zero")
    size = _octal_field(header[124:136], "size")
    if _octal_field(header[136:148], "mtime") != 0:
        _fail("raw USTAR mtime must be zero")
    if header[156:157] != b"0":
        _fail("raw USTAR must contain regular files only")
    if any(header[157:257]) or any(header[265:297]) or any(header[297:329]):
        _fail("raw USTAR link or owner fields must be empty")
    if _octal_field(header[329:337], "devmajor", allow_empty_zero=True) != 0 or _octal_field(header[337:345], "devminor", allow_empty_zero=True) != 0:
        _fail("raw USTAR device fields must be zero")
    name = _ustar_ascii_field(header[0:100], "name", allow_empty=False, full_width=100)
    prefix = _ustar_ascii_field(header[345:500], "prefix", allow_empty=True, full_width=155)
    canonical = _canonical_name(prefix + "/" + name if prefix else name)
    expected_name, expected_prefix = _canonical_ustar_fields(canonical)
    if name != expected_name or prefix != expected_prefix:
        _fail("USTAR name/prefix representation is not canonical")
    return canonical, size


def _stage_payload(reader: _CountingReader, size: int, destination: Path) -> str:
    digest = hashlib.sha256()
    remaining = size
    with destination.open("xb") as output:
        while remaining:
            chunk = _read_exact(reader, min(CHUNK_SIZE, remaining), "payload")
            output.write(chunk)
            digest.update(chunk)
            remaining -= len(chunk)
    padding_size = (-size) % 512
    if padding_size and any(_read_exact(reader, padding_size, "payload padding")):
        _fail("USTAR payload padding is not zero")
    return digest.hexdigest()


def _register_regular_path(
    name: str,
    *,
    names: set[str],
    folded_components: dict[str, str],
    file_names: set[str],
) -> None:
    if name in names:
        _fail("duplicate canonical member name")
    prefix_parts: list[str] = []
    for part in name.split("/"):
        prefix_parts.append(part)
        component_path = "/".join(prefix_parts)
        folded = component_path.casefold()
        previous = folded_components.get(folded)
        if previous is not None and previous != component_path:
            _fail("case-fold collision between member paths")
        folded_components[folded] = component_path
    ancestor = name
    while "/" in ancestor:
        ancestor = ancestor.rsplit("/", 1)[0]
        if ancestor in file_names:
            _fail("member is nested under a regular file")
    if any(previous.startswith(name + "/") for previous in names):
        _fail("regular file conflicts with existing descendants")
    names.add(name)
    file_names.add(name)


def _stage_archive(source: BinaryIO, staging: Path) -> tuple[list[_Entry], int, str]:
    """Parse raw bytes before any tar library sees a candidate-controlled header."""
    reader = _CountingReader(source, MAX_RAW_ARCHIVE_BYTES)
    entries: list[_Entry] = []
    names: set[str] = set()
    folded_components: dict[str, str] = {}
    file_names: set[str] = set()
    total_bytes = 0
    previous_name_bytes: Optional[bytes] = None
    try:
        while True:
            header = _read_exact(reader, 512, "header")
            if header == b"\0" * 512:
                if _read_exact(reader, 512, "end marker") != b"\0" * 512:
                    _fail("USTAR requires exactly two zero end blocks")
                if reader.read(1):
                    _fail("USTAR archive has trailing bytes or extra zero blocks")
                break
            if len(entries) >= MAX_MEMBER_COUNT:
                _fail("archive contains too many members")
            name, size = _verify_ustar_header(header)
            encoded_name = name.encode("utf-8")
            if previous_name_bytes is not None and encoded_name <= previous_name_bytes:
                _fail("raw USTAR members are not in canonical UTF-8 byte order")
            previous_name_bytes = encoded_name
            if size > MAX_MEMBER_BYTES or total_bytes + size > MAX_TOTAL_MEMBER_BYTES:
                _fail("archive payload exceeds byte limit")
            _register_regular_path(name, names=names, folded_components=folded_components, file_names=file_names)
            staged = staging / f"payload-{len(entries):08d}"
            digest = _stage_payload(reader, size, staged)
            total_bytes += size
            entries.append(_Entry(name, "file", size, digest, staged))
    except OSError as exc:
        raise ValidationError(f"invalid raw USTAR archive: {exc}") from exc
    return entries, reader.count, reader.digest.hexdigest()


def _canonical_tar(entries: list[_Entry], output: Path) -> tuple[int, str, str]:
    temporary = output.with_name(f".{output.name}.tmp-{os.getpid()}")
    try:
        # One 512-byte USTAR header plus padded data per regular file, followed
        # by exactly two zero blocks.  tarfile normally pads to 10KiB records;
        # trim that all-zero convenience padding so the final subject has no
        # ambiguous trailing archive bytes.
        strict_length = 1024
        # Job B emits only strict USTAR regular-file records.  Policy enforcement
        # above rejects directories, links, and special entries; USTAR here
        # prevents the final artifact from introducing PAX/GNU extensions.
        with tarfile.open(temporary, mode="w", format=tarfile.USTAR_FORMAT, encoding="utf-8") as archive:
            for entry in sorted(entries, key=lambda item: item.name.encode("utf-8")):
                info = tarfile.TarInfo(entry.name + "/" if entry.kind == "dir" else entry.name)
                info.uid = 0
                info.gid = 0
                info.uname = ""
                info.gname = ""
                info.mtime = 0
                info.mode = 0o600
                if entry.kind != "file":
                    _fail("canonical release must contain regular files only")
                assert entry.staged_path is not None
                info.type = tarfile.REGTYPE
                info.size = entry.size
                strict_length += 512 + ((entry.size + 511) // 512) * 512
                with entry.staged_path.open("rb") as input_file:
                    archive.addfile(info, input_file)
        with temporary.open("r+b") as canonical:
            canonical.seek(strict_length)
            canonical.truncate()
            canonical.flush()
            os.fsync(canonical.fileno())
        digest = hashlib.sha256()
        size = 0
        with temporary.open("rb") as canonical:
            for chunk in iter(lambda: canonical.read(CHUNK_SIZE), b""):
                digest.update(chunk)
                size += len(chunk)
        os.replace(temporary, output)
        return size, digest.hexdigest(), _inventory_sha256(entries)
    finally:
        temporary.unlink(missing_ok=True)


def _required_string(mapping: Mapping[str, Any], key: str) -> str:
    value = mapping.get(key)
    if not isinstance(value, str) or not value.strip():
        _fail(f"binding field {key!r} must be a non-empty string")
    return value


def _require_exact_keys(mapping: Mapping[str, Any], expected: set[str], label: str) -> None:
    actual = set(mapping)
    if actual != expected:
        _fail(f"binding {label} keys must be exactly {sorted(expected)!r}")


def validate_binding(binding: Any) -> dict[str, Any]:
    """Validate all immutable provenance required in the canonical receipt."""
    if not isinstance(binding, dict):
        _fail("binding must be an object")
    root_keys = {"schema", "source", "signer", "candidate", "run", "artifact", "runner", "tools", "cache", "test_matrix"}
    _require_exact_keys(binding, root_keys, "root")
    if binding["schema"] != BINDING_SCHEMA:
        _fail("unexpected binding schema")
    for child in ("source", "signer", "candidate", "run", "artifact", "runner", "tools", "cache", "test_matrix"):
        if not isinstance(binding[child], dict):
            _fail(f"binding {child} must be an object")
    source = binding["source"]
    _require_exact_keys(source, {"id", "repository", "commit", "ref"}, "source")
    if not _required_string(source, "id").isdigit() or "/" not in _required_string(source, "repository"):
        _fail("binding source id or repository is invalid")
    if source["repository"] != TRUSTED_REPOSITORY:
        _fail("binding source repository is not the trusted repository")
    if not SHA40.fullmatch(_required_string(source, "commit")) or not _required_string(source, "ref").startswith("refs/"):
        _fail("binding source commit or ref is invalid")
    candidate = binding["candidate"]
    _require_exact_keys(candidate, {"commit", "ref", "tree"}, "candidate")
    for key in ("commit", "tree"):
        if not SHA40.fullmatch(_required_string(candidate, key)):
            _fail(f"binding candidate {key} is not a full SHA")
    _required_string(candidate, "ref")
    signer = binding["signer"]
    _require_exact_keys(signer, {"repository", "workflow_path", "workflow_ref", "commit", "blob"}, "signer")
    if "/" not in _required_string(signer, "repository"):
        _fail("binding signer repository is invalid")
    if not _required_string(signer, "workflow_path").startswith(".github/workflows/"):
        _fail("binding signer workflow path is invalid")
    if not _required_string(signer, "workflow_ref").startswith(_required_string(signer, "repository") + "/"):
        _fail("binding signer workflow ref is invalid")
    if (
        signer["repository"] != TRUSTED_REPOSITORY
        or signer["workflow_path"] != TRUSTED_WORKFLOW_PATH
        or signer["workflow_ref"] != TRUSTED_WORKFLOW_REF
    ):
        _fail("binding signer does not identify the trusted main workflow")
    for key in ("commit", "blob"):
        if not SHA40.fullmatch(_required_string(signer, key)):
            _fail(f"binding signer {key} is not a full SHA")
    run = binding["run"]
    _require_exact_keys(run, {"id", "attempt", "finalize_job", "prepare_result"}, "run")
    if not _required_string(run, "id").isdigit() or not _required_string(run, "attempt").isdigit():
        _fail("binding run id or attempt is invalid")
    _required_string(run, "finalize_job")
    if _required_string(run, "prepare_result") != "success":
        _fail("binding prepare_result must be successful")
    artifact = binding["artifact"]
    _require_exact_keys(artifact, {"name"}, "artifact")
    _required_string(artifact, "name")
    runner = binding["runner"]
    _require_exact_keys(runner, {"os", "image"}, "runner")
    _required_string(runner, "os")
    _required_string(runner, "image")
    tools = binding["tools"]
    if not tools or any(not isinstance(key, str) or not isinstance(value, str) or not value for key, value in tools.items()):
        _fail("binding tools must be a non-empty string map")
    cache = binding["cache"]
    _require_exact_keys(cache, {"shared", "enabled"}, "cache")
    if cache != {"shared": False, "enabled": False}:
        _fail("binding cache must prove shared and enabled are false")
    matrix = binding["test_matrix"]
    if not matrix or any(not isinstance(key, str) or not isinstance(value, (str, int, float, bool, list, dict)) for key, value in matrix.items()):
        _fail("binding test_matrix must be a non-empty JSON object")
    # Round-trip through canonical JSON to reject values that stdlib JSON cannot
    # represent deterministically (for example NaN).
    return json.loads(canonical_json(binding).decode("utf-8"))


def canonical_json(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, ensure_ascii=False, allow_nan=False, separators=(",", ":")) + "\n").encode("utf-8")


def _policy_file_name(value: Any) -> str:
    if not isinstance(value, str):
        _fail("release policy file name must be a string")
    return _canonical_name(value)


def _policy_prefix(value: Any) -> str:
    if not isinstance(value, str) or not value.endswith("/"):
        _fail("release policy prefix must end in slash")
    return _canonical_name(value[:-1]) + "/"


def load_release_policy(path: Path) -> _ReleasePolicy:
    """Load a strict trusted policy; caller must obtain it from trusted checkout."""
    try:
        raw = path.read_bytes()
        if len(raw) > 64 * 1024:
            _fail("release policy exceeds byte cap")
        document = json.loads(raw.decode("utf-8"), parse_constant=lambda _value: (_ for _ in ()).throw(ValueError("non-finite JSON")))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise ValidationError(f"invalid release policy: {exc}") from exc
    if not isinstance(document, dict):
        _fail("release policy must be an object")
    _require_exact_keys(document, {"schema", "version", "archive", "inventory", "limits", "paths"}, "release policy")
    if document["schema"] != "spspy.trusted-reverse-producer-v2.release-policy" or document["version"] != VERSION:
        _fail("unexpected release policy schema or version")
    if document["archive"] != ARCHIVE_CONTRACT:
        _fail("release policy archive contract is not the trusted v2 contract")
    if document["inventory"] != INVENTORY_CONTRACT:
        _fail("release policy inventory contract is not the trusted v2 contract")
    limits = document["limits"]
    if not isinstance(limits, dict):
        _fail("release policy limits must be an object")
    _require_exact_keys(limits, {"max_entries", "max_file_bytes", "max_payload_bytes", "max_path_bytes"}, "release policy limits")
    maxima = {
        "max_entries": MAX_MEMBER_COUNT,
        "max_file_bytes": MAX_MEMBER_BYTES,
        "max_payload_bytes": MAX_TOTAL_MEMBER_BYTES,
        "max_path_bytes": MAX_PATH_BYTES,
    }
    if any(type(limits[key]) is not int or limits[key] <= 0 or limits[key] > maxima[key] for key in limits):
        _fail("release policy limit is invalid or exceeds finalizer ceiling")
    paths = document["paths"]
    if not isinstance(paths, dict):
        _fail("release policy paths must be an object")
    _require_exact_keys(paths, {"allowed_files", "allowed_prefixes", "required_files", "required_prefixes"}, "release policy paths")
    parsed: dict[str, list[str]] = {}
    for key, parser in (("allowed_files", _policy_file_name), ("allowed_prefixes", _policy_prefix), ("required_files", _policy_file_name), ("required_prefixes", _policy_prefix)):
        values = paths[key]
        if not isinstance(values, list):
            _fail(f"release policy {key} must be a list")
        converted = [parser(value) for value in values]
        if len(set(converted)) != len(converted) or len({value.casefold() for value in converted}) != len(converted):
            _fail(f"release policy {key} has a duplicate or case collision")
        parsed[key] = converted
    allowed_files = frozenset(parsed["allowed_files"])
    allowed_prefixes = tuple(sorted(parsed["allowed_prefixes"]))
    required_files = frozenset(parsed["required_files"])
    required_prefixes = tuple(sorted(parsed["required_prefixes"]))
    if not required_files.issubset(allowed_files):
        _fail("release policy required file is not allowed")
    if any(prefix not in allowed_prefixes for prefix in required_prefixes):
        _fail("release policy required prefix is not allowed")
    if not allowed_files and not allowed_prefixes:
        _fail("release policy must allow at least one path")
    return _ReleasePolicy(
        blob=document,
        sha256=hashlib.sha256(raw).hexdigest(),
        allowed_files=allowed_files,
        allowed_prefixes=allowed_prefixes,
        required_files=required_files,
        required_prefixes=required_prefixes,
        limits={key: int(value) for key, value in limits.items()},
    )


def _policy_allows(name: str, policy: _ReleasePolicy) -> bool:
    return name in policy.allowed_files or any(name.startswith(prefix) for prefix in policy.allowed_prefixes)


def _enforce_release_policy(entries: list[_Entry], policy: _ReleasePolicy) -> None:
    file_entries = [entry for entry in entries if entry.kind == "file"]
    if len(file_entries) != len(entries):
        _fail("release policy allows regular files only")
    if not file_entries or len(file_entries) > policy.limits["max_entries"]:
        _fail("release inventory is empty or exceeds policy entry limit")
    names = {entry.name for entry in file_entries}
    total = 0
    for entry in file_entries:
        if len(entry.name.encode("utf-8")) > policy.limits["max_path_bytes"]:
            _fail("release path exceeds policy limit")
        if entry.size > policy.limits["max_file_bytes"]:
            _fail("release file exceeds policy limit")
        total += entry.size
        if ".git" in entry.name.split("/"):
            _fail("release contains forbidden .git path")
        if not _policy_allows(entry.name, policy):
            _fail(f"release path is outside trusted policy: {entry.name}")
    if total > policy.limits["max_payload_bytes"]:
        _fail("release payload exceeds policy limit")
    missing = sorted(policy.required_files - names)
    if missing:
        _fail(f"release is missing required files: {missing!r}")
    for prefix in policy.required_prefixes:
        if not any(name.startswith(prefix) for name in names):
            _fail(f"release is missing required prefix inventory: {prefix}")


def _git_environment() -> dict[str, str]:
    return {
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_OPTIONAL_LOCKS": "0",
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin",
    }


def _stop_exact_process(process: subprocess.Popen[bytes]) -> None:
    """Stop and reap only this exact child; never signal a process group."""
    if process.poll() is not None:
        return
    try:
        process.terminate()
    except ProcessLookupError:
        pass
    try:
        process.wait(timeout=1)
        return
    except subprocess.TimeoutExpired:
        pass
    if process.poll() is None:
        try:
            process.kill()
        except ProcessLookupError:
            pass
    process.wait(timeout=2)


def _run_git_stream(
    git_dir: Path,
    arguments: Sequence[str],
    *,
    deadline: float,
    stdout_cap: int,
    on_stdout: Callable[[bytes], None],
    stdin: Any = subprocess.DEVNULL,
) -> None:
    """Run trusted Git with strict streaming caps and one shared deadline."""
    command = [
        "/usr/bin/git",
        f"--git-dir={git_dir}",
        "-c",
        "core.hooksPath=/dev/null",
        *arguments,
    ]
    try:
        process = subprocess.Popen(
            command,
            env=_git_environment(),
            stdin=stdin,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except OSError as exc:
        raise ValidationError("trusted git object inspection failed") from exc
    assert process.stdout is not None and process.stderr is not None
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ, "stdout")
    selector.register(process.stderr, selectors.EVENT_READ, "stderr")
    stdout_bytes = 0
    stderr_bytes = 0
    try:
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                _fail("trusted git object inspection exceeded shared timeout")
            events = selector.select(min(0.1, remaining))
            for key, _mask in events:
                stream = key.fileobj
                chunk = os.read(stream.fileno(), CHUNK_SIZE)
                if not chunk:
                    selector.unregister(stream)
                    stream.close()
                    continue
                if key.data == "stdout":
                    stdout_bytes += len(chunk)
                    if stdout_bytes > stdout_cap:
                        _fail("trusted git stdout exceeded strict byte cap")
                    on_stdout(chunk)
                else:
                    stderr_bytes += len(chunk)
                    if stderr_bytes > GIT_STDERR_BYTES:
                        _fail("trusted git stderr exceeded strict byte cap")
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            _fail("trusted git object inspection exceeded shared timeout")
        try:
            return_code = process.wait(timeout=remaining)
        except subprocess.TimeoutExpired as exc:
            raise ValidationError("trusted git object inspection exceeded shared timeout") from exc
        if return_code != 0:
            _fail("trusted git object inspection rejected candidate database")
    except BaseException:
        _stop_exact_process(process)
        raise
    finally:
        selector.close()
        for stream in (process.stdout, process.stderr):
            if not stream.closed:
                stream.close()


class _BoundedCollector:
    def __init__(self) -> None:
        self.chunks: list[bytes] = []

    def feed(self, chunk: bytes) -> None:
        self.chunks.append(chunk)

    def value(self) -> bytes:
        return b"".join(self.chunks)


class _NulRecords:
    def __init__(self, record_cap: int, callback: Callable[[bytes], None]) -> None:
        self.record_cap = record_cap
        self.callback = callback
        self.buffer = bytearray()

    def feed(self, chunk: bytes) -> None:
        self.buffer.extend(chunk)
        while True:
            delimiter = self.buffer.find(0)
            if delimiter < 0:
                if len(self.buffer) > self.record_cap:
                    _fail("git ls-tree record exceeded strict byte cap")
                return
            if delimiter > self.record_cap:
                _fail("git ls-tree record exceeded strict byte cap")
            record = bytes(self.buffer[:delimiter])
            del self.buffer[:delimiter + 1]
            if not record:
                _fail("git ls-tree emitted an empty record")
            self.callback(record)

    def finish(self) -> None:
        if self.buffer:
            _fail("git ls-tree output is not NUL terminated")


def _git_identity(git_dir: Path, expression: str, deadline: float) -> str:
    collector = _BoundedCollector()
    _run_git_stream(
        git_dir,
        ["rev-parse", "--verify", expression],
        deadline=deadline,
        stdout_cap=128,
        on_stdout=collector.feed,
    )
    raw = collector.value()
    try:
        value = raw.decode("ascii", "strict").strip()
    except UnicodeDecodeError as exc:
        raise ValidationError("trusted git returned a non-ASCII identity") from exc
    if not GIT_OBJECT.fullmatch(value):
        _fail("trusted git returned an invalid object identity")
    return value


def _parse_ls_tree_record(record: bytes) -> tuple[str, str, str, str, str]:
    try:
        metadata, encoded_name = record.split(b"\t", 1)
        fields = metadata.split()
        if len(fields) != 4:
            _fail("git tree record has an invalid shape")
        mode = fields[0].decode("ascii", "strict")
        object_type = fields[1].decode("ascii", "strict")
        object_id = fields[2].decode("ascii", "strict")
        size_text = fields[3].decode("ascii", "strict")
        name = _canonical_name(encoded_name.decode("utf-8", "strict"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise ValidationError("git tree record is not canonical UTF-8 metadata") from exc
    if not GIT_OBJECT.fullmatch(object_id):
        _fail("git tree object identity is not a 40-character SHA-1")
    return mode, object_type, object_id, size_text, name


def _regular_git_leaf(record: bytes, policy: _ReleasePolicy) -> _GitLeaf:
    mode, object_type, object_id, size_text, name = _parse_ls_tree_record(record)
    if mode not in {"100644", "100755"} or object_type != "blob":
        _fail(f"candidate policy path is not a regular Git blob: {name}")
    if not size_text.isdigit():
        _fail("git tree regular-file size is invalid")
    size = int(size_text)
    if size > policy.limits["max_file_bytes"]:
        _fail(f"candidate policy file exceeds size limit: {name}")
    return _GitLeaf(name=name, mode=mode, object_id=object_id, size=size)


def _stream_ls_tree(
    git_dir: Path,
    arguments: Sequence[str],
    *,
    policy: _ReleasePolicy,
    deadline: float,
    callback: Callable[[bytes], None],
) -> None:
    record_cap = policy.limits["max_path_bytes"] + 128
    records = _NulRecords(record_cap, callback)
    stdout_cap = policy.limits["max_entries"] * record_cap + record_cap
    _run_git_stream(
        git_dir,
        arguments,
        deadline=deadline,
        stdout_cap=stdout_cap,
        on_stdout=records.feed,
    )
    records.finish()


def _git_tree_leaves(git_dir: Path, tree: str, policy: _ReleasePolicy, deadline: float) -> list[_GitLeaf]:
    leaves_by_name: dict[str, _GitLeaf] = {}
    observed_prefix_leaves = 0

    def add_prefix_record(record: bytes) -> None:
        nonlocal observed_prefix_leaves
        observed_prefix_leaves += 1
        if observed_prefix_leaves > policy.limits["max_entries"]:
            _fail("candidate policy inventory exceeds entry limit")
        leaf = _regular_git_leaf(record, policy)
        if not any(leaf.name.startswith(prefix) for prefix in policy.allowed_prefixes):
            _fail(f"git prefix listing escaped trusted policy: {leaf.name}")
        existing = leaves_by_name.get(leaf.name)
        if existing is not None and existing != leaf:
            _fail("git tree returned inconsistent duplicate metadata")
        leaves_by_name[leaf.name] = leaf

    if policy.allowed_prefixes:
        prefix_pathspecs = [":(top,literal)" + prefix[:-1] for prefix in policy.allowed_prefixes]
        _stream_ls_tree(
            git_dir,
            ["ls-tree", "-r", "-z", "-l", "--full-tree", tree, "--", *prefix_pathspecs],
            policy=policy,
            deadline=deadline,
            callback=add_prefix_record,
        )

    for exact_name in sorted(policy.allowed_files):
        exact_records: list[bytes] = []
        _stream_ls_tree(
            git_dir,
            ["ls-tree", "-z", "-l", "--full-tree", tree, "--", ":(top,literal)" + exact_name],
            policy=policy,
            deadline=deadline,
            callback=exact_records.append,
        )
        if not exact_records:
            continue
        if len(exact_records) != 1:
            _fail(f"exact candidate policy path resolved ambiguously: {exact_name}")
        mode, object_type, _object_id, _size_text, returned_name = _parse_ls_tree_record(exact_records[0])
        if returned_name != exact_name:
            _fail(f"exact candidate policy path returned a different path: {exact_name}")
        if mode == "040000" and object_type == "tree":
            _fail(f"candidate policy file is a directory: {exact_name}")
        leaf = _regular_git_leaf(exact_records[0], policy)
        existing = leaves_by_name.get(leaf.name)
        if existing is not None and existing != leaf:
            _fail("git tree returned inconsistent duplicate metadata")
        leaves_by_name[leaf.name] = leaf

    leaves = list(leaves_by_name.values())
    if len(leaves) > policy.limits["max_entries"]:
        _fail("candidate policy inventory exceeds entry limit")
    if sum(leaf.size for leaf in leaves) > policy.limits["max_payload_bytes"]:
        _fail("candidate policy inventory exceeds payload limit")
    names: set[str] = set()
    folded_components: dict[str, str] = {}
    file_names: set[str] = set()
    for leaf in sorted(leaves, key=lambda item: item.name.encode("utf-8")):
        _register_regular_path(leaf.name, names=names, folded_components=folded_components, file_names=file_names)
    return leaves


class _BatchBlobParser:
    def __init__(self, leaves: Sequence[_GitLeaf]) -> None:
        self.leaves = list(leaves)
        self.index = 0
        self.buffer = bytearray()
        self.remaining: Optional[int] = None
        self.digest: Optional[Any] = None
        self.entries: list[_Entry] = []

    def feed(self, chunk: bytes) -> None:
        self.buffer.extend(chunk)
        while True:
            if self.index >= len(self.leaves):
                if self.buffer:
                    _fail("git cat-file --batch emitted trailing bytes")
                return
            leaf = self.leaves[self.index]
            if self.remaining is None:
                delimiter = self.buffer.find(ord("\n"))
                if delimiter < 0:
                    if len(self.buffer) > 128:
                        _fail("git cat-file --batch header exceeded byte cap")
                    return
                if delimiter > 128:
                    _fail("git cat-file --batch header exceeded byte cap")
                header = bytes(self.buffer[:delimiter])
                del self.buffer[:delimiter + 1]
                fields = header.split()
                if len(fields) != 3:
                    _fail("git cat-file --batch header shape is invalid")
                try:
                    object_id = fields[0].decode("ascii", "strict")
                    object_type = fields[1].decode("ascii", "strict")
                    size_text = fields[2].decode("ascii", "strict")
                except UnicodeDecodeError as exc:
                    raise ValidationError("git cat-file --batch header is not ASCII") from exc
                if object_id != leaf.object_id or object_type != "blob" or not size_text.isdigit() or int(size_text) != leaf.size:
                    _fail(f"git cat-file --batch metadata differs for: {leaf.name}")
                self.remaining = leaf.size
                self.digest = hashlib.sha256()
            if self.remaining:
                take = min(self.remaining, len(self.buffer))
                if take:
                    assert self.digest is not None
                    self.digest.update(self.buffer[:take])
                    del self.buffer[:take]
                    self.remaining -= take
                if self.remaining:
                    return
            if not self.buffer:
                return
            if self.buffer[0] != ord("\n"):
                _fail("git cat-file --batch blob lacks exact newline framing")
            del self.buffer[0]
            assert self.digest is not None
            self.entries.append(_Entry(leaf.name, "file", leaf.size, self.digest.hexdigest(), None))
            self.index += 1
            self.remaining = None
            self.digest = None

    def finish(self) -> list[_Entry]:
        if self.index != len(self.leaves) or self.remaining is not None or self.buffer:
            _fail("git cat-file --batch output is truncated")
        return self.entries


def _git_blob_entries(git_dir: Path, leaves: Sequence[_GitLeaf], deadline: float) -> list[_Entry]:
    ordered = sorted(leaves, key=lambda item: item.name.encode("utf-8"))
    parser = _BatchBlobParser(ordered)
    with tempfile.TemporaryFile() as commands:
        for leaf in ordered:
            commands.write(leaf.object_id.encode("ascii") + b"\n")
        commands.seek(0)
        stdout_cap = sum(leaf.size for leaf in ordered) + len(ordered) * 128
        _run_git_stream(
            git_dir,
            ["cat-file", "--batch"],
            deadline=deadline,
            stdout_cap=stdout_cap,
            on_stdout=parser.feed,
            stdin=commands,
        )
    return parser.finish()


def _inventory_sha256(entries: Sequence[_Entry]) -> str:
    digest = hashlib.sha256()
    for entry in sorted(entries, key=lambda item: item.name.encode("utf-8")):
        digest.update(b"file\0" + entry.name.encode("utf-8") + b"\0")
        digest.update(entry.sha256.encode("ascii") + b"\0" + str(entry.size).encode("ascii") + b"\n")
    return digest.hexdigest()


def load_candidate_inventory(
    git_dir: Path,
    expected_commit: str,
    expected_tree: str,
    policy: _ReleasePolicy,
) -> list[_Entry]:
    """Build the complete release inventory from Git objects, never the worktree."""
    if not SHA40.fullmatch(expected_commit) or not SHA40.fullmatch(expected_tree):
        _fail("trusted reverse producer v2 supports only full 40-character SHA-1 commit and tree object IDs")
    try:
        info = git_dir.lstat()
    except OSError as exc:
        raise ValidationError("candidate Git object database is missing") from exc
    if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
        _fail("candidate Git object database path is not a direct directory")
    git_dir = git_dir.resolve(strict=True)
    deadline = time.monotonic() + GIT_INSPECTION_TIMEOUT_SECONDS
    if _git_identity(git_dir, expected_commit + "^{commit}", deadline) != expected_commit:
        _fail("candidate Git database does not contain the exact declared commit")
    if _git_identity(git_dir, expected_commit + "^{tree}", deadline) != expected_tree:
        _fail("candidate Git commit tree differs from the declared tree")
    leaves = _git_tree_leaves(git_dir, expected_tree, policy, deadline)
    entries = _git_blob_entries(git_dir, leaves, deadline)
    _enforce_release_policy(entries, policy)
    return entries


def _compare_archive_to_candidate(archive_entries: Sequence[_Entry], candidate_entries: Sequence[_Entry]) -> None:
    archive = {entry.name: entry for entry in archive_entries}
    candidate = {entry.name: entry for entry in candidate_entries}
    if set(archive) != set(candidate):
        missing = sorted(set(candidate) - set(archive))
        unexpected = sorted(set(archive) - set(candidate))
        _fail(f"raw archive does not exactly match candidate policy inventory; missing={missing!r}, unexpected={unexpected!r}")
    for name in sorted(candidate):
        actual = archive[name]
        expected = candidate[name]
        if actual.size != expected.size or actual.sha256 != expected.sha256:
            _fail(f"raw archive bytes differ from candidate Git blob: {name}")
def canonicalize_archive(
    source: BinaryIO,
    canonical_tar: Path,
    receipt: Path,
    binding: Mapping[str, Any],
    *,
    release_policy: _ReleasePolicy,
    candidate_git_dir: Path,
    source_receipt: BinaryIO,
) -> dict[str, Any]:
    """Validate source and atomically emit its canonical tar and receipt."""
    canonical_tar.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    receipt.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    checked_binding = validate_binding(binding)
    bounded_receipt = _CountingReader(source_receipt, 1024 * 1024)
    while bounded_receipt.read(CHUNK_SIZE):
        pass
    with tempfile.TemporaryDirectory(prefix="reverse-v2-stage-", dir=canonical_tar.parent) as directory:
        entries, raw_bytes, raw_digest = _stage_archive(source, Path(directory))
        _enforce_release_policy(entries, release_policy)
        candidate_entries = load_candidate_inventory(
            candidate_git_dir,
            checked_binding["candidate"]["commit"],
            checked_binding["candidate"]["tree"],
            release_policy,
        )
        _compare_archive_to_candidate(entries, candidate_entries)
        canonical_bytes, canonical_digest, payload_digest = _canonical_tar(entries, canonical_tar)
    candidate_inventory_digest = _inventory_sha256(candidate_entries)
    if candidate_inventory_digest != payload_digest:
        _fail("candidate and canonical inventory digests diverged")
    document: dict[str, Any] = {
        "canonical": {"bytes": canonical_bytes, "sha256": canonical_digest},
        "canonicalization": dict(ARCHIVE_CONTRACT),
        "candidate_inventory": {
            "bytes": sum(entry.size for entry in candidate_entries),
            "commit": checked_binding["candidate"]["commit"],
            "entries": len(candidate_entries),
            "format": INVENTORY_CONTRACT["format"],
            "sha256": candidate_inventory_digest,
            "tree": checked_binding["candidate"]["tree"],
        },
        "payload": {
            "bytes": sum(entry.size for entry in entries if entry.kind == "file"),
            "entries": len(entries),
            "input_tree_sha256": payload_digest,
            "sha256": payload_digest,
        },
        "provenance": checked_binding,
        "raw": {"bytes": raw_bytes, "sha256": raw_digest},
        "release_policy": {"blob": release_policy.blob, "sha256": release_policy.sha256},
        "schema": RECEIPT_SCHEMA,
        "source_receipt": {"bytes": bounded_receipt.count, "sha256": bounded_receipt.digest.hexdigest()},
        "version": VERSION,
    }
    receipt_tmp = receipt.with_name(f".{receipt.name}.tmp-{os.getpid()}")
    try:
        receipt_tmp.write_bytes(canonical_json(document))
        os.replace(receipt_tmp, receipt)
    finally:
        receipt_tmp.unlink(missing_ok=True)
    return document


def _load_binding(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValidationError(f"invalid binding file: {exc}") from exc
    if not isinstance(data, dict):
        raise ValidationError("binding file must hold an object")
    return data


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--receipt", required=True, type=Path)
    parser.add_argument("--binding", required=True, type=Path)
    parser.add_argument("--policy", required=True, type=Path)
    parser.add_argument("--candidate-git-dir", required=True, type=Path)
    parser.add_argument("--source-receipt", required=True, type=Path)
    return parser


def main(argv: Optional[list[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        binding = _load_binding(args.binding)
        release_policy = load_release_policy(args.policy)
        with args.input.open("rb") as source, args.source_receipt.open("rb") as raw_receipt:
            document = canonicalize_archive(
                source,
                args.output,
                args.receipt,
                binding,
                release_policy=release_policy,
                candidate_git_dir=args.candidate_git_dir,
                source_receipt=raw_receipt,
            )
        print(canonical_json({"canonical_sha256": document["canonical"]["sha256"], "receipt": str(args.receipt)}).decode("utf-8"), end="")
        return 0
    except (ValidationError, OSError) as exc:
        print(f"trusted reverse v2 finalizer: {exc}", file=os.sys.stderr)
        return 78


if __name__ == "__main__":
    raise SystemExit(main())
