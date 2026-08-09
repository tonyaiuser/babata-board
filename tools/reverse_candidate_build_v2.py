"""Job-A-only raw candidate builder for the isolated release v2 protocol.

Candidate configuration and files are hostile input.  This helper therefore
does not run tests, commands, hooks, or imports from the candidate tree.  It
only copies the fixed allowlist into a strict raw USTAR stream and records
non-authoritative summary evidence.  Job B owns all trusted policy and final
receipt production.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import re
import stat
import tarfile
import unicodedata
from pathlib import Path

SCHEMA = "spspy.candidate-reverse-v2.receipt"
MAX_CONFIG = 128 * 1024
MAX_FILE_BYTES = 64 * 1024 * 1024
MAX_PAYLOAD_BYTES = 256 * 1024 * 1024
MAX_ENTRIES = 4096
MAX_PATH_BYTES = 240
GIT_OID40 = re.compile(r"^[0-9a-f]{40}$")
REPO = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")


class CandidateError(RuntimeError):
    pass


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def _safe_relative(path):
    if not isinstance(path, str) or not path or "\\" in path:
        raise CandidateError("allowlist path is invalid")
    normalized = unicodedata.normalize("NFC", path)
    try:
        normalized.encode("ascii", "strict")
    except UnicodeEncodeError as exc:
        raise CandidateError("allowlist path is not strict USTAR ASCII") from exc
    pieces = normalized.split("/")
    if (normalized != path or normalized.startswith("/") or any(piece in ("", ".", "..") for piece in pieces) or
            any(piece.casefold() == ".git" for piece in pieces) or
            any(ord(character) < 32 or ord(character) == 127 for character in normalized)):
        raise CandidateError("allowlist path is unsafe")
    return normalized


def _open_directory_beneath(root_fd, relative):
    """Open a directory below an anchored root without following symlinks."""
    fd = os.dup(root_fd)
    try:
        for component in filter(None, relative.split("/")):
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0) |
                            getattr(os, "O_CLOEXEC", 0), dir_fd=fd)
            os.close(fd)
            fd = child
        if not stat.S_ISDIR(os.fstat(fd).st_mode):
            raise CandidateError("candidate directory component is not a directory")
        return fd
    except OSError as exc:
        os.close(fd)
        raise CandidateError("candidate directory path is unsafe") from exc
    except BaseException:
        os.close(fd)
        raise


def _open_regular_beneath(root_fd, relative, maximum):
    pieces = relative.split("/")
    parent_fd = _open_directory_beneath(root_fd, "/".join(pieces[:-1]))
    try:
        fd = os.open(pieces[-1], os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) |
                     getattr(os, "O_CLOEXEC", 0), dir_fd=parent_fd)
    except OSError as exc:
        raise CandidateError("candidate input path is unsafe") from exc
    finally:
        os.close(parent_fd)
    observed = os.fstat(fd)
    if (not stat.S_ISREG(observed.st_mode) or observed.st_nlink != 1 or
            observed.st_size < 0 or observed.st_size > maximum):
        os.close(fd)
        raise CandidateError("candidate input is not a bounded regular file")
    return fd, observed


def _load_policy(root_fd):
    fd = None
    try:
        fd, before = _open_regular_beneath(root_fd, "config/reverse_producer_v2.json", MAX_CONFIG)
        raw = _read_open_regular(fd, before, MAX_CONFIG)
    finally:
        if fd is not None:
            os.close(fd)
    try:
        policy = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise CandidateError("candidate config is not UTF-8 JSON") from exc
    if set(policy) != {"schema", "workflow", "limits", "allowlist", "outputs"} or policy.get("schema") != "spspy-reverse-producer/v2":
        raise CandidateError("candidate config schema differs")
    workflow = policy.get("workflow")
    if (not isinstance(workflow, dict) or set(workflow) != {"repository", "path", "authority_ref", "signer_workflow_ref", "blob_oid"} or
            not isinstance(workflow.get("repository"), str) or not REPO.fullmatch(workflow["repository"]) or
            not isinstance(workflow.get("path"), str) or _safe_relative(workflow["path"]) != workflow["path"] or
            not workflow["path"].startswith(".github/workflows/") or
            workflow.get("authority_ref") != "refs/heads/main" or
            workflow.get("signer_workflow_ref") != "%s/%s@%s" % (workflow.get("repository"), workflow.get("path"), workflow.get("authority_ref")) or
            (workflow.get("blob_oid") is not None and (not isinstance(workflow["blob_oid"], str) or
                                                        not GIT_OID40.fullmatch(workflow["blob_oid"])))):
        raise CandidateError("candidate workflow declaration is unsafe")
    limits = policy.get("limits")
    if not isinstance(limits, dict) or set(limits) != {"max_file_bytes", "max_payload_bytes", "max_entries", "max_path_bytes"}:
        raise CandidateError("candidate config limits differ")
    if any(type(value) is not int or value <= 0 for value in limits.values()):
        raise CandidateError("candidate config numeric limit is invalid")
    maxima = {"max_file_bytes": MAX_FILE_BYTES, "max_payload_bytes": MAX_PAYLOAD_BYTES,
              "max_entries": MAX_ENTRIES, "max_path_bytes": MAX_PATH_BYTES}
    if any(limits[key] > maxima[key] for key in limits):
        raise CandidateError("candidate config limit exceeds builder ceiling")
    if policy.get("outputs") != ["release-payload.tar", "release-receipt.json"]:
        raise CandidateError("candidate output inventory differs")
    allowlist = policy.get("allowlist")
    if not isinstance(allowlist, list) or not allowlist:
        raise CandidateError("candidate allowlist is empty")
    seen = set()
    items = []
    for item in allowlist:
        if not isinstance(item, dict) or set(item) != {"path", "kind"} or item.get("kind") not in ("file", "directory"):
            raise CandidateError("candidate allowlist entry is invalid")
        relative = _safe_relative(item["path"])
        if relative.casefold() in seen:
            raise CandidateError("candidate allowlist collision")
        seen.add(relative.casefold())
        items.append((relative, item["kind"]))
    return raw, policy, tuple(sorted(items))


def _read_open_regular(fd, before, maximum):
    """Read a previously opened regular file while checking its identity."""
    chunks = []
    total = 0
    while True:
        chunk = os.read(fd, 65536)
        if not chunk:
            break
        total += len(chunk)
        if total > maximum:
            raise CandidateError("candidate input exceeds limit")
        chunks.append(chunk)
    after = os.fstat(fd)
    identity = lambda item: (item.st_dev, item.st_ino, item.st_size, item.st_mtime_ns, item.st_ctime_ns,
                             item.st_mode, item.st_uid, item.st_nlink)
    if identity(before) != identity(after) or total != before.st_size:
        raise CandidateError("candidate input changed during read")
    return b"".join(chunks)


def _read_regular(root_fd, relative, maximum):
    fd, before = _open_regular_beneath(root_fd, relative, maximum)
    try:
        return _read_open_regular(fd, before, maximum)
    finally:
        os.close(fd)


def _walk_input_directory(root_fd, relative):
    directory_fd = _open_directory_beneath(root_fd, relative)
    try:
        try:
            names = sorted(os.listdir(directory_fd))
        except OSError as exc:
            raise CandidateError("candidate directory cannot be listed safely") from exc
        files = []
        for name in names:
            child_relative = _safe_relative(relative + "/" + name)
            try:
                observed = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            except OSError as exc:
                raise CandidateError("candidate directory entry changed") from exc
            if stat.S_ISLNK(observed.st_mode):
                raise CandidateError("candidate contains a symlink")
            if stat.S_ISDIR(observed.st_mode):
                files.extend(_walk_input_directory(root_fd, child_relative))
            elif stat.S_ISREG(observed.st_mode):
                files.append(child_relative)
            else:
                raise CandidateError("candidate contains non-regular entry")
        return files
    finally:
        os.close(directory_fd)


def _iter_input_files(root_fd, allowlist, limits):
    files = []
    for relative, kind in allowlist:
        if kind == "file":
            fd, _observed = _open_regular_beneath(root_fd, relative, limits["max_file_bytes"])
            os.close(fd)
            files.append(relative)
            continue
        files.extend(_walk_input_directory(root_fd, relative))
    if not files or len(files) > limits["max_entries"]:
        raise CandidateError("candidate file count outside limit")
    canonical = []
    names = set()
    folded_components = {}
    for relative in sorted(files):
        relative = _safe_relative(relative)
        if len(relative.encode("utf-8")) > limits["max_path_bytes"] or relative in names:
            raise CandidateError("candidate path collision or overflow")
        parts = relative.split("/")
        for index in range(1, len(parts) + 1):
            component_path = "/".join(parts[:index])
            folded = component_path.casefold()
            previous = folded_components.get(folded)
            if previous is not None and previous != component_path:
                raise CandidateError("candidate path has a case-fold component collision")
            folded_components[folded] = component_path
        if any("/".join(parts[:index]) in names for index in range(1, len(parts))):
            raise CandidateError("candidate path is nested below a regular file")
        if any(existing.startswith(relative + "/") for existing in names):
            raise CandidateError("candidate regular file conflicts with a descendant")
        names.add(relative)
        canonical.append(relative)
    return canonical


def _inventory_sha256(entries):
    digest = hashlib.sha256()
    for entry in sorted(entries, key=lambda item: item["path"].encode("utf-8")):
        digest.update(b"file\0" + entry["path"].encode("utf-8") + b"\0")
        digest.update(entry["sha256"].encode("ascii") + b"\0" + str(entry["size"]).encode("ascii") + b"\n")
    return digest.hexdigest()


def _build_candidate_from_fd(*, root_fd, candidate_repository, source_commit, source_tree, workflow_repository,
                             workflow_path, workflow_ref, signer_workflow_ref, workflow_commit, workflow_blob,
                             output_dir):
    config_raw, policy, allowlist = _load_policy(root_fd)
    if (not isinstance(candidate_repository, str) or not REPO.fullmatch(candidate_repository) or
            not all(isinstance(value, str) and GIT_OID40.fullmatch(value) for value in
                (source_commit, source_tree, workflow_commit, workflow_blob)) or workflow_ref != "refs/heads/main" or
            workflow_repository != policy["workflow"]["repository"] or workflow_path != policy["workflow"]["path"] or
            workflow_ref != policy["workflow"]["authority_ref"] or signer_workflow_ref != policy["workflow"]["signer_workflow_ref"] or
            policy["workflow"]["blob_oid"] is None or workflow_blob != policy["workflow"]["blob_oid"]):
        raise CandidateError("candidate workflow authority differs or is unavailable")
    raw_destination = Path(output_dir)
    if raw_destination.exists() and raw_destination.is_symlink():
        raise CandidateError("output directory is a symlink")
    destination = raw_destination.resolve()
    if not destination.exists() or not destination.is_dir() or any(destination.iterdir()):
        raise CandidateError("output directory must exist, be a directory, and be empty")
    payload_path = destination / "release-payload.tar"
    receipt_path = destination / "release-receipt.json"
    temporary_payload = destination / (".release-payload.%d.tmp" % os.getpid())
    temporary_receipt = destination / (".release-receipt.%d.tmp" % os.getpid())
    files = _iter_input_files(root_fd, allowlist, policy["limits"])
    total = 0
    tar_length = 1024
    entries = []
    try:
        with open(temporary_payload, "xb") as output:
            with tarfile.open(fileobj=output, mode="w", format=tarfile.USTAR_FORMAT) as archive:
                for relative in files:
                    data = _read_regular(root_fd, relative, policy["limits"]["max_file_bytes"])
                    total += len(data)
                    if total > policy["limits"]["max_payload_bytes"]:
                        raise CandidateError("candidate payload exceeds limit")
                    info = tarfile.TarInfo(relative)
                    info.size = len(data)
                    info.mode = 0o600
                    info.uid = info.gid = info.mtime = 0
                    info.uname = info.gname = ""
                    archive.addfile(info, io.BytesIO(data))
                    tar_length += 512 + ((len(data) + 511) // 512) * 512
                    entries.append({"path": relative, "sha256": hashlib.sha256(data).hexdigest(), "size": len(data)})
            # tarfile appends a 10 KiB record.  Job B accepts exactly two zero
            # EOA blocks, so cut only the known deterministic padding.
            output.seek(tar_length)
            output.truncate()
            output.flush()
            os.fsync(output.fileno())
        payload = temporary_payload.read_bytes()
        if len(payload) != tar_length or payload[-1024:] != b"\0" * 1024:
            raise CandidateError("candidate USTAR framing differs")
        input_tree_sha256 = _inventory_sha256(entries)
        receipt = {"schema": SCHEMA, "candidate": {"repository": candidate_repository, "commit": source_commit,
                                                       "tree": source_tree, "input_tree_sha256": input_tree_sha256},
                   "job_a_config_sha256": hashlib.sha256(config_raw).hexdigest(), "entries": entries, "checks": [],
                   "payload_sha256": hashlib.sha256(payload).hexdigest(), "payload_size": len(payload),
                   "workflow": {"repository": workflow_repository, "path": workflow_path, "authority_ref": workflow_ref,
                                "signer_workflow_ref": signer_workflow_ref, "commit": workflow_commit, "blob": workflow_blob}}
        with open(temporary_receipt, "xb") as output:
            output.write(_canonical(receipt) + b"\n")
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary_payload, payload_path)
        os.replace(temporary_receipt, receipt_path)
        directory_fd = os.open(destination, os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_CLOEXEC", 0))
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except BaseException:
        for temporary in (temporary_payload, temporary_receipt):
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass
        raise
    return {"payload": payload_path, "receipt": receipt_path, "receipt_data": receipt}


def build_candidate(*, candidate_root, candidate_repository, source_commit, source_tree, workflow_repository,
                    workflow_path, workflow_ref, signer_workflow_ref, workflow_commit, workflow_blob, output_dir):
    """Emit Job-A raw files into a wrapper-owned, initially empty directory."""
    raw_root = Path(candidate_root)
    if os.path.islink(raw_root):
        raise CandidateError("candidate root must not be a symlink")
    try:
        root = raw_root.resolve(strict=True)
        root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0) |
                          getattr(os, "O_CLOEXEC", 0))
    except OSError as exc:
        raise CandidateError("candidate root is unsafe") from exc
    try:
        if not stat.S_ISDIR(os.fstat(root_fd).st_mode):
            raise CandidateError("candidate root is unsafe")
        return _build_candidate_from_fd(root_fd=root_fd, candidate_repository=candidate_repository,
                                        source_commit=source_commit, source_tree=source_tree,
                                        workflow_repository=workflow_repository, workflow_path=workflow_path,
                                        workflow_ref=workflow_ref, signer_workflow_ref=signer_workflow_ref,
                                        workflow_commit=workflow_commit, workflow_blob=workflow_blob,
                                        output_dir=output_dir)
    finally:
        os.close(root_fd)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate-root", required=True)
    parser.add_argument("--candidate-repository", required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--source-tree", required=True)
    parser.add_argument("--workflow-repository", required=True)
    parser.add_argument("--workflow-path", required=True)
    parser.add_argument("--workflow-ref", required=True)
    parser.add_argument("--signer-workflow-ref", required=True)
    parser.add_argument("--workflow-commit", required=True)
    parser.add_argument("--workflow-blob", required=True)
    parser.add_argument("--output-dir", required=True)
    args = parser.parse_args(argv)
    try:
        result = build_candidate(candidate_root=args.candidate_root, candidate_repository=args.candidate_repository,
                                 source_commit=args.source_commit, source_tree=args.source_tree,
                                 workflow_repository=args.workflow_repository, workflow_path=args.workflow_path,
                                 workflow_ref=args.workflow_ref, signer_workflow_ref=args.signer_workflow_ref,
                                 workflow_commit=args.workflow_commit,
                                 workflow_blob=args.workflow_blob, output_dir=args.output_dir)
    except CandidateError as exc:
        parser.error(str(exc))
    print(_canonical({"payload_sha256": result["receipt_data"]["payload_sha256"], "schema": SCHEMA}).decode("ascii"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
