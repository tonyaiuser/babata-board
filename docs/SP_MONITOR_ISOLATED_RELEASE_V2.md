# SPSPY isolated release v2

This document describes the implemented release-evidence protocol. It is not a
deployment command, does not start a periodic scan, and is not connected to the
Facebook release path. Production activation remains fail-closed; see
"Operational state" below.

## Boundaries and authority

| Stage | Treats as hostile | Produces | Authority |
| --- | --- | --- | --- |
| Job A candidate builder | candidate config and candidate tree | raw USTAR plus a non-authoritative candidate receipt | none |
| Job B trusted reusable workflow | the whole Job-A pair | canonical USTAR plus the v1 trusted receipt | pinned workflow bytes and pinned policy bytes |
| Online host verifier | GitHub ZIP, bundles, and REST responses | one `VerifiedArtifact` for a single run | out-of-band `ExpectedAuthority`, pinned TUF root, and pinned `gh` |
| R1/R2 seal | both online results | canonical evidence envelope | two independent run/artifact/job authorities |
| Offline activation/CAS | envelope and every embedded evidence object | fresh activation result or durable CAS release | four fresh offline verifications using external authorities |

`ExpectedAuthority` is supplied outside the artifact and envelope. It pins:

- candidate repository numeric ID/name, commit, Git tree, ref, and file-inventory digest;
- caller repository numeric ID/name, commit, ref, workflow numeric ID and path;
- signer repository numeric ID/name, workflow path/ref/commit, Git blob OID, and workflow-bytes SHA-256;
- policy path, Git blob OID and raw-byte SHA-256, plus the out-of-band TUF-root SHA-256;
- runner label/OS/image and exact run, attempt, artifact, and REST job identities.

The current producer checks out the candidate from the caller repository, so
their repository IDs and names must match. Candidate commit/tree identity is
still separate from the caller workflow commit and is never inferred from the
workflow-run head.

## Job A interface

The candidate builder accepts only this fixed interface:

```text
reverse_candidate_build_v2.py \
  --candidate-root <checked-out root> \
  --candidate-repository <owner/repo> \
  --source-commit <40-hex> \
  --source-tree <40-hex> \
  --workflow-repository <owner/repo> \
  --workflow-path .github/workflows/trusted-reverse-producer-v2.yml \
  --workflow-ref refs/heads/main \
  --signer-workflow-ref <owner/repo/.github/workflows/trusted-reverse-producer-v2.yml@refs/heads/main> \
  --workflow-commit <40-hex> \
  --workflow-blob <40-hex> \
  --output-dir <wrapper-owned empty directory>
```

It does not accept a command, test executable, policy path, or runner. It only
copies the fixed allowlist. Its receipt is
`spspy.candidate-reverse-v2.receipt` and remains hostile input to Job B.
`config/reverse_producer_v2.json` separates the plain authority ref
`refs/heads/main` from the full signer workflow identity.

## Frozen producer contract

The trusted policy schema is
`spspy.trusted-reverse-producer-v2.release-policy`, version `1`. Its exact root
keys are `archive`, `inventory`, `limits`, `paths`, `schema`, and `version`.
The production policy fixture is 1,122 bytes with SHA-256
`cba580d3683481b17db1541fe44315aec24d61fbb0804823058181231ce3b9d6`.
The policy document embedded in the receipt, the raw-byte SHA-256, and the
policy file's 40-hex Git blob OID are three separate bindings.

The inventory digest is SHA-256 over UTF-8-bytewise sorted records:

```text
file NUL utf8_path NUL content_sha256_hex NUL size_decimal LF
```

The final receipt schema is `spspy.trusted-reverse-producer-v2.receipt`,
version `1`, with exact root keys `canonical`, `canonicalization`,
`candidate_inventory`, `payload`, `provenance`, `raw`, `release_policy`,
`source_receipt`, `schema`, and `version`. Receipt bytes must themselves be
canonical JSON.

Canonical archives contain only USTAR typeflag `0` regular files, mode `0600`,
UID/GID/mtime zero, zero padding, UTF-8-bytewise ordering, and exactly two
terminal zero blocks. The consumer reconstructs the archive and requires exact
byte equality. Long names use stdlib `TarInfo._posix_split_name`'s
first-feasible component split. A 100-byte name field or 155-byte prefix field
may occupy the whole field without a NUL; shorter values require a NUL followed
only by zero bytes. Controls, links, GNU/PAX records, ambiguous octal fields,
case-fold collisions, and regular-file ancestor conflicts are rejected.

## GitHub and attestation verification

The GitHub artifact ZIP must contain exactly these two bounded regular members:

```text
canonical-reverse.tar
canonical-reverse-receipt.json
```

The online verifier independently checks repository metadata, signer workflow
and policy Git blobs/bytes, artifact metadata, the workflow run, and the exact
attempt-specific jobs endpoint. The frozen REST evidence records repository and
head IDs/SHA/branch, run attempt/workflow, and exact successful hosted-runner
job. Artifact ID and job ID are REST facts; they are not claimed to be signed.
GitHub has no artifact-to-job cryptographic link, so the protocol combines the
artifact-to-run REST link with signed subject bytes, certificate run identity,
and the pinned reusable workflow/receipt. It does not describe that combination
as a signed artifact ID.

For both the tar and receipt, verification flags are constructed only from
`ExpectedAuthority`: repository, signer digest, source digest/ref, exact
certificate identity and issuer, hosted-runner denial, SLSA v1 predicate type,
saved bundle, and custom trusted root. `gh 2.87.3` makes its certificate,
signer-repository, and signer-workflow selectors mutually exclusive, so the
command uses only exact `--cert-identity`; the parsed verified certificate is
then compared with the expected signer repository, workflow path/ref, and
commit. The implementation uses `actions/attest` default SLSA provenance;
there is no fictional custom `spspyReleaseV2` predicate.

The parser follows `gh 2.87.3 --format json`: `attestation.bundle`,
`verificationResult.mediaType`, `signature.certificate`,
`verifiedTimestamps`, and the nested in-toto statement. Only the verified
certificate and timestamps are treated as values the originating workflow
cannot manipulate. The statement and predicate are checked as cross-evidence
for subject SHA/name, caller workflow/dependency, hosted builder, repository ID,
and invocation URI; their trust comes from the separately pinned reusable
workflow and the signed, strictly validated receipt, not from predicate fields
alone.

Production never searches `PATH` or executes Homebrew's mutable symlink. It
pins `/opt/homebrew/Cellar/gh/2.87.3/bin/gh`, exact version output, mode `0555`,
owner, link count, file identity before/after invocation, and SHA-256
`67b51ba8ca861e0fcd4749d47eba740e8db8c799a8b18645833e904e09f7fb70`.
The reviewed upstream `cli/cli` tag `v2.87.3` resolves to commit
`cf862d65df7f8ff528015e235c8cccd48cea286f`.
The subprocess has a minimal environment, optional host-supplied `GH_TOKEN`, no
shell, fixed timeouts, and actively bounded stdout/stderr. No credential is
stored in the repository. A `gh` upgrade or Cellar path change requires an
explicit review and re-seal of path, version, mode and hash.

## R1/R2, activation, and CAS

R1 and R2 must have different run IDs, artifact IDs, and job IDs while all
stable external authority fields match. Each run verifies the tar and receipt
online. The envelope preserves both receipts, all four downloaded bundles, and
selected REST evidence. Offline verification parses the payload/receipts again
and reruns four `gh attestation verify` calls with the external R1/R2
authorities and external root.

`reverify_for_activation(...)` performs that full verification immediately
before activation and returns an immutable `ActivationReverifyResult` binding
authority, envelope, payload, and root digests. Activation code must call this
function itself; it must not accept a caller-created proof object.

`RepositoryCAS.store_release(...)` likewise accepts raw evidence plus both
external authorities and repeats the full offline verification on every call.
It does not trust a public dataclass or a previous boolean result. No CAS child
is created before verification succeeds. Publication uses exact-mode/owner/link
checks, no-follow descriptor-relative I/O, per-file hashes, a bounded-retry
nonblocking exclusive lock, a private transaction directory, fsync, a commit
marker, and atomic rename. Lock contention fails closed at a monotonic deadline.
Recovery publishes a committed transaction only when its complete inventory
equals the release bytes freshly reverified by the same call. A forged marker,
wrong digest, hardlink alias, or malformed existing entry fails closed.

## Native selector and recovery protocol

The release family and on-disk control names retain `v2`, but the native wire
and durable-state protocol is version 3. Its packed little-endian structures
have fixed, compile-time-asserted sizes and offsets; every reserved field must
be zero. A version-2 or differently sized state/marker is blocked rather than
upgraded in place.

`prior_present` is an explicit boolean in every transaction message and in both
durable records. When it is false, the prior digest and prior FD are both
absent. A genuinely fresh root may select only with that absent form. Once a
terminal selection exists, a later epoch must prove the exact selected
predecessor before re-verification, CAS publication, or selector mutation. A
candidate digest equal to a present predecessor is rejected as ambiguous.

The native parent holds the bounded nonblocking selector lock. The activation
and rollback workers each hold a fixed role-lease file from before `READY`
until exit. Durable state and the permanent nonce marker bind the two lease
inode identities, all verification digests, epoch, nonce, and the explicit
prior form. Recorded PIDs are audit data only: inspection and recovery never
use PID liveness and never signal a process. They acquire the selector and both
role leases to prove the workers have exited.

`inspect_reconciliation(...)` is strictly read-only and reports a canonical
`SP_RELEASE_V3_INSPECT` classification. It distinguishes fresh, busy/active,
terminal, recoverable, debris, and blocked roots without creating or repairing
entries. `recover_interrupted(...)` requires the caller to echo the exact raw
state SHA-256 observed by inspection, reacquires all three locks, and rebinds
that digest after locking. It can converge only a semantically complete state,
an exact nonce marker, a provable `current.payload`, and exited workers; it
never retries the interrupted nonce.

Rollback recovery from phase 4 with the candidate already selected first
persists and fsyncs phase 8 (`RECOVERING_ROLLBACK`, origin phase 4), then restores
the exact predecessor. An absent predecessor is restored as true absence only
after proving `current.payload` still hashes to the candidate, unlinking it,
and fsyncing the root. Once phase 8 is durable, every later recovery path can
only continue rollback. Inspection reports transaction temporary files as
debris without changing them. Under the selector and both role leases,
recovery may delete and fsync at most one exact, safe, transaction-bound state
or role temporary and then recompute from durable authority; it never promotes
a temporary. A state temporary is accepted only when its name is exactly
`.sp-release-v2.state.<nonce-hex>.<decoded-phase>.tmp`; matching a nonce prefix
or valid-looking contents is insufficient. Unknown, noncanonical, or multiple
temporaries remain in place and classify as blocked/debris. The complete scan
must establish that exactly one acceptable temporary exists before any unlink;
the deletion and root-directory fsync happen only after that decision.

Reconciliation JSON preserves an observed digest even when `current.payload`
does not match either authoritative candidate and is therefore classified
`UNKNOWN`. `ABSENT` always carries the zero digest, while `PAYLOAD` and `PRIOR`
always carry a nonzero digest. Fresh, selector-busy, and worker-active reports
are empty-state reports only; fresh is `ABSENT`, while busy and active are
`UNKNOWN`.

Public activation, inspection, and recovery execute only the preinstalled
helper at
`/Library/Application Support/SPSPY/libexec/sp-release-seatbelt-v3`. Runtime
compilation is not a production fallback. The public gate requires a non-root
runtime identity, a descriptor-walked root-owned and non-writable directory
chain on trusted local APFS/HFS storage, no extended ACLs, an exact root-owned
`0555` single-link helper, and sealed binary SHA-256, CDHash, and architecture
authorities. The held audit FD and native program additionally bind the named
inode and bytes at execution. Those three production authorities are
deliberately unset in this checkout, so the public API fails before opening an
activation root. The randomly named owner-private `/private/tmp` executable
snapshot and owner-helper compile flag exist only behind explicit internal
test/canary hooks; they are not the production platform boundary.

## Verification matrix

The automated tests cover:

| Class | Evidence |
| --- | --- |
| Producer golden | production policy raw hash/Git blob semantics, canonical receipt hash, canonical tar hash, inventory digest |
| USTAR hostility | NUL typeflag, controls, noncanonical octal, extra EOA blocks, `a` plus `a/b`, first-vs-last split, full-width name/prefix |
| Attestation | pinned `gh 2.87.3` documented JSON-schema fixture, parser/argv contract, four simulated offline calls, alternate signer/caller replay |
| REST/replay | repository/head IDs, SHA/branch, run attempt, exact attempt jobs query, hosted runner, same-run replay |
| Tamper | receipt encoding, policy bytes/Git OID, TUF root, envelope payload/REST evidence |
| CAS | zero writes before failed proof, bounded cross-process lock contention, idempotency, exact modes/hashes, pre/post-marker crash, forged durable transaction, hardlink alias |
| Tool pin | absolute real path, version, binary hash, and before/after identity mismatch |
| Native selector v3 | fresh absence, predecessor binding, fixed layout/version rejection, held-root rename swap, role leases, read-only inspection, exact-state recovery, phase-8 rollback, six recovery crash points, temporary debris, mutable-input snapshot isolation |

Run the focused suite with either supported interpreter:

```text
/usr/bin/python3 -B -m unittest -v \
  tests/test_reverse_candidate_build_v2.py \
  tests/test_sp_release_artifact_v2.py

/opt/homebrew/bin/python3 -B -m unittest -v \
  tests/test_reverse_candidate_build_v2.py \
  tests/test_sp_release_artifact_v2.py

/usr/bin/python3 -B -m unittest -v \
  tests/test_sp_release_activate_v2.py \
  tests/test_sp_release_seatbelt_v2.py

/opt/homebrew/bin/python3 -B -m unittest -v \
  tests/test_sp_release_activate_v2.py \
  tests/test_sp_release_seatbelt_v2.py
```

## Operational state

This is an implemented and locally tested protocol component, not an activated
release. `config/reverse_producer_v2.json` intentionally has `blob_oid: null`,
and no production TUF root or per-run `ExpectedAuthority` records are sealed in
this change. The fixed root-owned native helper is not installed and its
binary SHA-256, CDHash, and architecture authorities are also unset. Those
missing authorities make the builder, verifier, and public selector API fail
closed. No GitHub workflow was dispatched, no artifact was activated, and no
Facebook release or scan was started by this work.

Production deployment additionally requires a controlled GitHub-hosted canary
to obtain genuine `actions/attest` bundles and `gh 2.87.3 --format json`
results. A separately reviewed installation process must build/sign the native
helper, record toolchain evidence, install it through privileged operations,
and seal its binary SHA-256, CDHash, and architecture. The pinned executables
must then successfully perform online download, all four offline tar/receipt
verifications, and an isolated selector/recovery canary. The resulting evidence
must be reviewed and sealed. These compatibility and installation gates have
not been run; production activation is prohibited until they pass.
