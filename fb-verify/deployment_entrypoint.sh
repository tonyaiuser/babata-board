#!/usr/bin/env bash
# Stable launchd entrypoint for immutable FB verifier releases.
set -euo pipefail

DEPLOY_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENTRYPOINT_NAME="$(basename "$0")"

case "$ENTRYPOINT_NAME" in
  run_daily_fb_verify.sh|run_nightly_single_page_fb_verify.sh|sync_deploy.sh) ;;
  *)
    printf 'unsupported FB verifier deployment entrypoint: %s\n' "$ENTRYPOINT_NAME" >&2
    exit 64
    ;;
esac

if [[ -e "${DEPLOY_ROOT}/.deployment.gate" ]] || \
   [[ -L "${DEPLOY_ROOT}/.deployment.gate" ]]; then
  printf 'FB verifier deployment gate is active; retry after deployment finishes\n' >&2
  exit 75
fi

if [[ ! -L "${DEPLOY_ROOT}/current" ]]; then
  printf 'FB verifier current release is missing: %s\n' "${DEPLOY_ROOT}/current" >&2
  exit 66
fi

# Resolve the symlink once. A concurrent atomic release switch cannot change
# this invocation's code root after resolution, and old releases are immutable.
RELEASE_ROOT="$(cd "${DEPLOY_ROOT}/current" && pwd -P)"
TARGET="${RELEASE_ROOT}/${ENTRYPOINT_NAME}"
if [[ ! -x "$TARGET" ]]; then
  printf 'FB verifier release entrypoint is missing: %s\n' "$TARGET" >&2
  exit 66
fi
RELEASE_ID="$(basename "$RELEASE_ROOT")"
if [[ ! "$RELEASE_ID" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$ ]]; then
  printf 'FB verifier immutable release id is unsafe: %s\n' "$RELEASE_ID" >&2
  exit 66
fi

export FB_VERIFY_DATA_ROOT="${DEPLOY_ROOT}/data"
export FB_VERIFY_DEPLOY_DIR="$DEPLOY_ROOT"
case "$ENTRYPOINT_NAME" in
  run_daily_fb_verify.sh|run_nightly_single_page_fb_verify.sh)
    # Daily and nightly serialize on the same kernel-backed lock.  Nightly's
    # nested daily call inherits and validates the already-held descriptor.
    export FB_VERIFY_RUN_LOCK_PATH="${DEPLOY_ROOT}/data/run_daily.lock"
    # This value is derived exactly once from the already-resolved immutable
    # release directory.  The runner must never consult `current` later.
    export FB_VERIFY_RELEASE_ID="$RELEASE_ID"
    ;;
esac
exec "$TARGET" "$@"
