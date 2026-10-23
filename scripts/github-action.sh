#!/usr/bin/env bash
set -euo pipefail

if [[ ! "${PATCHROVER_PACK}" =~ ^[a-z0-9]+([.-][a-z0-9]+)*$ ]]; then
  echo "Invalid response-pack ID" >&2
  exit 1
fi

if [[ -z "${GITHUB_ACTION_PATH:-}" || -z "${GITHUB_WORKSPACE:-}" || -z "${RUNNER_TEMP:-}" ]]; then
  echo "This entrypoint must run inside GitHub Actions" >&2
  exit 1
fi

case "${PATCHROVER_TRAIL_OUTPUT}" in
  /*|*..*)
    echo "trail-output must be a workspace-relative path without '..'" >&2
    exit 1
    ;;
esac

for relative_input in "${PATCHROVER_SBOM:-}" "${PATCHROVER_KUBE_SNAPSHOT:-}"; do
  case "$relative_input" in
    "") ;;
    /*|*..*)
      echo "optional evidence paths must be workspace-relative and cannot contain '..'" >&2
      exit 1
      ;;
  esac
done

arguments=(
  assess
  --pack "${GITHUB_ACTION_PATH}/packs/${PATCHROVER_PACK}"
  --repo "${GITHUB_WORKSPACE}"
  --out "${GITHUB_WORKSPACE}/${PATCHROVER_TRAIL_OUTPUT}"
  --force
)

if [[ -n "${PATCHROVER_SBOM:-}" ]]; then
  arguments+=(--sbom "${GITHUB_WORKSPACE}/${PATCHROVER_SBOM}")
fi
if [[ -n "${PATCHROVER_KUBE_SNAPSHOT:-}" ]]; then
  arguments+=(--kube-snapshot "${GITHUB_WORKSPACE}/${PATCHROVER_KUBE_SNAPSHOT}")
fi

cd "${GITHUB_ACTION_PATH}"
build_directory="$(mktemp -d "${RUNNER_TEMP}/patchrover-action.XXXXXX")"
cleanup() {
  rm -rf "${build_directory}"
}
trap cleanup EXIT

go build -trimpath -o "${build_directory}/patchrover" ./cmd/patchrover
"${build_directory}/patchrover" "${arguments[@]}"
