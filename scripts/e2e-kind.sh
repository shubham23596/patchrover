#!/usr/bin/env bash
set -euo pipefail

for dependency in go docker kind kubectl; do
  if ! command -v "$dependency" >/dev/null 2>&1; then
    echo "$dependency is required for the disposable-cluster test" >&2
    exit 1
  fi
done

project_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
work_directory="$(mktemp -d)"
cluster_name="patchrover-e2e-${RANDOM}"
context="kind-${cluster_name}"

cleanup() {
  kind delete cluster --name "$cluster_name" >/dev/null 2>&1 || true
  rm -rf "$work_directory"
}
trap cleanup EXIT

cd "$project_root"
go build -trimpath -o "$work_directory/patchrover" ./cmd/patchrover
kind create cluster --name "$cluster_name" --wait 120s

node="$(kind get nodes --name "$cluster_name" | head -n 1)"
node_image="$(docker inspect --format '{{.Config.Image}}' "$node")"
docker tag "$node_image" php:8.4.26-apache
docker tag "$node_image" php:8.4.27-apache
kind load docker-image --name "$cluster_name" php:8.4.26-apache php:8.4.27-apache

kubectl --context "$context" run patchrover-affected \
  --image=php:8.4.26-apache \
  --image-pull-policy=Never \
  --restart=Never \
  --command -- /bin/sh -c 'sleep 600'
kubectl --context "$context" wait pod/patchrover-affected --for=condition=Ready --timeout=90s

set +e
"$work_directory/patchrover" assess \
  --pack packs/php-2026-rce \
  --repo packs/php-2026-rce/fixtures/affected \
  --kube-context "$context" \
  --out "$work_directory/affected-trail.json"
affected_status=$?
set -e
if [[ "$affected_status" -ne 2 ]]; then
  echo "expected affected exit code 2, received $affected_status" >&2
  exit 1
fi

kubectl --context "$context" delete pod patchrover-affected --wait=true
kubectl --context "$context" run patchrover-fixed \
  --image=php:8.4.27-apache \
  --image-pull-policy=Never \
  --restart=Never \
  --command -- /bin/sh -c 'sleep 600'
kubectl --context "$context" wait pod/patchrover-fixed --for=condition=Ready --timeout=90s

"$work_directory/patchrover" verify \
  --pack packs/php-2026-rce \
  --trail "$work_directory/affected-trail.json" \
  --repo packs/php-2026-rce/fixtures/fixed \
  --kube-context "$context" \
  --receipt "$work_directory/receipt.json"
"$work_directory/patchrover" receipt verify "$work_directory/receipt.json"

echo "Disposable OCI and Kubernetes evidence flow passed."
