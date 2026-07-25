#!/bin/sh
# Construction du binaire ardoise — statique, reproductible (ES-9, DIST-1).
# La chaîne d'approvisionnement complète (SBOM, signatures, provenance)
# arrive en phase F ; ce script reste volontairement minimal.
set -eu
cd "$(dirname "$0")"

VERSION="${ARDOISE_VERSION:-0.1.0-dev}"
ID_COMPILATION="${ARDOISE_ID_COMPILATION:-$(git rev-parse --short=12 HEAD 2>/dev/null || echo inconnu)}"

CGO_ENABLED=0 go build \
  -trimpath \
  -buildvcs=false \
  -ldflags "-s -w -buildid= \
    -X ardoise.pm/internal/cli.Version=${VERSION} \
    -X ardoise.pm/internal/cli.IDCompilation=${ID_COMPILATION}" \
  -o ardoise ./cmd/ardoise

echo "binaire : ./ardoise (version ${VERSION}, compilation ${ID_COMPILATION})"
echo ""
echo "tests avec détection de race (-race, CGO requis)..."
CGO_ENABLED=1 go test -race -count=1 ./...
echo "tests : OK"
