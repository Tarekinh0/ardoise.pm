# Ardoise — Image de production (multi-stage, UBI micro)
# Images épinglées par SHA256 le 2026-07-25 (SRQ-P001-1, SRQ-P001-6, PR-101)
# Aucun secret, clef, ou certificat dans l'image finale.

# ============================================================
# Stage 1 : Compilation Go statique et reproductible (SRQ-P002-5)
# ============================================================
FROM golang:1.24-bookworm@sha256:1ecb7edf62a0408027bd5729dfd6b1b8766e578e8df93995b225dfd0944eb651 AS builder

WORKDIR /build

# La somme go.sum est vérifiée avant compilation (SRQ-P002-1)
COPY go.mod go.sum ./
RUN go mod download && go mod verify

# Sources — seul le strict nécessaire est copié
COPY cmd/          ./cmd/
COPY internal/     ./internal/

# Compilation statique, reproductible (ES-9, ADR-001, ADR-008)
# CGO_ENABLED=0, -trimpath, -buildvcs=false, -ldflags="-s -w -buildid="
ARG VERSION="0.1.0"
ARG ID_COMPILATION="inconnu"
ARG SOURCE_DATE_EPOCH="0"

# Propager SOURCE_DATE_EPOCH dans l'environnement du RUN pour
# que la toolchain Go le lise et produise un binaire reproductible
# (ES-9, ADR-008).
ENV SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH

RUN CGO_ENABLED=0 GOFLAGS=-buildvcs=false \
  go build \
  -trimpath \
  -ldflags "-s -w -buildid= \
    -X ardoise.pm/internal/cli.Version=${VERSION} \
    -X ardoise.pm/internal/cli.IDCompilation=${ID_COMPILATION}" \
  -o /ardoise ./cmd/ardoise

# ============================================================
# Stage 2 : Image minimale UBI micro (SRQ-P001-1, DPO-P-001-1)
# ============================================================
# Digest vérifié depuis registry.access.redhat.com le 2026-07-25
FROM registry.access.redhat.com/ubi9/ubi-micro@sha256:98ab4c56274cf6d9f5574884543c5f6f599ac32732f428e3c9904c65853c1f26

# Métadonnées de l'image (pas de données d'exploitation)
LABEL org.opencontainers.image.title="ardoise.pm"
LABEL org.opencontainers.image.description="Service ephemeral de messagerie chiffree"
LABEL org.opencontainers.image.source="https://github.com/ardoise/ardoise"
LABEL org.opencontainers.image.vendor="Ardoise"
LABEL org.opencontainers.image.licenses="Apache-2.0"

# Non-root : l'image ne tourne jamais en root (SRQ-P001-2, DPO-P-001-2)
USER 1000:1000

# Binaire seul — aucun fichier source, aucune clef, aucun certificat
# (DPO-P-001-1 : seul le binaire compile est copie dans le stage final)
COPY --from=builder --chmod=555 /ardoise /ardoise

# Port d'écoute standard (SRQ-P001 containers spec)
EXPOSE 8443

# Point d'entrée en forme exec (pas de shell) — ubi-micro n'a pas /bin/sh
# (SRQ-P001-3 : pas de shell form)
ENTRYPOINT ["/ardoise", "serve", "--config", "/etc/ardoise/ardoise.json"]
