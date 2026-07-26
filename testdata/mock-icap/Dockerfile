# Mock ICAP — pour tests d'intégration docker-compose uniquement
# Ne jamais déployer en production.
FROM golang:1.24-bookworm@sha256:1ecb7edf62a0408027bd5729dfd6b1b8766e578e8df93995b225dfd0944eb651 AS builder
WORKDIR /build
COPY main.go ./
RUN GO111MODULE=off CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /mock-icap .

FROM registry.access.redhat.com/ubi9/ubi-micro@sha256:98ab4c56274cf6d9f5574884543c5f6f599ac32732f428e3c9904c65853c1f26
USER 1000:1000
COPY --from=builder --chmod=555 /mock-icap /mock-icap
ENTRYPOINT ["/mock-icap"]
