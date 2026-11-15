# KubeChaos operator image. Build from the repository root:
#   docker build -f operator/Dockerfile -t kubechaos-operator:dev .
# Base images are pinned by digest; update deliberately.

FROM golang:1.26-bookworm@sha256:dc40a13b61304647ed7e5d581d246b86413dfc29d63c6d018310feb93cd98fc0 AS build
WORKDIR /src
ENV CGO_ENABLED=0 GOOS=linux GOWORK=off GOTOOLCHAIN=local
COPY operator/go.mod operator/go.sum ./operator/
RUN --mount=type=cache,target=/root/go/pkg/mod cd operator && go mod download
COPY operator/ ./operator/
ARG VERSION=dev
RUN --mount=type=cache,target=/root/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    cd operator && go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/manager ./cmd/manager

# Distroless static, non-root: no shell, no package manager, UID 65532.
FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
COPY --from=build /out/manager /manager
USER 65532:65532
ENTRYPOINT ["/manager"]
