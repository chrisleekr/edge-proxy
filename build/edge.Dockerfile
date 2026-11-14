# Edge image: one static binary on distroless, running as nonroot.
# Bases are pinned by digest; update tag and digest together.
# Build stages run on the build host and cross-compile, so a multi-platform
# build needs no emulation.
FROM --platform=$BUILDPLATFORM golang:1.27.4-trixie@sha256:b54b2639de8c1bfe538ec5ffc45f29b1932235ac5f6d63c059853646677112d9 AS build
ARG TARGETOS TARGETARCH
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
# grpcnotrace drops gRPC's golang.org/x/net/trace, whose html/template
# disables the linker's dead-method elimination: 13 MB more without it.
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -tags grpcnotrace -trimpath -ldflags="-s -w" -o /out/edge ./cmd/edge

FROM gcr.io/distroless/static-debian13:nonroot@sha256:aafe993665bf6200db38a02c11a9351e782a84b6a45e7f33b6695638c88e3931
COPY --from=build /out/edge /edge
EXPOSE 8080 9090
ENTRYPOINT ["/edge"]
