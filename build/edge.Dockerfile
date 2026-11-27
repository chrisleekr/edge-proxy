# Edge image: one static binary on distroless, running as nonroot.
# Bases are pinned by digest; update tag and digest together.
# Build stages run on the build host and cross-compile, so a multi-platform
# build needs no emulation.
FROM --platform=$BUILDPLATFORM golang:1.27.4-trixie@sha256:430985542100b871e108ccc00e8dcc5eef08ca14ee5825e98ebf563d8ffec4ee AS build
ARG TARGETOS TARGETARCH
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
# grpcnotrace drops gRPC's golang.org/x/net/trace, whose html/template
# disables the linker's dead-method elimination: 13 MB more without it.
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -tags grpcnotrace -trimpath -ldflags="-s -w" -o /out/edge ./cmd/edge

FROM gcr.io/distroless/static-debian13:nonroot@sha256:8ce6dd87e9823c5b48dcfb2c8604714ccb351ce59607327bcc4957448da279b5
COPY --from=build /out/edge /edge
EXPOSE 8080 9090
ENTRYPOINT ["/edge"]
