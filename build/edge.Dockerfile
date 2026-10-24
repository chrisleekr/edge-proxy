# Edge image: one static binary on distroless, running as nonroot.
# Bases are pinned by digest; update tag and digest together.
# Build stages run on the build host and cross-compile, so a multi-platform
# build needs no emulation.
FROM --platform=$BUILDPLATFORM golang:1.27.3-trixie@sha256:1896654cfc5c2b5ad74c07f29cb36f5d2d1cbed42e3054070fbfe444e521e83c AS build
ARG TARGETOS TARGETARCH
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
# grpcnotrace drops gRPC's golang.org/x/net/trace, whose html/template
# disables the linker's dead-method elimination: 13 MB more without it.
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -tags grpcnotrace -trimpath -ldflags="-s -w" -o /out/edge ./cmd/edge

FROM gcr.io/distroless/static-debian13:nonroot@sha256:516757106de35205efb70b91ba03f6f1298424a0678c603255cf2852a7000087
COPY --from=build /out/edge /edge
EXPOSE 8080 9090
ENTRYPOINT ["/edge"]
