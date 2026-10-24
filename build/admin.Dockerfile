# Admin image: the UI is built with Node, embedded with go:embed, and the
# static binary runs on distroless as nonroot. Node is never in the image.
FROM --platform=$BUILDPLATFORM node:24.22.0-trixie-slim@sha256:7f486cabe892bff8fef04c0f7da8dba84a560be3e4e2740b7a86afc57ebec315 AS ui
WORKDIR /ui
COPY web/admin/package.json web/admin/package-lock.json ./
RUN npm ci
COPY web/admin ./
RUN npm run build

# Build stages run on the build host and cross-compile, so a multi-platform
# build needs no emulation.
FROM --platform=$BUILDPLATFORM golang:1.27.3-trixie@sha256:1896654cfc5c2b5ad74c07f29cb36f5d2d1cbed42e3054070fbfe444e521e83c AS build
ARG TARGETOS TARGETARCH
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
COPY web/admin/ui.go ./web/admin/
COPY --from=ui /ui/dist ./web/admin/dist
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -tags grpcnotrace -trimpath -ldflags="-s -w" -o /out/admin ./cmd/admin

FROM gcr.io/distroless/static-debian13:nonroot@sha256:516757106de35205efb70b91ba03f6f1298424a0678c603255cf2852a7000087
COPY --from=build /out/admin /admin
EXPOSE 8081
ENTRYPOINT ["/admin"]
