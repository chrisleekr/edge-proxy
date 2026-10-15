# Admin image: the UI is built with Node, embedded with go:embed, and the
# static binary runs on distroless as nonroot. Node is never in the image.
FROM --platform=$BUILDPLATFORM node:24.21.0-trixie-slim@sha256:173f125896c3b47ddf056734c7ea789d04595a6a08769a8f78e0df642781fb66 AS ui
WORKDIR /ui
COPY web/admin/package.json web/admin/package-lock.json ./
RUN npm ci
COPY web/admin ./
RUN npm run build

# Build stages run on the build host and cross-compile, so a multi-platform
# build needs no emulation.
FROM --platform=$BUILDPLATFORM golang:1.27.2-trixie@sha256:47667934874913a449b96faa7ef4777fa285d9ec29126ee80ed61c45b7cccf0e AS build
ARG TARGETOS TARGETARCH
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
COPY web/admin/ui.go ./web/admin/
COPY --from=ui /ui/dist ./web/admin/dist
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags="-s -w" -o /out/admin ./cmd/admin

FROM gcr.io/distroless/static-debian13:nonroot@sha256:e2e927ec666bae08560abb3c55d0659eceabb657f56b6782ab500a9fc7f555e3
COPY --from=build /out/admin /admin
EXPOSE 8081
ENTRYPOINT ["/admin"]
