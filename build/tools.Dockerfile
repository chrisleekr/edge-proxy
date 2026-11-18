# Load-test helpers (mock upstream, mock IdP, seed). Test-only; runs as root
# so it can write the shared volume.
FROM golang:1.27.4-trixie@sha256:f18c3d73a184fb0582828510722e723b63a93f7188d11dd223d9be6f6880e65d AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
COPY web/admin/ui.go ./web/admin/
COPY web/admin/dist/.gitkeep ./web/admin/dist/
COPY loadtest ./loadtest
RUN CGO_ENABLED=0 go build -tags grpcnotrace -trimpath -o /out/tools ./loadtest/tools

FROM gcr.io/distroless/static-debian13@sha256:1a64f46364620465ef9e9a8f5413757dfdf22695e050bbfd7303eeaf17a59383
COPY --from=build /out/tools /tools
ENTRYPOINT ["/tools"]
