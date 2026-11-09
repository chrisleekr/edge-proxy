# Load-test helpers (mock upstream, mock IdP, seed). Test-only; runs as root
# so it can write the shared volume.
FROM golang:1.27.3-trixie@sha256:af1bfc2614ebb1dbd31af514b78740fd678850e76498762b425ecee4c5c6ea80 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
COPY web/admin/ui.go ./web/admin/
COPY web/admin/dist/.gitkeep ./web/admin/dist/
COPY loadtest ./loadtest
RUN CGO_ENABLED=0 go build -tags grpcnotrace -trimpath -o /out/tools ./loadtest/tools

FROM gcr.io/distroless/static-debian13@sha256:448810357cc8e67b7208988abdba0f5ec3d3aebee0a5b13eb624979792cffc0f
COPY --from=build /out/tools /tools
ENTRYPOINT ["/tools"]
