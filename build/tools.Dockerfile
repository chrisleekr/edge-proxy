# Load-test helpers (mock upstream, mock IdP, seed). Test-only; runs as root
# so it can write the shared volume.
FROM golang:1.27.3-trixie@sha256:1896654cfc5c2b5ad74c07f29cb36f5d2d1cbed42e3054070fbfe444e521e83c AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
COPY web/admin/ui.go ./web/admin/
COPY web/admin/dist/.gitkeep ./web/admin/dist/
COPY loadtest ./loadtest
RUN CGO_ENABLED=0 go build -trimpath -o /out/tools ./loadtest/tools

FROM gcr.io/distroless/static-debian13@sha256:9e0130bec991f471279b70f1630ada11e46dad439ef2949544f96001225329fb
COPY --from=build /out/tools /tools
ENTRYPOINT ["/tools"]
