# Load-test helpers (mock upstream, mock IdP, seed). Test-only; runs as root
# so it can write the shared volume.
FROM golang:1.27.4-trixie@sha256:430985542100b871e108ccc00e8dcc5eef08ca14ee5825e98ebf563d8ffec4ee AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
COPY web/admin/ui.go ./web/admin/
COPY web/admin/dist/.gitkeep ./web/admin/dist/
COPY loadtest ./loadtest
RUN CGO_ENABLED=0 go build -tags grpcnotrace -trimpath -o /out/tools ./loadtest/tools

FROM gcr.io/distroless/static-debian13@sha256:4c2cd1dee442c9a99924a378c7c126fac8fef14771579ef567c3f2bdd7a5122a
COPY --from=build /out/tools /tools
ENTRYPOINT ["/tools"]
