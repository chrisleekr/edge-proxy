# Load-test helpers (mock upstream, mock IdP, seed). Test-only; runs as root
# so it can write the shared volume.
FROM golang:1.27.2-trixie@sha256:47667934874913a449b96faa7ef4777fa285d9ec29126ee80ed61c45b7cccf0e AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
COPY web/admin/ui.go ./web/admin/
COPY web/admin/dist/.gitkeep ./web/admin/dist/
COPY loadtest ./loadtest
RUN CGO_ENABLED=0 go build -trimpath -o /out/tools ./loadtest/tools

FROM gcr.io/distroless/static-debian13@sha256:58133991db06659feaabe0f4e97a35cebf15ef4ea08f8a4c6d2ee5f75e4aa6a0
COPY --from=build /out/tools /tools
ENTRYPOINT ["/tools"]
