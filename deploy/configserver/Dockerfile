# Build the static configserver binary (UI is embedded via go:embed).
FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags "-s -w" -o /out/configserver ./cmd/configserver
# Stage a data dir owned by the distroless nonroot user (uid 65532) so a fresh
# named volume inherits writable ownership on first mount.
RUN mkdir -p /out/data && chown 65532:65532 /out/data

# Minimal, non-root runtime. No shell, no package manager — just the static binary.
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/configserver /configserver
COPY --from=build --chown=nonroot:nonroot /out/data /data
ENV DATA_DIR=/data LISTEN=:8080 IDLE_TIMEOUT=30m
EXPOSE 8080
USER nonroot:nonroot
VOLUME ["/data"]
ENTRYPOINT ["/configserver"]
