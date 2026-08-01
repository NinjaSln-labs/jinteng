# Multi-arch friendly static binary build
FROM golang:1.22-alpine AS build
WORKDIR /src
RUN apk add --no-cache git ca-certificates
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG TARGETOS=linux
ARG TARGETARCH=amd64
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags="-s -w" -o /out/lanvault ./cmd/lanvault

FROM alpine:3.20
RUN apk add --no-cache ca-certificates tini wget \
    && adduser -D -H -u 10001 lanvault \
    && mkdir -p /data \
    && chown lanvault:lanvault /data
COPY --from=build /out/lanvault /usr/local/bin/lanvault
COPY deploy/entrypoint.sh /entrypoint.sh
RUN chmod 755 /entrypoint.sh
USER lanvault
VOLUME ["/data"]
ENV LANVAULT_DIR=/data
ENV LANVAULT_LISTEN=0.0.0.0:8787
EXPOSE 8787
ENTRYPOINT ["/sbin/tini", "--", "/entrypoint.sh"]
