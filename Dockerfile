# A private Tor bridge that serves the reality transport.
#
#   docker run -d --name reality-bridge -p 443:443 -v reality-bridge:/var/lib/tor \
#     -e REALITY_DEST=www.microsoft.com:443 -e PUBLIC_IP=203.0.113.7 \
#     ghcr.io/hanzamas/reality-pt-bridge
#   docker logs reality-bridge    # prints the bridge line for your users

FROM golang:1.27 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath \
      -ldflags "-s -w -X github.com/hanzamas/reality-pt/internal/version.Version=${VERSION}" \
      -o /out/ ./cmd/reality-server ./cmd/reality-keygen

FROM debian:stable-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends tor \
 && rm -rf /var/lib/apt/lists/*
COPY --from=build /out/reality-server /out/reality-keygen /usr/local/bin/
COPY docker/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod 0755 /usr/local/bin/entrypoint.sh
USER debian-tor
VOLUME /var/lib/tor
EXPOSE 443
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
