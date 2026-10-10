FROM golang:1.26-bookworm AS builder
RUN apt-get update && apt-get install -y --no-install-recommends libsqlite3-dev ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY go.mod ./
COPY *.go openapi.json docs.html ./
RUN CGO_ENABLED=1 go build -trimpath -ldflags='-s -w' -o /bridge .

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates libsqlite3-0 && rm -rf /var/lib/apt/lists/* && groupadd -g 10001 bridge && useradd -u 10001 -g bridge -M bridge && mkdir /data && chown 10001:10001 /data
COPY --from=builder /bridge /usr/local/bin/bridge
USER 10001:10001
WORKDIR /data
EXPOSE 8080
VOLUME /data
ENTRYPOINT ["/usr/local/bin/bridge"]
