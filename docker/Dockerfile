FROM golang:alpine AS entrypoint

ENV CGO_ENABLED=0 GOOS=linux GOARCH=amd64

COPY main.go /go/src/github.com/9seconds/docker-shadow/main.go

RUN set -ex \
  && apk add --update \
    git \
  && cd /go/src/github.com/9seconds/docker-shadow \
  && go build -a -installsuffix cgo -ldflags="-s -w" -o /entry

# -----------------------------------------------------------------------------


FROM golang:alpine AS v2ray-plugin

ENV CGO_ENABLED=0 GOOS=linux GOARCH=amd64

RUN set -ex \
  && apk add --update \
    git \
  && git clone --single-branch --depth 1 \
    https://github.com/shadowsocks/v2ray-plugin.git \
  && cd v2ray-plugin \
  && go build -a -installsuffix cgo -ldflags="-s -w" -o /plugin


# -----------------------------------------------------------------------------

FROM shadowsocks/shadowsocks-libev AS runit-docker

USER root

RUN set -ex \
  && apk --update --no-cache add \
    gcc \
    git \
    make \
    musl-dev \
  && git clone --depth 1 --single-branch https://github.com/pixers/runit-docker /tmp/runit-docker \
  && cd /tmp/runit-docker \
  && make


# -----------------------------------------------------------------------------

FROM shadowsocks/shadowsocks-libev

ENTRYPOINT ["/entry"]
ENV LD_PRELOAD=/lib/runit-docker.so
EXPOSE 443/tcp 443/udp
USER root

RUN set -ex \
  && apk add --update --no-cache runit rng-tools

COPY --from=entrypoint /entry /entry
COPY --from=v2ray-plugin /plugin /usr/bin/v2ray-plugin
COPY --from=runit-docker /tmp/runit-docker/runit-docker.so /lib/runit-docker.so
COPY show /usr/bin/show
COPY runit/shadowsocks/run /etc/service/shadowsocks/run
