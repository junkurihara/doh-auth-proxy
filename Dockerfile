FROM ubuntu:23.04 AS base

SHELL ["/bin/sh", "-x", "-c"]
ENV SERIAL 2

########################################
FROM base as builder

ENV CFLAGS=-Ofast
ENV BUILD_DEPS curl make ca-certificates build-essential pkg-config libssl-dev

WORKDIR /tmp

COPY . /tmp/

ENV RUSTFLAGS "-C link-arg=-s"

RUN update-ca-certificates 2> /dev/null || true

RUN apt-get update && apt-get install -qy --no-install-recommends $BUILD_DEPS && \
    curl -sSf https://sh.rustup.rs | bash -s -- -y --default-toolchain stable && \
    export PATH="$HOME/.cargo/bin:$PATH" && \
    echo "Building DoH Auth Proxy from source" && \
    cargo build --release --no-default-features && \
    mkdir -p /opt/doh-auth-proxy/sbin && \
    strip --strip-all /tmp/target/release/doh-auth-proxy

########################################
FROM base AS runner
LABEL maintainer="Jun Kurihara"

ENV RUNTIME_DEPS logrotate ca-certificates

RUN apt-get update && \
    apt-get install -qy --no-install-recommends $RUNTIME_DEPS && \
    apt-get -qy clean && \
    rm -fr /tmp/* /var/tmp/* /var/cache/apt/* /var/lib/apt/lists/* /var/log/apt/* /var/log/*.log &&\
    mkdir -p /opt/doh-auth-proxy/sbin &&\
    mkdir -p /var/log/doh-auth-proxy && \
    touch /var/log/doh-auth-proxy.log

COPY --from=builder /tmp/target/release/doh-auth-proxy /opt/doh-auth-proxy/sbin/doh-auth-proxy
COPY docker-bin/run.sh /
COPY docker-bin/entrypoint.sh /

RUN chmod 755 /run.sh && \
    chmod 755 /entrypoint.sh

EXPOSE 53/udp 53/tcp

CMD ["/entrypoint.sh"]

ENTRYPOINT ["/entrypoint.sh"]
