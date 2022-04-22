FROM ubuntu:22.04
LABEL maintainer="Jun Kurihara"

SHELL ["/bin/sh", "-x", "-c"]
ENV SERIAL 2

ENV CFLAGS=-Ofast
ENV BUILD_DEPS   curl make build-essential libevent-dev libexpat1-dev autoconf file libssl-dev byacc pkg-config
ENV RUNTIME_DEPS bash util-linux coreutils findutils grep libssl3 ldnsutils libevent-2.1 expat ca-certificates jed logrotate

RUN apt-get update; apt-get -qy dist-upgrade; apt-get -qy clean && \
    apt-get install -qy --no-install-recommends $RUNTIME_DEPS && \
    rm -fr /tmp/* /var/tmp/* /var/cache/apt/* /var/lib/apt/lists/* /var/log/apt/* /var/log/*.log

RUN update-ca-certificates 2> /dev/null || true

WORKDIR /tmp

COPY . /tmp/

ENV RUSTFLAGS "-C link-arg=-s"

RUN apt-get update && apt-get install -qy --no-install-recommends $BUILD_DEPS && \
    curl -sSf https://sh.rustup.rs | bash -s -- -y --default-toolchain stable && \
    export PATH="$HOME/.cargo/bin:$PATH" && \
    echo "Building DoH Auth Proxy from source" && \
    cargo build --release --no-default-features && \
    mkdir -p /opt/doh-auth-proxy/sbin && \
    mv /tmp/target/release/doh-auth-proxy /opt/doh-auth-proxy/sbin/ && \
    strip --strip-all /opt/doh-auth-proxy/sbin/doh-auth-proxy && \
    apt-get -qy purge $BUILD_DEPS && apt-get -qy autoremove && \
    rm -fr ~/.cargo ~/.rustup && \
    rm -fr /tmp/* /var/tmp/* /var/cache/apt/* /var/lib/apt/lists/* /var/log/apt/* /var/log/*.log

COPY docker-bin/run.sh /
COPY docker-bin/entrypoint.sh /

RUN chmod 755 /run.sh && \
    chmod 755 /entrypoint.sh

EXPOSE 53/udp 53/tcp

CMD ["/entrypoint.sh"]

ENTRYPOINT ["/entrypoint.sh"]
