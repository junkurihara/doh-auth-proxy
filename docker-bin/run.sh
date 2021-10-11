#!/usr/bin/env bash

LOG_FILE=/var/log/doh-auth-proxy/doh-auth-proxy.log
LOG_SIZE=10M
LOG_NUM=10

# logrotate
if [ $LOGROTATE_NUM ]; then
  LOG_NUM=${LOGROTATE_NUM}
fi
if [ $LOGROTATE_SIZE ]; then
  LOG_SIZE=${LOGROTATE_SIZE}
fi

cat > /etc/logrotate.conf << EOF
# see "man logrotate" for details
# rotate log files weekly
weekly
# use the adm group by default, since this is the owning group
# of /var/log/syslog.
su root adm
# keep 4 weeks worth of backlogs
rotate 4
# create new (empty) log files after rotating old ones
create
# use date as a suffix of the rotated file
#dateext
# uncomment this if you want your log files compressed
#compress
# packages drop log rotation information into this directory
include /etc/logrotate.d
# system-specific logs may be also be configured here.
EOF

cat > /etc/logrotate.d/doh-auth-proxy << EOF
${LOG_FILE} {
    dateext
    daily
    missingok
    rotate ${LOG_NUM}
    notifempty
    compress
    delaycompress
    dateformat -%Y-%m-%d-%s
    size ${LOG_SIZE}
    copytruncate
}
EOF

cp -p /etc/cron.daily/logrotate /etc/cron.hourly/
service cron start

echo "Start DoH Auth Proxy"

# read custom configuration
source /opt/doh-auth-proxy/etc/.env

# set bootstrap dns
if [ -z "${BOOTSTRAP_DNS_ADDR}" ]; then
  BOOTSTRAP_DNS_ADDR=8.8.8.8
fi
if [ -z "${BOOTSTRAP_DNS_PORT}" ]; then
  BOOTSTRAP_DNS_PORT=53
fi

# debug level logging
LOG_LEVEL=info
if [ ${DEBUG} ]; then
  echo "Logging in debug mode"
  LOG_LEVEL=debug
fi

echo "bootstrap dns: ${BOOTSTRAP_DNS_ADDR}:${BOOTSTRAP_DNS_PORT}"

if [ ${ODOH_RELAY_URL} ]; then
  echo "Running as ODoH mode"
  echo "ODoH target ${TARGET_URL}"
  echo "ODoH relay  ${ODOH_RELAY_URL}"
  RUST_LOG=${LOG_LEVEL} /opt/doh-auth-proxy/sbin/doh-auth-proxy \
      --listen-address=0.0.0.0:53 \
      --target-url=${TARGET_URL} \
      --relay-url=${ODOH_RELAY_URL} \
      --bootstrap-dns=${BOOTSTRAP_DNS_ADDR}:${BOOTSTRAP_DNS_PORT}
else
  echo "Running as DoH mode"
  echo "DoH target ${TARGET_URL}"
  RUST_LOG=${LOG_LEVEL} /opt/doh-auth-proxy/sbin/doh-auth-proxy \
      --listen-address=0.0.0.0:53 \
      --target-url=${TARGET_URL} \
      --bootstrap-dns=${BOOTSTRAP_DNS_ADDR}:${BOOTSTRAP_DNS_PORT}
fi
