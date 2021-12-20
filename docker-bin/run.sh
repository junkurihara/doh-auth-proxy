#!/usr/bin/env bash

LOG_FILE=/var/log/doh-auth-proxy/doh-auth-proxy.log
CONFIG_FILE=/etc/doh-auth-proxy.toml
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

echo "Bootstrap dns: ${BOOTSTRAP_DNS_ADDR}:${BOOTSTRAP_DNS_PORT}"

if [ ${TOKEN_API} ] && [ ${USERNAME} ] && [ ${PASSWORD} ] && [ ${CLIENT_ID} ]; then
  CREDENTIAL_FILE_PATH=/etc/doh_auth
  cat > ${CREDENTIAL_FILE_PATH} << EOF
username=${USERNAME}
password=${PASSWORD}
client_id=${CLIENT_ID}
EOF
  echo "Authorization is enabled to the token API: ${TOKEN_API}"
  CREDENTIAL_FP="credential_file = \"${CREDENTIAL_FILE_PATH}\""
  CREDENTIAL_API="token_api = \"${TOKEN_API}\""
fi

RELAY_URLS=""
if [ ${ODOH_RELAY_URLS} ]; then
  echo "Running as ODoH mode"
  ODOH_RELAY_URL_STRING="odoh_relay_urls = ["
  ODOH_RELAY_URL_ARRAY=( `echo ${ODOH_RELAY_URLS} | tr -s ',' ' '`)
  for i in ${ODOH_RELAY_URL_ARRAY[@]}; do
    ODOH_RELAY_URL_STRING+="\"${i}\", "
    echo "(O)DoH relay url ${i}"
  done
  ODOH_RELAY_URL_STRING+="]"

  if [ -z ${ODOH_RELAY_RANDOMIZATION}]; then
    ODOH_RELAY_RANDOMIZATION="true"
  fi
  ODOH_RELAY_RAND_STRING="odoh_relay_randomization = ${ODOH_RELAY_RANDOMIZATION}"

  if [ ${MODOH_MID_RELAY_URLS} ]; then
    MODOH_MID_RELAY_URL_STRING="mid_relay_urls = ["
    MODOH_MID_RELAY_URL_ARRAY=( `echo ${MODOH_MID_RELAY_URLS} | tr -s ',' ' '`)
    if [ -z ${MODOH_MAX_MID_RELAYS} ]; then
      MODOH_MAX_MID_RELAYS=1
    fi
    echo "Multiple relay-based ODoH is enabled"
    for i in ${MODOH_MID_RELAY_URL_ARRAY[@]}; do
      MODOH_MID_RELAY_URL_STRING+="\"${i}\","
      echo "MODoH mid relay ${i}"
    done
    MODOH_MID_RELAY_URL_STRING+="]"
    MAX_MID_RELAYS_STRING+="max_mid_relays = ${MODOH_MAX_MID_RELAYS}"
  fi
else
  echo "Running as DoH mode"
fi

if [ ${TARGET_URLS} ]; then
  TARGET_URL_STRING="target_urls = ["
  TARGET_URL_ARRAY=( `echo ${TARGET_URLS} | tr -s ',' ' '`)
  for i in ${TARGET_URL_ARRAY[@]}; do
    TARGET_URL_STRING+="\"${i}\", "
    echo "(O)DoH target url ${i}"
  done
  TARGET_URL_STRING+="]"
fi

if [ -z ${TARGET_RANDOMIZATION} ]; then
  TARGET_RANDOMIZATION="true"
fi
TARGET_RAND_STRING="target_randomization = ${TARGET_RANDOMIZATION}"

cat > ${CONFIG_FILE} << EOF
listen_addresses = ["0.0.0.0:53"]
bootstrap_dns = "${BOOTSTRAP_DNS_ADDR}:${BOOTSTRAP_DNS_PORT}"
${TARGET_URL_STRING}
${TARGET_RAND_STRING}

[authentication]
${CREDENTIAL_API}
${CREDENTIAL_FP}

[anonymization]
${ODOH_RELAY_URL_STRING}
${ODOH_RELAY_RAND_STRING}
${MODOH_MID_RELAY_URL_STRING}
${MAX_MID_RELAYS_STRING}
EOF

RUST_LOG=${LOG_LEVEL} /opt/doh-auth-proxy/sbin/doh-auth-proxy --config ${CONFIG_FILE}
