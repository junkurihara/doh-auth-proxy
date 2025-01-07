#!/usr/bin/env bash
CONFIG_FILE=/modoh/doh-auth-proxy.toml
DEFAULT_LOG_LEVEL="info"
DEFAULT_TARGET_URLS="https://dns.google/dns-query"
DEFAULT_BOOTSTRAP_DNS="8.8.8.8"
QUERY_LOG_FILE=/modoh/log/query.log

# bootstrap DNS
echo "Bootstrap DNS: ${BOOTSTRAP_DNS:-${DEFAULT_BOOTSTRAP_DNS}}"

##########################
# authentication and authorization
if [ ${TOKEN_API} ] && [ ${USERNAME} ] && [ ${PASSWORD} ] && [ ${CLIENT_ID} ]; then
  CREDENTIAL_FILE_PATH=/modoh/doh_auth_cred
  cat > ${CREDENTIAL_FILE_PATH} << EOF
username=${USERNAME}
password=${PASSWORD}
client_id=${CLIENT_ID}
EOF
  echo "Authorization is enabled to the token API: ${TOKEN_API}"
  CREDENTIAL_FP="credential_file = \"${CREDENTIAL_FILE_PATH}\""
  CREDENTIAL_API="token_api = \"${TOKEN_API}\""
  USE_ANONYMOUS_TOKEN_STR="use_anonymous_token = ${USE_ANONYMOUS_TOKEN:-false}"
fi

##########################
# relay configuration
RELAY_URLS=""
if [ ${ODOH_RELAY_URLS} ]; then
  ##########################
  # ODoH and MODoH case
  echo "Running as ODoH mode"
  ODOH_RELAY_URL_STRING="odoh_relay_urls = ["
  ODOH_RELAY_URL_ARRAY=( `echo ${ODOH_RELAY_URLS} | tr -s ',' ' '`)
  for i in ${ODOH_RELAY_URL_ARRAY[@]}; do
    ODOH_RELAY_URL_STRING+="\"${i}\", "
    echo "(O)DoH relay url ${i}"
  done
  ODOH_RELAY_URL_STRING+="]"

  # relay randomization
  ODOH_RELAY_RAND_STRING="odoh_relay_randomization = ${ODOH_RELAY_RANDOMIZATION:-true}"


  # handling multiple relay case for MODoH
  if [ ${MODOH_MID_RELAY_URLS} ]; then
    MODOH_MID_RELAY_URL_STRING="mid_relay_urls = ["
    MODOH_MID_RELAY_URL_ARRAY=( `echo ${MODOH_MID_RELAY_URLS} | tr -s ',' ' '`)
    echo "Multiple relay-based ODoH is enabled"
    for i in ${MODOH_MID_RELAY_URL_ARRAY[@]}; do
      MODOH_MID_RELAY_URL_STRING+="\"${i}\","
      echo "MODoH mid relay ${i}"
    done
    MODOH_MID_RELAY_URL_STRING+="]"
    MAX_MID_RELAYS_STRING+="max_mid_relays = ${MODOH_MAX_MID_RELAYS:-1}"
  fi
else
  ##########################
  # simple DoH case
  echo "Running as DoH mode"
fi

##########################
# target resolver configuration
TARGET_URL_STRING="target_urls = ["
TARGET_URL_ARRAY=( `echo ${TARGET_URLS:-${DEFAULT_TARGET_URLS}} | tr -s ',' ' '`)
for i in ${TARGET_URL_ARRAY[@]}; do
  TARGET_URL_STRING+="\"${i}\", "
  echo "(O)DoH target url ${i}"
done
TARGET_URL_STRING+="]"


# target randomization
TARGET_RAND_STRING="target_randomization = ${TARGET_RANDOMIZATION:-true}"

##########################
# plugin configuration
# blocking
if [ ${DOMAINS_BLOCKED_FILE} ]; then
  PLUGIN_BLOCK_STRING="domains_blocked_file=\"/modoh/plugins/${DOMAINS_BLOCKED_FILE}\""
fi

# overriding
if [ ${DOMAINS_OVERRIDDEN_FILE} ]; then
  PLUGIN_OVERRIDE_STRING="domains_overridden_file=\"/modoh/plugins/${DOMAINS_OVERRIDDEN_FILE}\""
fi

##########################
# export as a config toml file
cat > ${CONFIG_FILE} << EOF
listen_addresses = ["0.0.0.0:53", "[::]:53"]
bootstrap_dns = ["${BOOTSTRAP_DNS:-${DEFAULT_BOOTSTRAP_DNS}}"]
${TARGET_URL_STRING}
${TARGET_RAND_STRING}

[authentication]
${CREDENTIAL_API}
${CREDENTIAL_FP}
${USE_ANONYMOUS_TOKEN_STR}

[anonymization]
${ODOH_RELAY_URL_STRING}
${ODOH_RELAY_RAND_STRING}
${MODOH_MID_RELAY_URL_STRING}
${MAX_MID_RELAYS_STRING}

[plugins]
${PLUGIN_BLOCK_STRING}
${PLUGIN_OVERRIDE_STRING}
EOF

echo "configured toml file:"
echo "---------------------"
cat ${CONFIG_FILE}
echo "---------------------"


# query-response logging
QUERY_LOG_ARG=""
if [ -z $ENABLE_QUERY_LOG ]; then
  ENABLE_QUERY_LOG=false
fi
if [ -z $ENABLE_JSON_QUERY_LOG ]; then
  ENABLE_JSON_QUERY_LOG=false
fi
if $ENABLE_JSON_QUERY_LOG; then
  echo "Query-Response logging in JSON format enabled with file ${QUERY_LOG_FILE}"
  QUERY_LOG_ARG="--query-log ${QUERY_LOG_FILE} --json-query-log"
elif $ENABLE_QUERY_LOG ; then
  echo "Query-Response logging enabled with file ${QUERY_LOG_FILE}"
  QUERY_LOG_ARG="--query-log ${QUERY_LOG_FILE}"
fi

##########################
# start
echo "Start with log level ${LOG_LEVEL:-${DEFAULT_LOG_LEVEL}}"
RUST_LOG=${LOG_LEVEL:-${DEFAULT_LOG_LEVEL}} /modoh/bin/doh-auth-proxy --config ${CONFIG_FILE} ${QUERY_LOG_ARG}
