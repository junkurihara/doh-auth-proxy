#!/usr/bin/env sh
LOG_DIR=/modoh/log
LOG_FILE=${LOG_DIR}/doh-auth-proxy.log
LOG_SIZE=10M
LOG_NUM=10

LOGGING=${LOG_TO_FILE:-false}
USER=${HOST_USER:-doh-auth-proxy}
USER_ID=${HOST_UID:-900}
GROUP_ID=${HOST_GID:-900}

#######################################
# Setup logrotate
function setup_logrotate () {
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
# su root adm
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

  cat > /etc/logrotate.d/doh-auth-proxy.conf << EOF
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
    su ${USER} ${USER}
}
EOF
}

#######################################
function setup_ubuntu () {
  # Check the existence of the user, if not exist, create it.
  if [ ! $(id ${USER}) ]; then
    echo "doh-auth-proxy: Create user ${USER} with ${USER_ID}:${GROUP_ID}"
    groupadd -g ${GROUP_ID} ${USER}
    useradd -u ${USER_ID} -g ${GROUP_ID} ${USER}
  fi

  # for crontab when logging
  if "${LOGGING}"; then
    # Set up logrotate
    setup_logrotate

    # Setup cron
    mkdir -p /etc/cron.15min/
    cp -p /etc/cron.daily/logrotate /etc/cron.15min/
    echo "*/15 * * * * root cd / && run-parts --report /etc/cron.15min" >> /etc/crontab
    service cron start
  fi
}

#######################################

if [ $(whoami) != "root" -o $(id -u) -ne 0 -a $(id -g) -ne 0 ]; then
  echo "Do not execute 'docker run' or 'docker-compose up' with a specific user through '-u'."
  echo "If you want to run 'doh-auth-proxy' with a specific user, use HOST_USER, HOST_UID and HOST_GID environment variables."
  exit 1
fi

# set up user and cron for ubuntu base image
setup_ubuntu

# Check the given user and its uid:gid
if [ $(id -u ${USER}) -ne ${USER_ID} -a $(id -g ${USER}) -ne ${GROUP_ID} ]; then
  echo "${USER} exists or was previously created. However, its uid and gid are inconsistent. Please recreate your container."
  exit 1
fi

# Change permission according to the given user
chown -R ${USER_ID}:${USER_ID} /modoh

# run doh-auth-proxy
echo "Start with user: ${USER} (${USER_ID}:${GROUP_ID})"
if "${LOGGING}"; then
  echo "Start with writing log file"
  gosu ${USER} sh -c "/modoh/run.sh 2>&1 | tee ${LOG_FILE}"
else
  echo "Start without writing log file"
  gosu ${USER} sh -c "/modoh/run.sh 2>&1"
fi
