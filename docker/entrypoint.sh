#!/usr/bin/env bash
LOG_FILE=/var/log/doh-auth-proxy/doh-auth-proxy.log

/run.sh 2>&1 | tee $LOG_FILE
