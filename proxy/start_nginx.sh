#!/bin/bash

declare -a unpw
unpw=($(aws secretsmanager get-secret-value --secret-id MLflow_Login | \
gawk 'match($4,/{"Username":"(\S+)","Password":"(\S+)"}/,ary) {print(ary[1],ary[2]);}'))

if [ ${#unpw[@]} -eq 2 ]; then
  # use htpasswd for basic authentication
  if htpasswd -c -b /etc/nginx/.htpasswd ${unpw[0]} ${unpw[1]}
  then
    nginx -g "daemon off;"
  else
    echo "ERROR: start_nginx.sh failed to create /etc/nginx/.htpasswd"
  fi
else
  echo "ERROR: start_nginx.sh failed to get credentials for MLflow_Login, return sz=${#unpw[@]}"
  exit 1
fi

exit 0