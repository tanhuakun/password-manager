#!/bin/bash

## REACT environment variables
declare -a react_arr=("GOOGLE_CLIENT_ID")


# Recreate config file
rm -rf /var/www/build/env-config.js
touch /var/www/build/env-config.js

echo "window._env_ = {" >> /var/www/build/env-config.js
for varname in "${react_arr[@]}"
do
  value=$(printf '%s\n' "${!varname}")
  echo "  $varname: \"$value\"," >> /var/www/build/env-config.js
done

echo "}" >> /var/www/build/env-config.js


## NGINX substitution
declare -a nginx_arr=("PASS_MAN_BACKEND_URL")

for varname in "${nginx_arr[@]}"
do
  value=$(printf '%s\n' "${!varname}")
  echo "s~<$varname>~${!varname}~g"
  sed -i "s~<$varname>~${!varname}~g" /etc/nginx/nginx.conf
done