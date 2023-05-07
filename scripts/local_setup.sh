#!/bin/bash

# check if secret exists, if it doesn't, read new secret value from user.
check_or_get_secret_from_user() {
  secret_name=$1
  prompt=$2
  is_password=$3
  if [ "$(docker secret inspect $secret_name --format {{.Spec.Name}} 2> /dev/null)" != $secret_name ] ; then
    echo $prompt

    if $is_password; then
      while true
      do
        read -s value1

        echo "Enter it again:"
        read -s value2

        if [ "$value1" = "$value2" ]
        then
          secret=$value1
          break
        else
          echo "Values do not match, please try again."
        fi
      done
    else
      read secret
    fi
    retval=$secret
  else
    echo $secret_name exists in docker secrets, skipping...
    retval=""
  fi
}

# if secret_val is non_empty, set it into docker!
set_secret_if_non_empty() {
  secret_name=$1
  secret_val=$2
  if [ -n "${secret_val}" ]; then
    printf $secret_val | docker secret create $secret_name -
  fi
}

check_or_get_secret_from_user db_user "Enter a username for the mysql database" false
db_user=$retval
check_or_get_secret_from_user db_password "Enter a password for the mysql database" true
db_password=$retval

while true
do
  check_or_get_secret_from_user jwt_secret "Enter a 32 bytes secret key in base64 format for jsonwebtoken signing, it can be generated like this: openssl rand -base64 32" true
  jwt_secret=$retval
  if echo $jwt_secret | base64 -d 2>&1 >/dev/null | grep "invalid input"; then
    echo "jwt secret is not in base64 format, please try again!"
  else
    break
  fi
done

if ([ -z $db_user ] || [ -z $db_password ]) && [ "$(docker secret inspect db_url --format {{.Spec.Name}} 2> /dev/null)" != "db_url" ]; then
  echo "db_user and/or db_password has been set, but db_url has not."
  echo "Remove db_user and db_password secrets manually and try again!"
  exit 1
fi

if [ "$(docker secret inspect db_url --format {{.Spec.Name}} 2> /dev/null)" != "db_url" ]; then
  set_secret_if_non_empty db_url mysql://$db_user:$db_password@mysql/passwordmanager
fi

set_secret_if_non_empty db_user $db_user
set_secret_if_non_empty db_password $db_password
set_secret_if_non_empty jwt_secret $jwt_secret

echo "========================="
echo "Secrets set successfully!"

docker compose -f docker-compose.local.yml build