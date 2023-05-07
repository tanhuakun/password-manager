#!/bin/bash

## For ease of convenience passing setting ENV and calling docker setup in one go.
## Otherwise may need to export env via sudo -E or something

if [ -z "$1" ]; then
  echo "WARNING: Argument 1 GOOGLE_CLIENT_ID argument is not set!"
  exit 1
fi

GOOGLE_CLIENT_ID=$1
export GOOGLE_CLIENT_ID=$GOOGLE_CLIENT_ID

docker stack deploy -c docker-compose.local.yml password-manager