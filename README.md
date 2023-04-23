## Introduction

This is a password manager app, made with React + Nginx frontend, Rust backend, MySQL database and Redis cache.

This project is for learning purposes

## Local Deployment Using Docker Swarm 

**Start a docker swarm manager node** <br>
sudo docker swarm init

**Run given script to setup docker secrets, set google client ID for frontend and build service images** <br>
Linux: sudo ./scripts/local_setup.sh <br>
Windows: ./scripts/local_setup.ps1

**Deploy** <br>
sudo docker stack deploy -c docker-compose.local.yml password-manager

**Usage** <br>
Visit http://localhost:8080 to interact with password manager

## Creating 256-bit Base64 key for jwt_token:

**Linux:** <br>
`openssl rand -base64 32`

**Windows Powershell:** <br>

`$randomBytes = New-Object -TypeName Byte[] 32
$rngCryptoServiceProvider = New-Object -TypeName System.Security.Cryptography.RNGCryptoServiceProvider
$rngCryptoServiceProvider.GetBytes($randomBytes)
[Convert]::ToBase64String($randomBytes)`


## Possible Issues:

1. Data volume of mysql might cause issues if the mysql user and password was changed. At the risk of losing all your passwords, run `docker volume rm password-manager_my-datavolume` to remove the old volume. 