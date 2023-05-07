## Introduction

This is a password manager app, made with React + Nginx frontend, Rust backend, MySQL database and Redis cache.

This project is for learning purposes

## Local Deployment Using Docker Swarm 

### Commands:

**Prerequisites** <br>
* Clone this repository
* Ensure that docker is installed, use sudo infront of Linux commands if required.

**Start a docker swarm manager node** <br>
`docker swarm init`

**Run given script to setup docker secrets, set google client ID for frontend and build service images** <br>
Linux: `./scripts/local_setup.sh` <br>
Windows: `.\scripts\local_setup.ps1`

*Note: Methods for generating a base64 key for jwt token can be found in the next section.*

**Deploy with google client ID argument** <br>
Linux: `./scripts/local_deploy.sh <GOOGLE_CLIENT_ID>` <br>
Windows: `.\scripts\local_deploy.ps1 <GOOGLE_CLIENT_ID>`

*Note: Google Client ID is used for signing in with Google, and looks something like this XXXXX-XXXXXXXXXXXXXX.apps.googleusercontent.com. Set it to a random string (for example 'aaaa') if you do not want to use the sign in with Google feature.*

**Usage** <br>
Visit http://localhost:8080 to interact with password manager

### Creating 256-bit Base64 key for jwt_token:

**Linux:** <br>
```
openssl rand -base64 32
```

**Windows Powershell:** <br>

```
$randomBytes = New-Object -TypeName Byte[] 32

$rngCryptoServiceProvider = New-Object -TypeName System.Security.Cryptography.RNGCryptoServiceProvider

$rngCryptoServiceProvider.GetBytes($randomBytes)

[Convert]::ToBase64String($randomBytes)
```


### Possible Issues:

1. Data volume of mysql might cause issues if the mysql user and password was changed. At the risk of losing all your passwords, run `docker volume rm password-manager_my-datavolume` to remove the old volume. 