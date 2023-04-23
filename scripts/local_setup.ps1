function check_or_get_secret_from_user {
    param($secret_name, $prompt, $is_password)
    if (-not (docker secret inspect $secret_name --format {{.Spec.Name}} 2> $null)) {
        Write-Host $prompt
        if ($is_password) {
            while ($true) {
                $value1 = Read-Host -AsSecureString
                Write-Host "Enter it again:"
                $value2 = Read-Host -AsSecureString
                if ($value1 -ceq $value2) {
                    $secret = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($value1))
                    break
                } else {
                    Write-Host "Values do not match, please try again."
                }
            }
        } else {
            $secret = Read-Host
        }
        $retval = $secret
    } else {
        Write-Host "$secret_name exists in docker secrets, skipping..."
        $retval = ""
    }
    return $retval
}

function set_secret_if_non_empty {
    param($secret_name, $secret_val)
    if (-not [string]::IsNullOrWhiteSpace($secret_val)) {
        $secret_val | docker secret create $secret_name -
    }
}

$db_user = check_or_get_secret_from_user "db_user" "Enter a username for the mysql database" $false
$db_password = check_or_get_secret_from_user "db_password" "Enter a password for the mysql database" $true

while ($true) {
    $jwt_secret = check_or_get_secret_from_user "jwt_secret" "Enter a 32 bytes secret key in base64 format for jsonwebtoken signing, it can be generated like this: openssl rand -base64 32" $true
    if ($jwt_secret | [Convert]::TryFromBase64String($null)) {
        break
    } else {
        Write-Host "jwt secret is not in base64 format, please try again!"
    }
}

Write-Host "Enter your google client id for sign in with google in React frontend!"
$env:GOOGLE_CLIENT_ID = Read-Host

if ([string]::IsNullOrWhiteSpace($db_user) -or [string]::IsNullOrWhiteSpace($db_password) -and (docker secret inspect db_url --format {{.Spec.Name}} 2> $null) -ne "db_url") {
    Write-Host "db_user and/or db_password has been set, but db_url has not."
    Write-Host "Remove db_user and db_password secrets manually and try again!"
    exit 1
}

if ((docker secret inspect db_url --format {{.Spec.Name}} 2> $null) -ne "db_url") {
    set_secret_if_non_empty "db_url" "mysql://$db_user:$db_password@mysql/passwordmanager"
}

set_secret_if_non_empty "db_user" $db_user
set_secret_if_non_empty "db_password" $db_password
set_secret_if_non_empty "jwt_secret" $jwt_secret

Write-Host "========================="
Write-Host "Secrets set successfully!"

docker-compose -f docker-compose.local.yml build