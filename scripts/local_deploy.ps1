param(
  [string]$GOOGLE_CLIENT_ID
)

if ([string]::IsNullOrWhiteSpace($GOOGLE_CLIENT_ID)) {
  Write-Warning "Argument 1 GOOGLE_CLIENT_ID argument is not set!"
  exit 1
}

$env:GOOGLE_CLIENT_ID = $GOOGLE_CLIENT_ID

docker stack deploy -c docker-compose.local.yml password-manager