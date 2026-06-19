$password = $env:RDP_PASSWORD
if (-not $password) {
    throw "RDP_PASSWORD environment variable not set. Please set it in GitHub Secrets."
}
$securePass = ConvertTo-SecureString $password -AsPlainText -Force
New-LocalUser -Name "vum" -Password $securePass -AccountNeverExpires
Add-LocalGroupMember -Group "Administrators" -Member "vum"
Add-LocalGroupMember -Group "Remote Desktop Users" -Member "vum"
if (-not (Get-LocalUser -Name "vum")) {
    throw "User creation failed"
}
echo "RDP_USER=vum" >> $env:GITHUB_ENV
Write-Host "User 'vum' created successfully."
