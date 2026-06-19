# Create RDP user with password from GitHub Secret
$password = $env:RDP_PASSWORD
if (-not $password) {
    throw "RDP_PASSWORD environment variable not set. Please set it in GitHub Secrets."
}

# 密码强度校验（可选）
if ($password.Length -lt 8) {
    throw "Password must be at least 8 characters long."
}
if (($password -match "[a-z]") -and ($password -match "[A-Z]") -and ($password -match "[0-9]") -and ($password -match "[^a-zA-Z0-9]")) {
    Write-Host "Password meets complexity requirements."
} else {
    Write-Host "Warning: Password may not meet complexity rules. Continue anyway..."
}

$securePass = ConvertTo-SecureString $password -AsPlainText -Force

# 创建本地用户 vum，密码永不过期
New-LocalUser -Name "vum" -Password $securePass -AccountNeverExpires

# 加入管理员组（仅需要远程桌面可只加入 Remote Desktop Users）
Add-LocalGroupMember -Group "Administrators" -Member "vum"
Add-LocalGroupMember -Group "Remote Desktop Users" -Member "vum"

# 验证用户创建成功
if (-not (Get-LocalUser -Name "vum")) {
    throw "User creation failed"
}

# 将用户名写入环境变量（供后续步骤使用，密码不写入）
echo "RDP_USER=vum" >> $env:GITHUB_ENV
Write-Host "User 'vum' created successfully."
