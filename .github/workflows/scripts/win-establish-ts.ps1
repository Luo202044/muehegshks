# Bring up Tailscale and get IP + MagicDNS hostname

# 从 Secret 读取固定的主机名（短名称）
$fixedHostname = $env:RDP_HOSTNAME
if (-not $fixedHostname) {
    throw "RDP_HOSTNAME environment variable not set. Please set it in GitHub Secrets."
}

# 启动 Tailscale，使用固定主机名
& "$env:ProgramFiles\Tailscale\tailscale.exe" up --authkey=$env:TAILSCALE_AUTH_KEY --hostname=$fixedHostname

# 等待分配 IPv4 地址
$tsIP = $null
$retries = 0
while (-not $tsIP -and $retries -lt 10) {
    $tsIP = & "$env:ProgramFiles\Tailscale\tailscale.exe" ip -4
    Start-Sleep -Seconds 5
    $retries++
}
if (-not $tsIP) { throw "Tailscale IP not assigned." }

# 获取 Tailnet 域名（例如 your-tailnet.ts.net）
$tailnet = & "$env:ProgramFiles\Tailscale\tailscale.exe" status | Select-String -Pattern "tailnet" | ForEach-Object { ($_ -split ' ')[-1] }
$fullFQDN = "$fixedHostname.$tailnet"

# 写入环境变量
echo "TAILSCALE_IP=$tsIP" >> $env:GITHUB_ENV
echo "TAILSCALE_HOSTNAME=$fullFQDN" >> $env:GITHUB_ENV

Write-Host "Tailscale registered with hostname: $fixedHostname"
Write-Host "Full MagicDNS address: $fullFQDN"
