$listening = netstat -an | Select-String ":3389.*LISTENING"
if (-not $listening) {
    Write-Warning "RDP port 3389 is not listening."
} else {
    Write-Host "RDP service is listening on port 3389."
}
