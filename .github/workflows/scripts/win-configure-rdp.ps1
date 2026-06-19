Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 0
New-NetFirewallRule -DisplayName "RDP" -Direction Inbound -LocalPort 3389 -Protocol TCP -Action Allow
