# Find-LocalAdminAccess
Check the Domain for local Admin Access via SMB, WMI, or PSRemoting

Usage:

```
iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/Leo4j/Find-LocalAdminAccess/main/Find-LocalAdminACcess.ps1')
```
```
Find-LocalAdminAccess -Method SMB
```
```
Find-LocalAdminAccess -Method WMI
```
```
Find-LocalAdminAccess -Method PSRemoting
```
```
Find-LocalAdminAccess -Method WMI -ComputerNames "Workstation01.ferrari.local,DC01.ferrari.local"
```
```
Find-LocalAdminAccess -Method PSRemoting -ComputerFile c:\Users\Public\Documents\Targets.txt
```
```
Find-LocalAdminAccess -Method WMI -UserName "ferrari\Administrator" -Password "P@ssw0rd!"
```
```
Find-LocalAdminAccess -Method PSRemoting -UserName "ferrari\Administrator" -Password "P@ssw0rd!"
```

![image](https://github.com/Leo4j/Find-LocalAdminAccess/assets/61951374/16e6e0f7-2d44-4ebf-985a-ad2b38d43e48)


![image](https://github.com/Leo4j/Find-LocalAdminAccess/assets/61951374/01b5076b-8615-4b16-8b6d-79f19010682d)
