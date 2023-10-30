# Find-LocalAdminAccess
Check the Domain for local Admin Access via SMB, WMI, or PSRemoting. 

Run as Current User, or provide credentials (WMI and PSRemoting only)

Optionally, provide a command to run on targets where we are Admin

### Load script:

```
iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/Leo4j/Find-LocalAdminAccess/main/Find-LocalAdminAccess.ps1')
```

### Usage (SMB):
```
Find-LocalAdminAccess -Method SMB
```
```
Find-LocalAdminAccess -Method SMB -Targets "Workstation01.ferrari.local,DC01.ferrari.local"
```
```
Find-LocalAdminAccess -Method SMB -Command "whoami /all" # Will run a command on targets where we are admin
```
```
Find-LocalAdminAccess -Method SMB -Command "whoami /all" -NoOutput # Will run a command on targets where we are admin and won't wait for output
```
```
Find-LocalAdminAccess -Method SMB -Targets "Workstation01.ferrari.local,DC01.ferrari.local" -Command "whoami /all"
```

### Usage (WMI):
```
Find-LocalAdminAccess -Method WMI
```
```
Find-LocalAdminAccess -Method WMI -Targets "Workstation01.ferrari.local,DC01.ferrari.local"
```
```
Find-LocalAdminAccess -Method WMI -UserName "ferrari\Administrator" -Password "P@ssw0rd!"
```
```
Find-LocalAdminAccess -Method WMI -Command "whoami /all" # Will run a command on targets where we are admin
```
```
Find-LocalAdminAccess -Method WMI -Command "whoami /all" -NoOutput # Will run a command on targets where we are admin and won't wait for output
```
```
Find-LocalAdminAccess -Method WMI -Targets "Workstation01.ferrari.local,DC01.ferrari.local" -UserName "ferrari\Administrator" -Password "P@ssw0rd!" -Command "whoami /all"
```

### Usage (PSRemoting):
```
Find-LocalAdminAccess -Method PSRemoting
```
```
Find-LocalAdminAccess -Method PSRemoting -Targets c:\Users\Public\Documents\Targets.txt
```
```
Find-LocalAdminAccess -Method PSRemoting -UserName "ferrari\Administrator" -Password "P@ssw0rd!"
```
```
Find-LocalAdminAccess -Method PSRemoting -Command "whoami /all" # Will run a command on targets where we are admin
```
```
Find-LocalAdminAccess -Method PSRemoting -Command "whoami /all" -NoOutput # Will run a command on targets where we are admin and won't wait for output
```
```
Find-LocalAdminAccess -Method PSRemoting -Targets c:\Users\Public\Documents\Targets.txt -UserName "ferrari\Administrator" -Password "P@ssw0rd!" -Command "whoami /all"
```

![image](https://github.com/Leo4j/Find-LocalAdminAccess/assets/61951374/16e6e0f7-2d44-4ebf-985a-ad2b38d43e48)


![image](https://github.com/Leo4j/Find-LocalAdminAccess/assets/61951374/01b5076b-8615-4b16-8b6d-79f19010682d)
