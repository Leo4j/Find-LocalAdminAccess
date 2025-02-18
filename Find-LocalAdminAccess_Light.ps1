function Find-LocalAdminAccess {
	
	<#
	.SYNOPSIS
	Find-LocalAdminAccess Author: Rob LP (@L3o4j)
	https://github.com/Leo4j/Find-LocalAdminAccess
	
	Dependencies: Token-Impersonation Author: Rob LP (@L3o4j)
	https://github.com/Leo4j/Token-Impersonation

 	.DESCRIPTION
	Check the Domain for local Admin Access
	
	.PARAMETER Targets
	Specify a comma-separated list of targets, or the path to a file containing targets (one per line)
	
	.PARAMETER Domain
	Specify the Domain to enumerate machine targets for

 	.PARAMETER DomainController
	Specify the target DomainController
	
	.PARAMETER Local
	Check for access as the Local Built-In Administrator
	
	.PARAMETER Username
	Specify the Username to check access as
	
	.PARAMETER Password
	Specify the Password for the Username you want to check access as
	
	.PARAMETER UserDomain
	Specify the Domain for the Username you want to check access as
	
	.EXAMPLE
	Find-LocalAdminAccess
	Find-LocalAdminAccess -Local -Username "Administrator" -Password "P@ssw0rd!"
	Find-LocalAdminAccess -Username "Administrator" -Password "P@ssw0rd!" -UserDomain ferrari.local
	Find-LocalAdminAccess -Domain ferrari.local -DomainController DC01.ferrari.local -Targets "Workstation01.ferrari.local,DC01.ferrari.local"
 	#>
	
	param (
		[string]$Targets,
		[string]$Domain,
		[string]$DomainController,
		[string]$Username,
		[string]$Password,
		[string]$UserDomain,
		[switch]$Local,
		[switch]$ShowErrors
	)
	
	if (!$ShowErrors) {
		$ErrorActionPreference = "SilentlyContinue"
		$WarningPreference = "SilentlyContinue"
	}
	
	if($Local -and (-not $Username -OR -not $Password)){
		Write-Output ""
		Write-Output "[-] Please provide Username and Password for the Local User Account"
		Write-Output ""
		return
	}
	
	elseif (-not $Local -and (($Username -or $Password -or $UserDomain) -and (-not $Username -or -not $Password -or -not $UserDomain))) {
		Write-Output ""
		Write-Output "[-] Please provide Username, Password, and UserDomain"
		Write-Output ""
		return
	}
	
	elseif ($Local -and $Username -and $Password -and $UserDomain){
		Write-Output ""
		Write-Output "[-] You cannot provide the Local switch together with UserDomain"
		Write-Output ""
		return
	}
	
	if ($Targets) {
		$TestPath = Test-Path $Targets
		
		if ($TestPath) {
			$Computers = Get-Content -Path $Targets
			$Computers = $Computers | Sort-Object -Unique
		} else {
			$Computers = $Targets -split ","
			$Computers = $Computers | Sort-Object -Unique
		}
	} else {
		$Computers = @()
		
		if ($Domain){
			Write-Output ""
			Write-Output "[+] Scope: $Domain"
			Write-Output ""
			Write-Output "[+] Enumerating Targets..."
			Write-Output ""
			$objSearcher = New-Object System.DirectoryServices.DirectorySearcher
			if ($DomainController) {
				$TempDomainName = "DC=" + ($Domain.Split(".") -join ",DC=")
				$ldapPath = "LDAP://$DomainController/$TempDomainName"
				$objSearcher.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry($ldapPath)
			} else {
				$objSearcher.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$Domain")
			}
			$objSearcher.Filter = "(&(sAMAccountType=805306369)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
			$objSearcher.PageSize = 1000
   			$objSearcher.PropertiesToLoad.Clear() | Out-Null
			$objSearcher.PropertiesToLoad.Add("dNSHostName") | Out-Null
			$Computers = $objSearcher.FindAll() | ForEach-Object { $_.properties.dnshostname }
			$Computers = $Computers | Sort-Object -Unique
		}
		
		else{
			# All Domains
			$FindCurrentDomain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
			if(!$FindCurrentDomain){$FindCurrentDomain = [System.Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties().DomainName.Trim()}
			if(!$FindCurrentDomain){$FindCurrentDomain = $env:USERDNSDOMAIN}
			if(!$FindCurrentDomain){$FindCurrentDomain = Get-WmiObject -Namespace root\cimv2 -Class Win32_ComputerSystem | Select Domain | Format-Table -HideTableHeaders | out-string | ForEach-Object { $_.Trim() }}
			
			$ParentDomain = ($FindCurrentDomain | Select-Object -ExpandProperty Forest | Select-Object -ExpandProperty Name)
			$DomainContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Domain', $ParentDomain)
			$ChildContext = [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($DomainContext)
			$ChildDomains = @($ChildContext | Select-Object -ExpandProperty Children | Select-Object -ExpandProperty Name)
			
			$AllDomains = @($ParentDomain)
			
			if($ChildDomains){
				foreach($ChildDomain in $ChildDomains){
					$AllDomains += $ChildDomain
				}
			}
			
			# Trust Domains (save to variable)
			
			$TrustTargetNames = @(foreach($AllDomain in $AllDomains){(FindDomainTrusts -Domain $AllDomain).TargetName})
			$TrustTargetNames = $TrustTargetNames | Sort-Object -Unique
			$TrustTargetNames = $TrustTargetNames | Where-Object { $_ -notin $AllDomains }
			
			# Remove Outbound Trust from $AllDomains
			
			$OutboundTrusts = @(foreach($AllDomain in $AllDomains){FindDomainTrusts -Domain $AllDomain | Where-Object { $_.TrustDirection -eq 'Outbound' } | Select-Object -ExpandProperty TargetName})
			
			foreach($TrustTargetName in $TrustTargetNames){
				$AllDomains += $TrustTargetName
			}
			
			$AllDomains = $AllDomains | Sort-Object -Unique
			
			$PlaceHolderDomains = $AllDomains
			$AllDomains = $AllDomains | Where-Object { $_ -notin $OutboundTrusts }
			
			if($Exclude){
				$ExcludeDomains = @($Exclude -split ',')
				$AllDomains = $AllDomains | Where-Object { $_ -notin $ExcludeDomains }
			}
			
			### Remove Unreachable domains

			$ReachableDomains = $AllDomains

			foreach($AllDomain in $AllDomains){
				$ReachableResult = $null
				$DomainContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Domain', $AllDomain)
				$ReachableResult = [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($DomainContext)
				if($ReachableResult){}
				else{$ReachableDomains = $ReachableDomains | Where-Object { $_ -ne $AllDomain }}
			}

			$AllDomains = $ReachableDomains
			
			if($AllDomains -eq $null){
				Write-Host ""
				Write-Host " [-] No Domains in scope" -ForegroundColor Red
				Write-Host ""
				break
			}
			
			else{
				Write-Output ""
				Write-Output "[+] Scope: $($AllDomains -join ", ")"

			}
			Write-Output ""
			Write-Output "[+] Enumerating Targets..."
			Write-Output ""
			
			foreach($AllDomain in $AllDomains){
				$objSearcher = New-Object System.DirectoryServices.DirectorySearcher
				if ($DomainController) {
					$TempDomainName = "DC=" + ($AllDomain.Split(".") -join ",DC=")
					$ldapPath = "LDAP://$DomainController/$TempDomainName"
					$objSearcher.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry($ldapPath)
				} else {
					$objSearcher.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$AllDomain")
				}
				$objSearcher.Filter = "(&(sAMAccountType=805306369)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
				$objSearcher.PageSize = 1000
    				$objSearcher.PropertiesToLoad.Clear() | Out-Null
				$objSearcher.PropertiesToLoad.Add("dNSHostName") | Out-Null
				$Computers += $objSearcher.FindAll() | ForEach-Object { $_.properties.dnshostname }
			}
			
			$Computers = $Computers | Sort-Object -Unique
		}
	}

	$Computers = $Computers | Where-Object { $_ -and $_.trim() }
	$HostFQDN = [System.Net.Dns]::GetHostByName(($env:computerName)).HostName
	$TempHostname = $HostFQDN -replace '\..*', ''
	$Computers = $Computers | Where-Object {$_ -ne "$HostFQDN" -and $_ -ne "$TempHostname"}
	
	Write-Output "[+] Testing Access..."
	
	# Create a runspace pool
	$runspacePool = [runspacefactory]::CreateRunspacePool(1, 10)
	$runspacePool.Open()
	$runspaces = New-Object System.Collections.ArrayList

	$scriptBlock = {
		param($ComputerName, $UserName, $Password, $UserDomain, $Local)

		Function Test-Port {
			param ($ComputerName, $Port)
			$tcpClient = New-Object System.Net.Sockets.TcpClient
			$asyncResult = $tcpClient.BeginConnect($ComputerName, $Port, $null, $null)
			$wait = $asyncResult.AsyncWaitHandle.WaitOne(100)

			if ($wait) {
				try {
					$tcpClient.EndConnect($asyncResult)
					return $true
				} catch {
					return $false
				}
			} else {
				return $false
			}
		}
		
		# Define the required constants and structs
		Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public enum LogonType : int {
    LOGON32_LOGON_NEW_CREDENTIALS = 9,
}

public enum LogonProvider : int {
    LOGON32_PROVIDER_DEFAULT = 0,
}

public enum TOKEN_TYPE {
    TokenPrimary = 1,
    TokenImpersonation
}

public enum TOKEN_ACCESS : uint {
    TOKEN_DUPLICATE = 0x0002
}

public enum PROCESS_ACCESS : uint {
    PROCESS_QUERY_INFORMATION = 0x0400
}

public class Advapi32 {
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern bool LogonUser(
        String lpszUsername,
        String lpszDomain,
        String lpszPassword,
        LogonType dwLogonType,
        LogonProvider dwLogonProvider,
        out IntPtr phToken
    );

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool ImpersonateLoggedOnUser(IntPtr hToken);
    
    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool RevertToSelf();

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool DuplicateToken(IntPtr ExistingTokenHandle, int SECURITY_IMPERSONATION_LEVEL, out IntPtr DuplicateTokenHandle);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr hToken);
}

public class Kernel32 {
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);
}
"@ -Language CSharp

		function Token-Impersonation {
			param (
				[Parameter(Mandatory=$true)]
				[string]$Username,

				[Parameter(Mandatory=$true)]
				[string]$Password,

				[Parameter(Mandatory=$true)]
				[string]$Domain
			)

			process {
				$tokenHandle = [IntPtr]::Zero
				if (-not [Advapi32]::LogonUser($Username, $Domain, $Password, [LogonType]::LOGON32_LOGON_NEW_CREDENTIALS, [LogonProvider]::LOGON32_PROVIDER_DEFAULT, [ref]$tokenHandle)) {
					throw "[-] Failed to obtain user token."
				}

				if (-not [Advapi32]::ImpersonateLoggedOnUser($tokenHandle)) {
					[Advapi32]::CloseHandle($tokenHandle)
					throw "[-] Failed to impersonate user."
				}

				Write-Output "[+] Impersonation successful using provided credentials."
			}
		}

		function Revert-Token {
			process {
				if ([Advapi32]::RevertToSelf()) {
					Write-Output "[+] Successfully reverted to original user context."
				} else {
					Write-Output "[-] Failed to revert to original user."
				}
			}
		}

		# Check Ports
		$WinRMPort = Test-Port -ComputerName $ComputerName -Port 5985
		$WMIPort = Test-Port -ComputerName $ComputerName -Port 135
		$SMBPort = Test-Port -ComputerName $ComputerName -Port 445

		# if all three fail, return and kill the runspace
		if (-not $SMBPort -and -not $WMIPort -and -not $WinRMPort) {
			return "Unable to connect"
		}

		# Impersonate User
		if($Local -AND $Username -AND $Password){
			Token-Impersonation -Username $UserName -Domain "." -Password $Password
		}
		elseif($Username -AND $Password -AND $UserDomain){
			Token-Impersonation -Username $UserName -Domain $UserDomain -Password $Password
		}

		# SMB Check
		if ($SMBPort) {
			$SMBCheck = Test-Path "\\$ComputerName\c$" -ErrorAction SilentlyContinue
			if (-not $SMBCheck) {
				$SMBAccess = $False
			} else {
				$SMBAccess = $True
			}
		}

		# WMI Check
		if ($WMIPort) {
			$Timeout = 2000
			$Result = $null
			$Command = "Get-WmiObject -Class Win32_OperatingSystem -ComputerName '$ComputerName'"
			$Process = New-Object System.Diagnostics.Process
			$Process.StartInfo.FileName = "powershell.exe"
			$Process.StartInfo.Arguments = "-NoProfile -Command $Command"
			$Process.StartInfo.RedirectStandardOutput = $true
			$Process.StartInfo.RedirectStandardError = $true
			$Process.StartInfo.UseShellExecute = $false
			$Process.StartInfo.CreateNoWindow = $true
			$Process.Start() | Out-Null
			if ($Process.WaitForExit($Timeout)) {$Result = $Process.StandardOutput.ReadToEnd()}
			else {$Process.Kill()}
			$Process.Dispose()
			if ($Result) {$WMIAccess = $True}
			else {$WMIAccess = $False}
		}

		# WinRM Check
		if ($WinRMPort) {
			try {
				Invoke-Command -ComputerName $computerName -ScriptBlock { whoami } -ErrorAction Stop
				$WinRMAccess = $True
			} catch {
				if ($_.Exception.Message -like "*Access is Denied*") {
					$WinRMAccess = $False
				} elseif ($_.Exception.Message -like "*cannot be resolved*") {
					$WinRMAccess = $False
				}
			}
		}

		# Revert Token
		if(($Local -AND $Username -AND $Password) -OR ($Username -AND $Password -AND $UserDomain)){Revert-Token}

		return @{
			WMIAccess   = $WMIAccess
			SMBAccess   = $SMBAccess
			WinRMAccess = $WinRMAccess
		}
	}

	# Create and invoke runspaces for each computer
	foreach ($computer in $computers) {
		$ComputerName = "$computer"
		
		$runspace = [powershell]::Create().AddScript($scriptBlock).AddArgument($ComputerName)
		$runspace = $runspace.AddArgument($UserName).AddArgument($Password).AddArgument($UserDomain).AddArgument($Local)
		$runspace.RunspacePool = $runspacePool

		[void]$runspaces.Add([PSCustomObject]@{
			Runspace     = $runspace
			Handle       = $runspace.BeginInvoke()
			ComputerName = $ComputerName
			Completed    = $false
		})
	}
	
	$results = @()

	# Poll the runspaces and display results as they complete
	do {
		foreach ($runspace in $runspaces | Where-Object { -not $_.Completed }) {
			if ($runspace.Handle.IsCompleted) {
				$runspace.Completed = $true
				$result = $runspace.Runspace.EndInvoke($runspace.Handle)
			
				if ($result -eq "Unable to connect") { continue }

				# Build string of successful protocols
				$successfulProtocols = @()
				if ($result.SMBAccess -eq $True) { $successfulProtocols += "SMB" }
				if ($result.WinRMAccess -eq $True) { $successfulProtocols += "WinRM" }
				if ($result.WMIAccess -eq $True) { $successfulProtocols += "WMI" }

				if ($successfulProtocols.Count -gt 0) {
					$statusText = $successfulProtocols -join ', '
					$obj = New-Object PSObject -Property @{
                        ComputerName = $runspace.ComputerName
                        Protocol = $statusText
                    }
					$results += $obj
				}
			}
		}
		Start-Sleep -Milliseconds 100
	} while ($runspaces | Where-Object { -not $_.Completed })
	
	if($results){$results | Sort-Object ComputerName | ForEach-Object { Write-Output $_ }}
	else{
		Write-Output ""
		Write-Output "[-] No Access"
		Write-Output ""
	}

	# Clean up
	$runspacePool.Close()
	$runspacePool.Dispose()
}

function FindDomainTrusts {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Domain,
        [Parameter(Mandatory = $false)]
        [string]$Server
    )

    # Define the TrustAttributes mapping
    $TrustAttributesMapping = @{
        [uint32]'0x00000001' = 'NON_TRANSITIVE'
        [uint32]'0x00000002' = 'UPLEVEL_ONLY'
        [uint32]'0x00000004' = 'FILTER_SIDS'
        [uint32]'0x00000008' = 'FOREST_TRANSITIVE'
        [uint32]'0x00000010' = 'CROSS_ORGANIZATION'
        [uint32]'0x00000020' = 'WITHIN_FOREST'
        [uint32]'0x00000040' = 'TREAT_AS_EXTERNAL'
        [uint32]'0x00000080' = 'TRUST_USES_RC4_ENCRYPTION'
        [uint32]'0x00000100' = 'TRUST_USES_AES_KEYS'
        [uint32]'0x00000200' = 'CROSS_ORGANIZATION_NO_TGT_DELEGATION'
        [uint32]'0x00000400' = 'PIM_TRUST'
    }

    try {
        # Construct the LDAP path and create the DirectorySearcher
        $ldapPath = if ($Server) { "LDAP://$Server/DC=$($Domain -replace '\.',',DC=')" } else { "LDAP://DC=$($Domain -replace '\.',',DC=')" }
        $searcher = New-Object System.DirectoryServices.DirectorySearcher
        $searcher.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry($ldapPath)
        $searcher.Filter = "(objectClass=trustedDomain)"
        $searcher.PropertiesToLoad.AddRange(@("name", "trustPartner", "trustDirection", "trustType", "trustAttributes", "whenCreated", "whenChanged"))
        
        # Execute the search
        $results = $searcher.FindAll()

        # Enumerate the results
        foreach ($result in $results) {
            # Resolve the trust direction
            $Direction = Switch ($result.Properties["trustdirection"][0]) {
                0 { 'Disabled' }
                1 { 'Inbound' }
                2 { 'Outbound' }
                3 { 'Bidirectional' }
            }

            # Resolve the trust type
            $TrustType = Switch ($result.Properties["trusttype"][0]) {
                1 { 'WINDOWS_NON_ACTIVE_DIRECTORY' }
                2 { 'WINDOWS_ACTIVE_DIRECTORY' }
                3 { 'MIT' }
            }

            # Resolve the trust attributes
            $TrustAttributes = @()
            foreach ($key in $TrustAttributesMapping.Keys) {
                if ($result.Properties["trustattributes"][0] -band $key) {
                    $TrustAttributes += $TrustAttributesMapping[$key]
                }
            }

            # Create and output the custom object
            $trustInfo = New-Object PSObject -Property @{
                SourceName      = $Domain
                TargetName      = $result.Properties["trustPartner"][0]
                TrustDirection  = $Direction
                TrustType       = $TrustType
                TrustAttributes = ($TrustAttributes -join ', ')
                WhenCreated     = $result.Properties["whenCreated"][0]
                WhenChanged     = $result.Properties["whenChanged"][0]
            }

            $trustInfo
        }
    }
    catch {
        Write-Error "An error occurred: $_"
    }
    finally {
        $searcher.Dispose()
        if ($results) { $results.Dispose() }
    }
}
