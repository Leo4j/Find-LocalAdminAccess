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
	Specify the target Domain

 	.PARAMETER DomainController
	Specify the target DomainController
	
	.PARAMETER Local
	Check for access as the Local Built-In Administrator
	
	.PARAMETER Username
	Specify the Username for the Local Built-In Administrator
	
	.PARAMETER Password
	Specify the Password for the Local Built-In Administrator
	
	.EXAMPLE
	Find-LocalAdminAccess
	Find-LocalAdminAccess -Local -Username "Administrator" -Password "P@ssw0rd!"
	Find-LocalAdminAccess -Domain ferrari.local -DomainController DC01.ferrari.local -Targets "Workstation01.ferrari.local,DC01.ferrari.local"
 	#>
	
	param (
		[string]$Targets,
		[string]$Domain,
		[string]$DomainController,
		[string]$Username,
		[string]$Password,
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
		$objSearcher = New-Object System.DirectoryServices.DirectorySearcher
		if ($Domain) {
			if ($DomainController) {
				$TempDomainName = "DC=" + ($Domain.Split(".") -join ",DC=")
				$ldapPath = "LDAP://$DomainController/$TempDomainName"
				$objSearcher.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry($ldapPath)
			} else {
				$objSearcher.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$Domain")
			}
		} else {
			$objSearcher.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry
		}
		$objSearcher.Filter = "(&(sAMAccountType=805306369)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
		$objSearcher.PageSize = 1000
		$Computers = $objSearcher.FindAll() | ForEach-Object { $_.properties.dnshostname }
		$Computers = $Computers | Sort-Object -Unique
	}

	$Computers = $Computers | Where-Object { $_ -and $_.trim() }
	$HostFQDN = [System.Net.Dns]::GetHostByName(($env:computerName)).HostName
	$TempHostname = $HostFQDN -replace '\..*', ''
	$Computers = $Computers | Where-Object {$_ -ne "$HostFQDN" -and $_ -ne "$TempHostname"}
	
	# Create a runspace pool
	$runspacePool = [runspacefactory]::CreateRunspacePool(1, 10)
	$runspacePool.Open()
	$runspaces = New-Object System.Collections.ArrayList

	$scriptBlock = {
		param(
			[string]$ComputerName,
			[string]$UserName,
			[string]$Password
		)

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
		Token-Impersonation -Username $UserName -Domain "." -Password $Password

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
			try {
				Get-WmiObject -Class Win32_OperatingSystem -ComputerName $ComputerName -ErrorAction Stop
				$WMIAccess = $True
			} catch {
				$WMIAccess = $False
			}
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
		Revert-Token

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
		$runspace = $runspace.AddArgument($UserName).AddArgument($Password)
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
