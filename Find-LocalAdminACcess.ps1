function Find-LocalAdminAccess {
	
	<#

	.SYNOPSIS
	Find-LocalAdminAccess Author: Rob LP (@L3o4j)
	https://github.com/Leo4j/Find-LocalAdminAccess

	.DESCRIPTION
	Check the Domain for local Admin Access
	
	.PARAMETER ComputerNames
	Provide a single target or comma-separated targets
	
	.PARAMETER ComputerFile
	Provide a file containing targets (one per line)
	
	.PARAMETER Method
	Provide a method to check for Admin Access (SMB, WMI, PSRemoting)
	
	.PARAMETER UserName
	UserName to check for Admin Access as (Works with WMI and PSRemoting only)
	
	.PARAMETER Password
	Password for the UserName (Works with WMI and PSRemoting only)
	
	.PARAMETER ShowErrors
	Show Errors
	
	.EXAMPLE
	Find-LocalAdminAccess -Method SMB
	Find-LocalAdminAccess -Method WMI
	Find-LocalAdminAccess -Method PSRemoting
 	Find-LocalAdminAccess -Method WMI -UserName "ferrari\Administrator" -Password "P@ssw0rd!"
	Find-LocalAdminAccess -Method PSRemoting -UserName "ferrari\Administrator" -Password "P@ssw0rd!"
	
	#>
	
    	param (
        	[string]$ComputerNames,
        	[string]$ComputerFile,
		[Parameter(Mandatory=$true)]
        	[string]$Method,
        	[string]$UserName,
        	[string]$Password,
		[switch]$ShowErrors
    	)
	if(!$ShowErrors){
		$ErrorActionPreference = "SilentlyContinue"
		$WarningPreference = "SilentlyContinue"
	}
	
	Set-Variable MaximumHistoryCount 32767

    	if (($UserName -OR $Password) -AND ($Method -eq "SMB")) {
        	Write-Output "Please use Method WMI or PSRemoting if you need to run as a different user"
        	return
    	}

    	if ($Computerfile) {
        	$Computers = Get-Content $Computerfile | Sort-Object -Unique
    	} elseif ($ComputerNames) {
        	$Computers = $ComputerNames -split "," | Sort-Object -Unique
    	} else {
		$Computers = @()
        	$objSearcher = New-Object System.DirectoryServices.DirectorySearcher
        	$objSearcher.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry
        	$objSearcher.Filter = "(&(sAMAccountType=805306369)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
        	$objSearcher.PageSize = 1000
        	$Computers = $objSearcher.FindAll() | ForEach-Object { $_.properties.dnshostname }
    	}

    	$Computers = $Computers | Where-Object { $_ -and $_.trim() }
	$HostFQDN = [System.Net.Dns]::GetHostByName(($env:computerName)).HostName
	$TempHostname = $HostFQDN -replace '\..*', ''
	$Computers = $Computers | Where-Object {$_ -ne "$HostFQDN"}
	$Computers = $Computers | Where-Object {$_ -ne "$TempHostname"}
	
	$reachable_hosts = $null
	$Tasks = $null
	
	if($Method -eq "WMI"){$PortScan = 135}
	elseif($Method -eq "SMB"){$PortScan = 445}
	elseif($Method -eq "PSRemoting"){$PortScan = 5985}
	
	$reachable_hosts = @()
	
	$Tasks = $Computers | % {
		$tcpClient = New-Object System.Net.Sockets.TcpClient
		$asyncResult = $tcpClient.BeginConnect($_, $PortScan, $null, $null)
		$wait = $asyncResult.AsyncWaitHandle.WaitOne(50)
		if($wait) {
			try{
			$tcpClient.EndConnect($asyncResult)
			$reachable_hosts += $_
			} catch{}
		}
		$tcpClient.Close()
	}
	
	$Computers = $reachable_hosts
	
	if($UserName){
		Write-Host ""
		Write-Host "[+] $UserName has Local Admin access on:" -ForegroundColor Yellow
		Write-Host ""
	}
	else{
		Write-Host ""
		Write-Host "[+] The current user has Local Admin access on:" -ForegroundColor Yellow
		Write-Host ""
	}

    	$ScriptBlock = {
		param (
			$Computer,
			$Method,
			$UserName,
			$Password
		)
		
		$SecPassword = ConvertTo-SecureString $Password -AsPlainText -Force
		$cred = New-Object System.Management.Automation.PSCredential($UserName, $SecPassword)
		
		$result = @{
			Computer = $Computer
			Success  = $false
			Message  = ""
		}

		try {
			if ($UserName -AND $Password -AND ($Method -eq "WMI")) {
				Get-WmiObject -Class Win32_OperatingSystem -ComputerName $Computer -ErrorAction Stop -Credential $cred
			} elseif ($UserName -AND $Password -AND ($Method -eq "PSRemoting")) {
				Invoke-Command -ScriptBlock { hostname } -ComputerName $Computer -ErrorAction Stop -Credential $cred
			} elseif ($Method -eq "WMI") {
				Get-WmiObject -Class Win32_OperatingSystem -ComputerName $Computer -ErrorAction Stop
			} elseif ($Method -eq "PSRemoting") {
				Invoke-Command -ScriptBlock { hostname } -ComputerName $Computer -ErrorAction Stop
			} elseif ($Method -eq "SMB") {
				ls \\$Computer\c$ -ErrorAction Stop
			}
			$result.Success = $true
		} catch {
			$result.Message = $_.Exception.Message
		}

		return $result
	}

    	$runspacePool = [runspacefactory]::CreateRunspacePool(1, 10)
    	$runspacePool.Open()
    	$runspaces = New-Object System.Collections.ArrayList

    	foreach ($Computer in $Computers) {
        	$runspace = [powershell]::Create().AddScript($ScriptBlock).AddArgument($Computer).AddArgument($Method).AddArgument($UserName).AddArgument($Password)
        	$runspace.RunspacePool = $runspacePool
        	$null = $runspaces.Add([PSCustomObject]@{
            	Pipe = $runspace
            	Status = $runspace.BeginInvoke()
        })
    }

    $ComputerAccess = @()
	foreach ($run in $runspaces) {
		$result = $run.Pipe.EndInvoke($run.Status)
		if ($result.Success) {
			$ComputerAccess += $result.Computer
		} else {
			Write-Warning "[-] Failed on $($result.Computer): $($result.Message)"
		}
	}

    $runspaces | ForEach-Object {
        $_.Pipe.Dispose()
    }

    $runspacePool.Close()
    $runspacePool.Dispose()

    $ComputerAccess | Sort-Object | ForEach-Object { Write-Output $_ }

    try {
        $ComputerAccess | Sort-Object | Out-File $PWD\LocalAdminAccess.txt -Force
        Write-Host ""
	Write-Output "[+] Output saved to: $PWD\LocalAdminAccess.txt"
	Write-Host ""
    } catch {
        $ComputerAccess | Sort-Object | Out-File "c:\Users\Public\Documents\LocalAdminAccess.txt" -Force
	Write-Host ""
        Write-Output "[+] Output saved to: c:\Users\Public\Documents\LocalAdminAccess.txt"
	Write-Host ""
    }
}
