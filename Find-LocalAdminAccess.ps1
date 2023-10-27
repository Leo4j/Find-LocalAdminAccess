function Find-LocalAdminAccess {
	
	<#

	.SYNOPSIS
	Find-LocalAdminAccess Author: Rob LP (@L3o4j)
	https://github.com/Leo4j/Find-LocalAdminAccess

	.DESCRIPTION
	Check the Domain for local Admin Access
	
	.PARAMETER Targets
	Specify a comma-separated list of targets, or the path to a file containing targets (one per line)
	
	.PARAMETER Method
	Provide a method to check for Admin Access (SMB, WMI, PSRemoting)
	
	.PARAMETER UserName
	UserName to check for Admin Access as (Works with WMI and PSRemoting only)
	
	.PARAMETER Password
	Password for the UserName (Works with WMI and PSRemoting only)
	
	.PARAMETER ShowErrors
	Show Errors

 	.PARAMETER SaveOutput
	Save tool output
	
	.EXAMPLE
	Find-LocalAdminAccess -Method SMB
	Find-LocalAdminAccess -Method WMI
	Find-LocalAdminAccess -Method PSRemoting
 	Find-LocalAdminAccess -Method WMI -UserName "ferrari\Administrator" -Password "P@ssw0rd!"
	Find-LocalAdminAccess -Method PSRemoting -UserName "ferrari\Administrator" -Password "P@ssw0rd!"
	
	#>
	
    	param (
        	[string]$Targets,
		[Parameter(Mandatory=$true)]
        	[string]$Method,
        	[string]$UserName,
        	[string]$Password,
		[switch]$ShowErrors,
  		[switch]$SaveOutput
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

    	if ($Targets) {
     		$TestPath = Test-Path $Targets
		
		if($TestPath){
			$Computers = Get-Content -Path $Targets
			$Computers = $Computers | Sort-Object -Unique
		}
		
		else{
			$Computers = $Targets
			$Computers = $Computers -split ","
			$Computers = $Computers | Sort-Object -Unique
		}
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
	
	if($Method -eq "WMI"){$PortScan = 135}
	elseif($Method -eq "SMB"){$PortScan = 445}
	elseif($Method -eq "PSRemoting"){$PortScan = 5985}
	
	$runspacePool = [runspacefactory]::CreateRunspacePool(1, 10)
	$runspacePool.Open()

	$scriptBlock = {
		param ($computer, $port)
		$tcpClient = New-Object System.Net.Sockets.TcpClient
		$asyncResult = $tcpClient.BeginConnect($computer, $port, $null, $null)
		$wait = $asyncResult.AsyncWaitHandle.WaitOne(50)
		if ($wait) {
			try {
				$tcpClient.EndConnect($asyncResult)
				return $computer
			} catch {}
		}
		$tcpClient.Close()
		return $null
	}

	$runspaces = New-Object 'System.Collections.Generic.List[System.Object]'

	foreach ($computer in $Computers) {
		$powerShellInstance = [powershell]::Create().AddScript($scriptBlock).AddArgument($computer).AddArgument($PortScan)
		$powerShellInstance.RunspacePool = $runspacePool
		$runspaces.Add([PSCustomObject]@{
			Instance = $powerShellInstance
			Status   = $powerShellInstance.BeginInvoke()
		})
	}

	$reachable_hosts = @()
	foreach ($runspace in $runspaces) {
		$result = $runspace.Instance.EndInvoke($runspace.Status)
		if ($result) {
			$reachable_hosts += $result
		}
	}

	$Computers = $reachable_hosts

	$runspacePool.Close()
	$runspacePool.Dispose()
	
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
		
		$Error.Clear()

		if ($UserName -AND $Password -AND ($Method -eq "WMI")) {Get-WmiObject -Class Win32_OperatingSystem -ComputerName $Computer -ErrorAction Stop -Credential $cred}
  		elseif ($UserName -AND $Password -AND ($Method -eq "PSRemoting")) {Invoke-Command -ScriptBlock { hostname } -ComputerName $Computer -ErrorAction Stop -Credential $cred}
    		elseif ($Method -eq "WMI") {Get-WmiObject -Class Win32_OperatingSystem -ComputerName $Computer -ErrorAction Stop}
      		elseif ($Method -eq "PSRemoting") {Invoke-Command -ScriptBlock { hostname } -ComputerName $Computer -ErrorAction Stop}
		elseif ($Method -eq "SMB") {ls \\$Computer\c$ -ErrorAction Stop}
		if($error[0] -eq $null) {
			return @{
		    	Computer = $Computer
		    	Success  = $true
			}
	    	} else {
			return @{
		    	Computer = $Computer
		    	Success  = $false
		    	Message  = $error[0].ToString()
			}
	    	}
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

 	if($ComputerAccess){$ComputerAccess | Sort-Object | ForEach-Object { Write-Output $_ }}
  	else{Write-Output "[-] No Access"}
		
	if($SaveOutput){
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
}
