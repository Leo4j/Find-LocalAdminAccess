function Find-LocalAdminAccess {
	
	<#
	.SYNOPSIS
	Find-LocalAdminAccess Author: Rob LP (@L3o4j)
	https://github.com/Leo4j/Find-LocalAdminAccess
 	#>
	
	param (
		[string]$Targets,
		[string]$Command,
		[string]$Domain,
		[string]$DomainController,
		[switch]$ShowErrors
	)
	
	if(!$ShowErrors){
		$ErrorActionPreference = "SilentlyContinue"
		$WarningPreference = "SilentlyContinue"
	}
	
	if ($Targets) {
     	$TestPath = Test-Path $Targets
		
		if($TestPath){
			$Computers = Get-Content -Path $Targets
			$Computers = $Computers | Sort-Object -Unique
		}
		
		else{
			$Computers = $Targets -split ","
			$Computers = $Computers | Sort-Object -Unique
		}
    } 
	
	else {
		$Computers = @()
		$objSearcher = New-Object System.DirectoryServices.DirectorySearcher
		if($Domain){
			if($DomainController){
				$TempDomainName = "DC=" + $Domain.Split(".")
				$domainDN = $TempDomainName -replace " ", ",DC="
				$ldapPath = "LDAP://$DomainController/$domainDN"
				$objSearcher.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry($ldapPath)
			}
			else{$objSearcher.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$Domain")}
		}
		else{$objSearcher.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry}
		$objSearcher.Filter = "(&(sAMAccountType=805306369)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
		$objSearcher.PageSize = 1000
		$Computers = $objSearcher.FindAll() | ForEach-Object { $_.properties.dnshostname }
		$Computers = $Computers | Sort-Object -Unique
	}

    $Computers = $Computers | Where-Object { $_ -and $_.trim() }
	$HostFQDN = [System.Net.Dns]::GetHostByName(($env:computerName)).HostName
	$TempHostname = $HostFQDN -replace '\..*', ''
	$Computers = $Computers | Where-Object {$_ -ne "$HostFQDN"}
	$Computers = $Computers | Where-Object {$_ -ne "$TempHostname"}
	
	# Create a runspace pool
	$runspacePool = [runspacefactory]::CreateRunspacePool(1, 10)
	$runspacePool.Open()
	$runspaces = New-Object System.Collections.ArrayList

	$scriptBlock = {
		param ($computerName)

		Function Test-Port {
			param ($ComputerName, $Port)
			$tcpClient = New-Object System.Net.Sockets.TcpClient
			$asyncResult = $tcpClient.BeginConnect($ComputerName, $Port, $null, $null)
			$wait = $asyncResult.AsyncWaitHandle.WaitOne(100)

			if ($wait) {
				try {
					$tcpClient.EndConnect($asyncResult)
					return $true
				}
				catch {
					return $false
				}
			}
			else {
				return $false
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

		# SMB Check
		if ($SMBPort) {
			$SMBCheck = Test-Path "\\$ComputerName\c$" -ErrorAction SilentlyContinue
			if (-not $SMBCheck) {
				$SMBAccess = $False
			}
			else {
				$SMBAccess = $True
			}
		}

		# WMI Check
		if ($WMIPort) {
			try {
				Get-WmiObject -Class Win32_OperatingSystem -ComputerName $ComputerName -ErrorAction Stop
				$WMIAccess = $True
			}
			catch {
				$WMIAccess = $False
			}
		}

		# WinRM Check
		if ($WinRMPort) {
			try {
				Invoke-Command -ComputerName $computerName -ScriptBlock { whoami } -ErrorAction Stop
				$WinRMAccess = $True
			}
			catch {
				if ($_.Exception.Message -like "*Access is Denied*") {
					$WinRMAccess = $False
				}
				elseif ($_.Exception.Message -like "*cannot be resolved*") {
					$WinRMAccess = $False
				}
			}
		}

		return @{
			WMIAccess   = $WMIAccess
			SMBAccess   = $SMBAccess
			WinRMAccess = $WinRMAccess
		}
	}

	# Create and invoke runspaces for each computer
	foreach ($computer in $computers) {

		$ComputerName = "$Computer"
		
		$runspace = [powershell]::Create().AddScript($scriptBlock).AddArgument($ComputerName)
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
					#return $($runspace.ComputerName)
					continue
				}
			}
		}
		Start-Sleep -Milliseconds 100
	} while ($runspaces | Where-Object { -not $_.Completed })
	
	$results | Sort-Object ComputerName | ForEach-Object { Write-Output $_ }

	# Clean up
	$runspacePool.Close()
	$runspacePool.Dispose()
}