<#
.SYNOPSIS
    YubiKeyTools PowerShell module — manage YubiKeys via YubiEnroll and ykman.
.DESCRIPTION
    Manage, provision and inspect YubiKeys.  Wraps YubiEnroll for credential
    workflows and the YubiKey Manager CLI (`ykman`) for device-level details.
#>


function Get-YkInfo
{
    [CmdletBinding()]
	
	param
	(
		[int] $SerialNumber
		,
		[Switch] $KeepWarningsAndErrors
		,
		[Switch] $ReturnFullRawData
	)
	
	
	$YkmanExecutablePotentialPathsList = "${env:ProgramFiles}\Yubico\YubiKey Manager CLI\ykman.exe","${env:ProgramFiles(x86)}\Yubico\YubiKey Manager\ykman.exe"
	
	
	if (!$Global:YubiKeyManager)
	{
		foreach ($Path in $YkmanExecutablePotentialPathsList)
		{
			if (Test-Path $Path)
			{
				$Global:YubiKeyManager = Get-Command $Path
			}
		}
		
		if (!$Global:YubiKeyManager)
		{
			$Global:YubiKeyManager = Get-Command 'ykman' -ErrorAction SilentlyContinue
		}
		
		if (!$Global:YubiKeyManager)
		{
			throw 'ykman CLI not found.'
		}
		
		Write-Verbose "ykman CLI version $($YubiKeyManager.Version) was found: '$($YubiKeyManager.Source)'"
	}
	
	if (!$SerialNumber)
	{
		[Array] $SerialsList = & $YubiKeyManager.Source list --serials 2>$null
	} else
	{
		[Array] $SerialsList = $SerialNumber
	}
	
    if (!$SerialsList) { Write-Verbose 'No YubiKey detected.' }
	
	[Array] $Result = $null
	
	foreach ($SerialNumber in $SerialsList)
	{
		$KeyRawDataFull  = (& $YubiKeyManager.Source --device $SerialNumber 'info' 2>&1) -split "`r?`n"
		
		if ($ReturnFullRawData)
		{
			 return $KeyRawDataFull
		}
		
		$WarningError = $KeyRawDataFull | Where-Object { $_ -and ($_ -match '^(WARNING|ERROR):') }
		$KeyRawData = $KeyRawDataFull | Where-Object { $_ -and ($_ -notmatch '^(WARNING|ERROR):') }
		
		if ($WarningError -AND $KeepWarningsAndErrors)
		{
			Write-Host $WarningError
		}
		
		if (!$KeyRawData) { Write-Verbose 'No YubiKey detected.' }
		
		
		if (!($AppsTableHeaders = ($KeyRawData | ? {$_ -match '^Applications(\s+USB\s+NFC)?\s*$' }).Trim()))
		{
			Write-Host "KeyRawData:"
			Write-Host "$KeyRawData"
			throw 'Code issue, parsing must be updated for Get-YkInfo function'
		}
		
		$KeyData = @{} | Select DeviceType,SerialNumber,FirmwareVersion,FormFactor,KeyConfigLockedWithCode,NfcConnectivityCapable,NfcConnectivityEnabled,EnabledUSBInterfaces,CapableUsbApplications,CapableNfcApplications,EnabledUsbApplications,EnabledNfcApplications,ApplicationsUSB,ApplicationsNFC
		
		$KeyData.NfcConnectivityCapable = $false
		$KeyData.NfcConnectivityEnabled = $false
		$KeyData.KeyConfigLockedWithCode = $false
		
		$Section = 'header'
		$AppsUsb = [Ordered] @{}
		$AppsNfc = [Ordered] @{}
		
		
		
		foreach ($Line in $KeyRawData)
		{ 
			if ($Line -like "*NFC transport is enabled*")
			{
				$KeyData.NfcConnectivityEnabled = $true
			}
			if ($Line -like "*Configured capabilities are protected by a lock code*")
			{
				$KeyData.KeyConfigLockedWithCode = $true
			}
			
			if ($Line -match 'Applications\s+USB\s+NFC')
			{
				$Section = 'appsWithNfc'
				$KeyData.NfcConnectivityCapable = $true
				continue
			}
			
			if ($Line -match '^Applications$')
			{
				$Section = 'appsUsbOnly'
				$KeyData.PSObject.Properties.Remove('NfcConnectivityEnabled')
				$KeyData.PSObject.Properties.Remove('CapableNfcApplications')
				$KeyData.PSObject.Properties.Remove('EnabledNfcApplications')
				$KeyData.PSObject.Properties.Remove('ApplicationsNFC')
				continue
			}
			
			switch ($Section)
			{
				'header' {
					if ($Line -match '^(.*?):\s+(.+)$') {
						$Property,$Value = $Matches[1].Trim(),$Matches[2].Trim()
						switch ($Property) {
							'Device type'            { $KeyData.DeviceType = $Value.Trim() }
							'Serial number'          { $KeyData.SerialNumber = [int]$Value.Trim() }
							'Firmware version'       { $KeyData.FirmwareVersion = [version]$Value.Trim() }
							'Form factor'            { $KeyData.FormFactor = $Value.Trim() }
							'Enabled USB interfaces' { $KeyData.EnabledUSBInterfaces = $Value -split ',?\s+' }
						}
					}
				}
				'appsWithNfc' {
					
					$Cells = ($line -replace "`t", '  ') -split '\s{2,}' | ForEach-Object { $_.Trim() }
					$LineDataObject = New-Object PSObject -Property @{
						'AppName' = $Cells[0]
						'AppStatusUSB' = $cells[1]
						'AppStatusNFC' = $cells[2]
					}
					
					$AppsUsb[$LineDataObject.AppName] = $LineDataObject.AppStatusUSB
					$AppsNfc[$LineDataObject.AppName] = $LineDataObject.AppStatusNFC
				}
				'appsUsbOnly' {
					
					$Cells = ($line -replace "`t", '  ') -split '\s{2,}' | ForEach-Object { $_.Trim() }
					$LineDataObject = New-Object PSObject -Property @{
						'AppName' = $Cells[0]
						'AppStatusUSB' = $cells[1]
					}
					
					$AppsUsb[$LineDataObject.AppName] = $LineDataObject.AppStatusUSB
				}
			}
			
			$KeyData.ApplicationsUSB = $AppsUsb
			
			if ($Section -eq 'appsWithNfc')
			{
				$KeyData.ApplicationsNFC = $AppsNfc
			}
		}
		
		
		$KeyData.CapableUsbApplications = $KeyData.ApplicationsUSB.GetEnumerator() | ? { $_.Value -ne 'Not available' } | Select-Object -ExpandProperty Name
		$KeyData.EnabledUsbApplications = $KeyData.ApplicationsUSB.GetEnumerator() | ? { $_.Value -eq 'Enabled' } | Select-Object -ExpandProperty Name
		
		if ($Section -eq 'appsWithNfc')
		{
			$KeyData.CapableNfcApplications = $KeyData.ApplicationsNFC.GetEnumerator() | ? { $_.Value -ne 'Not available' } | Select-Object -ExpandProperty Name
			$KeyData.EnabledNfcApplications = $KeyData.ApplicationsNFC.GetEnumerator() | ? { $_.Value -eq 'Enabled' } | Select-Object -ExpandProperty Name
		}
		
		$Result += $KeyData
	}
	
	return $Result
}

function Wait-YkInsert
{
    [CmdletBinding()]
	param
	(
		[int]$TimeoutSeconds = 600
		,
		[int]$PollSeconds = 2
		,
		[Switch] $LimitToOne
	)
	
	Write-Verbose "Getting already inserted YubiKey(s)..."
    [Array] $initial = (Get-YkInfo).SerialNumber
	
	if ($initial)
	{
		Write-Verbose "YubiKey(s) already inserted (ignored excepted if removed for at least $($PollSeconds+1) seconds):`n$($initial -join `"`n`")"
	}
	else
	{
		Write-Verbose "No inserted YubiKey deteted"
	}
	
    $start = Get-Date
	
    do
	{
		Write-Host -NoNewline '.'
        Start-Sleep -Seconds $PollSeconds
        
		$current = Get-YkInfo
		
		if ($current.SerialNumber.Count -lt $initial.Count)
		{
			Write-Verbose "At least one YubiKey was removed, refreshing initial list"
			$initial = $current.SerialNumber
			continue
		}
		
		[Array] $new = $current | Where-Object { $_.SerialNumber -notin $initial }
		
		if ($new)
		{
			Write-Host ''
			if ($LimitToOne -AND ($new.count -gt 1))
			{
				throw 'More than one key was inserted'
			}
			return $new[0]
		}
		
		Write-Verbose "No newly inserted YubiKey deteted yet"
		
        if ($TimeoutSeconds -gt 0 -and (New-TimeSpan $start (Get-Date)).TotalSeconds -ge $TimeoutSeconds)
		{
            Write-Host ''
			throw 'Timeout waiting for YubiKey insertion.'
        }
		
    } while ($true)
}


function Get-RandomHexNumber # Get-RandomHexNumber -Length 64
{
	Param
	(
		[Int] $Length = 32
    )
	
	[String] $Chars = "0123456789ABCDEF"
	
	$Bytes = New-Object "System.Byte[]" $Length
	$RNGCryptoService = New-Object System.Security.Cryptography.RNGCryptoServiceProvider
	$RNGCryptoService.GetBytes($Bytes)
	
	$Result = ''
	1..$Length | foreach {
		$Result += $Chars[ $Bytes[$_] % $Chars.Length ]    
	}
	
	$Result
}

function Invoke-YubiEnrollCommand
{
    [CmdletBinding()]
	
	param
	(
		[parameter(Mandatory=$true, ParameterSetName="Command")]
		[String] $Command
		,
        [String[]] $Arguments = @()
		,
        [Switch] $Raw
		,
		[parameter(Mandatory=$true, ParameterSetName="Path")]
        [Switch] $OnlyReturnYubiEnrollPath
    )
	
    $YubiEnroll = Get-Command 'yubienroll' -ErrorAction SilentlyContinue
    if (-not $YubiEnroll) { throw 'YubiEnroll CLI not found.' }
	
	if ($OnlyReturnYubiEnrollPath)
	{
		return $YubiEnroll.Source
	}


	$psi = [System.Diagnostics.ProcessStartInfo] @{
		FileName               = $YubiEnroll.Source
		Arguments              = ($Command + ' ' + ($Arguments -join ' ')).Trim()
		RedirectStandardOutput = $true
		RedirectStandardError  = $true
		UseShellExecute        = $false
	}

	$proc   = [System.Diagnostics.Process]::Start($psi)
	$stdout = $proc.StandardOutput.ReadToEnd()
	$stderr = $proc.StandardError.ReadToEnd()
	$proc.WaitForExit()
	if ($proc.ExitCode -ne 0) { throw "YubiEnroll exited $($proc.ExitCode): $stderr" }

	if ($Raw) { return $stdout }
	try   { $stdout | ConvertFrom-Json } catch { $stdout }


}


function Check-YubiEnrollAuth
{
	$CurrentStatus = Invoke-YubiEnrollCommand -Command status
}



function Add-YkIdentity
{
    [CmdletBinding()]
	param
	(
		[Parameter(Mandatory)]
		[ValidateNotNullorEmpty()]
		[string] $UserID
		,
		[Parameter(Mandatory)]
		[ValidateSet("Reinitialize/ForcePinChange", "Reinitialize/NoForcedPinChange", "AddIdentity")]
		[string] $Profile
	)


	$YubiEnrollPath = Invoke-YubiEnrollCommand -OnlyReturnYubiEnrollPath
	& $YubiEnrollPath credentials add "$UserID" --profile "$Profile" --force -d $YubiKey.DeviceType
}


function Remove-YkIdentity
{
	param(
    [Parameter(Mandatory)]
		[ValidateNotNullorEmpty()]
		[string] $UserID
	)

	$YubiEnrollPath = Invoke-YubiEnrollCommand -OnlyReturnYubiEnrollPath
	& $YubiEnrollPath credentials delete "$UserID" --force
}


function Set-YkFidoPin
{
    [CmdletBinding()]
	param()
	
	[int]$OldPin = Read-Host 'Old Pin '
	[int]$NewPin = Read-Host 'New Pin'
	Invoke-YubiKeyManager -Command "fido access change-pin --pin $OldPin --new-pin $NewPin"
}

function Show-Profiles 
{
	[CmdletBinding()]
	param()

	$YubiEnrollPath = Invoke-YubiEnrollCommand -OnlyReturnYubiEnrollPath
	& $YubiEnrollPath profiles list
}


