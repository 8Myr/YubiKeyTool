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


function Show-Credentials
{
	[CmdletBinding()]
	param()

	$UserID = Read-Host 'UserID '
	$YubiEnrollPath = Invoke-YubiEnrollCommand -OnlyReturnYubiEnrollPath
	& $YubiEnrollPath credentials list "$UserID"
}


function Add-Profile
{
	[CmdletBinding()]
	param()

	Write-Host
	$ProfileName = Read-Host 'Name the profile to create '
	$YubiEnrollPath = Invoke-YubiEnrollCommand -OnlyReturnYubiEnrollPath
	& $YubiEnrollPath profiles add $ProfileName
}


function Remove-Profile
{
	[CmdletBinding()]
	param()

	Write-Host
	Show-Profiles
	$ProfileName = Read-Host 'Name the profile to delete '
	$Command = 'delete'
	try {
		$YubiEnrollPath = Invoke-YubiEnrollCommand -OnlyReturnYubiEnrollPath 
		& $YubiEnrollPath profiles $Command $ProfileName
	}
	catch {
		
		Write-Host "`nThis profile do not exist."
	}
}


function Invoke-YubiKeyManager 
{
	[CmdletBinding()]
    param (
        [string]$Command
    )
    try {
        $fullCommand = "ykman $Command"
        Write-Host "Executing: $fullCommand"
        Invoke-Expression $fullCommand
    } catch {
        Write-Host "`nFailed to execute YubiKey Manager command: $($_.Exception.Message)"
    }
}


function Reset-YkFidoCredentials
{
	[CmdletBinding()]
	param()

	Write-Host
	Invoke-YubiKeyManager -Command 'fido reset --force'
}


function Add-LockCode {
    [CmdletBinding()]
    param (
		[switch] $TestMode
	)
	if($TestMode)
	{
		$Stop = $false
    	while (!$Stop) {
    	    $Key = ykman list --serials
    	    Write-Host "Waiting for 1 key..."
    	    Start-Sleep 3
    	    if ($Key) {
    	        $Stop = $true
    	    }
    	}

    	$Key = ykman list --serials
    	$LockCode = '9AF3C7D1E028B64FC52AD0E8B71C4F93'

    	Write-Warning "Generated LockCode: $LockCode DO NOT LOOSE IT !
		"

    	Invoke-YubiKeyManager -Command "--device $Key config set-lock-code --new-lock-code $LockCode"

    	$LockRecord = [PSCustomObject]@{
    	    SerialNumber = $Key
    	    LockCode     = $LockCode
    	}

    	$CsvPath = "{ LockCodes.csv FULL PATH HERE }"

    	$LockRecord | Export-Csv -Path $CsvPath -Append -NoTypeInformation
	}
	else
	{

		$Stop = $false
		while (!$Stop) {
			$Key = ykman list --serials
			Write-Host "Waiting for 1 key..."
			Start-Sleep 3
			if ($Key) {
				$Stop = $true
			}
		}

		$Key = ykman list --serials
		$LockCode = Get-RandomHexNumber
		Write-Warning "Generated LockCode: $LockCode DO NOT LOOSE IT !
		"

		Invoke-YubiKeyManager -Command "--device $Key config set-lock-code --new-lock-code $LockCode"

		$LockRecord = [PSCustomObject]@{
			SerialNumber = $Key
			LockCode     = $LockCode
		}

		$CsvPath = "{ LockCodes.csv FULL PATH HERE }"

		$LockRecord | Export-Csv -Path $CsvPath -Append -NoTypeInformation
	}
}


function Clear-LockCode {
	[CmdletBinding()]
	param ()
	
	$SerialsList = ykman list --serials
	$Key = ykman list --serials
	$LockCode = Get-RandomHexNumber
	Write-Host $LockCode

	Invoke-YubiKeyManager -Command "--device $Key config set-lock-code -c"
}


function Add-ProfileConfiguration
{
	[CmdletBinding()]
	param()

	$TenantName = Read-Host "`nEnter Tenant Name "
	$ClientID = Read-Host "`nEnter AppID "
	$DirectoryID = Read-Host 'Enter Directory (tenant) ID '

	# 3 default profiles here : 
	$Profiles = @"	
[profiles."Reinitialize/ForcePinChange"]
min_pin_length = 6
require_always_uv = false
require_ea = false
reset = true
force_pin_change = true
random_pin = true
random_pin_length = 6
 
[profiles."Reinitialize/NoForcedPinChange"]
min_pin_length = 6
require_always_uv = false
require_ea = false
reset = true
force_pin_change = false
random_pin = true
random_pin_length = 6
 
[profiles."AddIdentity"]
min_pin_length = 6
require_always_uv = false
require_ea = false
reset = false
force_pin_change = false
random_pin = false
random_pin_length = 6
"@

	$fileContent = @"
active_provider = "$TenantName"

[providers.$TenantName]
provider = "ENTRA"
client_id = "$ClientID"
redirect_uri = "http://localhost/yubienroll-redirect"
tenant_id = "$DirectoryID"
entra_base_url = "https://login.microsoftonline.com"
graph_base_url = "https://graph.microsoft.com"

$Profiles
"@
	$ExistingConfig = gc "$($env:APPDATA)\Yubico\yubienroll\yubienroll.toml" -ErrorAction SilentlyContinue
	if ($ExistingConfig)
	{
			Write-Host "`nConfiguration already present."
	}
	else
	{
		Set-Content -Path "$($env:APPDATA)\Yubico\yubienroll\yubienroll.toml" -Value $fileContent
		Write-Host "`nConfiguration is loaded."
	}
}


function Login 
{
	[CmdletBinding()]
	param()
	try {
		$YubiEnrollPath = Invoke-YubiEnrollCommand -OnlyReturnYubiEnrollPath
		& $YubiEnrollPath login
	}
	catch {

		Write-Error "`n$_"
	}
}


function Invoke-YkAutoManage
{
    [CmdletBinding()]
	param
	(
		[int] $TimeoutSeconds = 0
		,
		[switch] $MassManagement
	)

	if (!$MassManagement) 
	{	
    	$YubiKey = Wait-YKInsert -TimeoutSeconds $TimeoutSeconds
	}
	else 
	{
		[array]$UserID = gc "{ UserIDs.txt FULL PATH HERE }"
		Show-Profiles
		$Profile = Read-Host "`nSelect profile "
		
		$Count = 0

		while($Count -ne $UserID.Count)
		{
			[Array] $Global:YubiKeyList = Get-YkInfo
			cls
			Write-Host "Please disconnect all keys then connect  | $($YubiKeyList.Count) YubiKey(s) found"
			$YubiKey = Wait-YkInsert			
			$logPath = New-Item -Path $([System.IO.Path]::GetTempPath()) -Name "transcript-yubienroll_$(Get-Date -Format 'yyyyMMdd-HHmmss').log"
    		Start-Transcript -Path $logPath -Append
    		Add-YkIdentity -UserID $UserID[$Count] -Profile $Profile
    		Stop-Transcript
    		$content = Get-Content $logPath
    		$pattern = 'Temporary PIN:\s*(\d{6})'
    		$Global:Pin = $null
    		foreach ($line in $content) {
    		    if ($line -match $pattern) {
    		        $Global:Pin = $Matches[1]
    		        break
    		    }
    		}
			$serialPattern = 'Serial (?:number|Number):\s*(\d+)'
			$Global:SerialFromTranscript = $null
			foreach ($line in $content) {
			    if ($line -match $serialPattern) {
			        $Global:SerialFromTranscript = $Matches[1]
			        break
			    }
			}

    		$newUser = [PSCustomObject]@{
    		    UserID = $UserID[$Count]
    		    Serial = $Global:SerialFromTranscript
    		    Pin    = $Global:Pin
    		}
		
    		$csvPath = "{ Users.csv FULL PATH HERE}"
    		if (Test-Path $csvPath) {
    		    $users = @(Import-Csv -Path $csvPath)
    		    $users += $newUser
    		} else {
    		    $users = @($newUser)
    		}
    		$users | Export-Csv -Path $csvPath -NoTypeInformation
		
        	Remove-Item -Path $logPath -Force
			$Count++
		}
	}
    Write-Host ('='*60); Write-Host 'YubiKey detected!'; "$($YubiKey.DeviceType) - $($YubiKey.FormFactor) [$($YubiKey.FirmwareVersion)] ($($YubiKey.SerialNumber))" | Write-Host; Write-Host ('='*60)
    while ($true) {
        Write-Host "`nSelect an action:";
        '1) Add Provider and default profiles','2) Login','3) Add Identity','4) Remove Identity','5) Wipe Key (fido)','6) List Profiles','7) Add Profile','8) Remove Profile','9) List Credentials','10) Change FIDO pin', '11) Device Infos (structured)', '12) Add Lock Code (careful)', '13) Clear Lock Code', '14) Mass Management', '15) Exit' | ForEach-Object { Write-Host $_ }
        switch (Read-Host 'Enter number') {
            '1' { Add-ProfileConfiguration }
            '2' { Login }
            '3' { 
					Write-Host "`nProfile list :`n"
					Show-Profiles
					Add-YkIdentity
				}
            '4' { Remove-YkIdentity -UserId (Read-Host 'User ID') }
            '5' { Reset-YkFidoCredentials }
			'6' { Show-Profiles }
			'7' { Add-Profile }
			'8' { Remove-Profile }
			'9' { Show-Credentials }
			'10' { Set-YkFidoPin }
			'11' { Get-YkInfo -SerialNumber $YubiKey.SerialNumber | Format-List }
			'12' { Add-LockCode}
			'13' { Clear-LockCode }
			'14' { Invoke-YkAutoManage -MassManagement }
			'15' { return }
            default { Write-Warning 'Invalid selection.' }
        }
    }
}
