#﻿$name = Read-Host -Prompt "Please Enter the ComputerName you want to use."
#$credential = Get-Credential azurestandard.com\admin
$test = Test-path c:\temp
if (!($test)){new-item c:\temp -ItemType Directory}
$mkps = Test-Path c:\ps
if (!($mkps)){new-item c:\ps -ItemType Directory}
#$cred = $credential
$test = Test-Path -Path C:\temp; if (!($test)){mkdir c:\temp}

    (Get-WmiObject -Class Win32_ComputerSystem -Property Name).Name | Out-File C:\temp\info.txt
Add-Content -Path c:\temp\info.txt -Value "Windows Key"
wmic path softwarelicensingservice get OA3xOriginalProductKey | Out-File -FilePath c:\temp\info.txt -Append

Add-Content -Path C:\temp\info.txt -Value "OS INFO"
Get-CimInstance Win32_OperatingSystem | Format-List osarchitecture, name | out-file -FilePath C:\temp\info.txt -Append

Add-Content -Path C:\temp\info.txt -Value "HARD DRIVE SIZE IN GB"
Get-WmiObject Win32_logicaldisk `| Format-Table DeviceId -auto | out-file -FilePath C:\temp\info.txt -Append

Get-WmiObject Win32_LogicalDisk -Filter "DeviceID='C:'" | Select-Object size | Measure-Object size -Sum | % {[Math]::Round(($_.sum / 1GB),2) } | Out-File -FilePath C:\temp\info.txt -Append

Add-Content -Path C:\temp\info.txt -Value "RAM IN GB"
Get-WMIObject -class Win32_PhysicalMemory | Measure-Object -Property capacity -Sum | % {[Math]::Round(($_.sum / 1GB),2)} | Out-File -FilePath C:\temp\info.txt -Append

Add-Content -Path C:\temp\info.txt -Value "PROCESSOR INFO"
gwmi win32_processor | Select-Object -Property manufacturer, maxclockspeed, name | out-File -FilePath C:\temp\info.txt -Append

Add-Content -Path C:\temp\info.txt -Value "NETWORK INFO"
get-wmiobject win32_networkadapter -filter "netconnectionstatus = 2" | Select-Object -Property "name", "macaddress" | out-File -FilePath C:\temp\info.txt -Append

Add-Content -Path C:\temp\info.txt -Value "PC INFO"
Get-CimInstance -ClassName Win32_ComputerSystem | Select-Object -Property "model", "manufacturer" | out-File -FilePath C:\temp\info.txt -Append

Get-Content -Path C:\temp\info.txt

Read-Host -Prompt "Copy the above info and press enter to continue (see c:\temp\info.txt)"

$name | add-content c:\temp\id.txt

Enable-PSRemoting -Force -SkipNetworkProfileCheck
Set-ExecutionPolicy RemoteSigned -Force

New-NetFirewallRule -Name "WINRM-HTTP-In-TCP-PUBLIC" -RemoteAddress Any -DisplayName WINRM-HTTP-In-TCP-PUBLIC




##########
# Privacy Settings
##########

# Disable Telemetry
Write-Host "Disabling Telemetry..."
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0

# Enable Telemetry
# Remove-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry"

# Disable Wi-Fi Sense
Write-Host "Disabling Wi-Fi Sense..."
If (!(Test-Path "HKLM:\Software\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting")) {
	New-Item -Path "HKLM:\Software\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\Software\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" -Name "Value" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\Software\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" -Name "Value" -Type DWord -Value 0

# Enable Wi-Fi Sense
# Set-ItemProperty -Path "HKLM:\Software\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" -Name "Value" -Type DWord -Value 1
# Set-ItemProperty -Path "HKLM:\Software\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" -Name "Value" -Type DWord -Value 1

# Disable SmartScreen Filter
Write-Host "Disabling SmartScreen Filter..."
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name "SmartScreenEnabled" -Type String -Value "Off"
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\AppHost" -Name "EnableWebContentEvaluation" -Type DWord -Value 0

# Enable SmartScreen Filter
# Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name "SmartScreenEnabled" -Type String -Value "RequireAdmin"
# Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\AppHost" -Name "EnableWebContentEvaluation"

# Disable Bing Search in Start Menu
Write-Host "Disabling Bing Search in Start Menu..."
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "BingSearchEnabled" -Type DWord -Value 0

# Enable Bing Search in Start Menu
# Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "BingSearchEnabled"

# Disable Location Tracking
Write-Host "Disabling Location Tracking..."
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" -Name "SensorPermissionState" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\lfsvc\Service\Configuration" -Name "Status" -Type DWord -Value 0

# Enable Location Tracking
# Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" -Name "SensorPermissionState" -Type DWord -Value 1
# Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\lfsvc\Service\Configuration" -Name "Status" -Type DWord -Value 1

# Disable Feedback
Write-Host "Disabling Feedback..."
If (!(Test-Path "HKCU:\Software\Microsoft\Siuf\Rules")) {
	New-Item -Path "HKCU:\Software\Microsoft\Siuf\Rules" -Force | Out-Null
}
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Siuf\Rules" -Name "NumberOfSIUFInPeriod" -Type DWord -Value 0

# Enable Feedback
# Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Siuf\Rules" -Name "NumberOfSIUFInPeriod"

# Disable Advertising ID
Write-Host "Disabling Advertising ID..."
If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo")) {
	New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" | Out-Null
}
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" -Name "Enabled" -Type DWord -Value 0

# Enable Advertising ID
# Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" -Name "Enabled"

# Disable Cortana
Write-Host "Disabling Cortana..."
If (!(Test-Path "HKCU:\Software\Microsoft\Personalization\Settings")) {
	New-Item -Path "HKCU:\Software\Microsoft\Personalization\Settings" -Force | Out-Null
}
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Personalization\Settings" -Name "AcceptedPrivacyPolicy" -Type DWord -Value 0
If (!(Test-Path "HKCU:\Software\Microsoft\InputPersonalization")) {
	New-Item -Path "HKCU:\Software\Microsoft\InputPersonalization" -Force | Out-Null
}
Set-ItemProperty -Path "HKCU:\Software\Microsoft\InputPersonalization" -Name "RestrictImplicitTextCollection" -Type DWord -Value 1
Set-ItemProperty -Path "HKCU:\Software\Microsoft\InputPersonalization" -Name "RestrictImplicitInkCollection" -Type DWord -Value 1
If (!(Test-Path "HKCU:\Software\Microsoft\InputPersonalization\TrainedDataStore")) {
	New-Item -Path "HKCU:\Software\Microsoft\InputPersonalization\TrainedDataStore" -Force | Out-Null
}
Set-ItemProperty -Path "HKCU:\Software\Microsoft\InputPersonalization\TrainedDataStore" -Name "HarvestContacts" -Type DWord -Value 0




# Disable OneDrive
Write-Host "Disabling OneDrive..."
If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive")) {
	New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" -Name "DisableFileSyncNGSC" -Type DWord -Value 1

# Enable OneDrive
# Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" -Name "DisableFileSyncNGSC"

# Uninstall OneDrive (WINDOWS WILL NOT SYSPREP WITHOUT IT!)
# Write-Host "Uninstalling OneDrive..."
# Stop-Process -Name OneDrive -ErrorAction SilentlyContinue
# Start-Sleep -s 3
# $onedrive = "$env:SYSTEMROOT\SysWOW64\OneDriveSetup.exe"
# If (!(Test-Path $onedrive)) {
# 	$onedrive = "$env:SYSTEMROOT\System32\OneDriveSetup.exe"
# }
# Start-Process $onedrive "/uninstall" -NoNewWindow -Wait
# Start-Sleep -s 3
# Stop-Process -Name explorer -ErrorAction SilentlyContinue
# Start-Sleep -s 3
# Remove-Item "$env:USERPROFILE\OneDrive" -Force -Recurse -ErrorAction SilentlyContinue
# Remove-Item "$env:LOCALAPPDATA\Microsoft\OneDrive" -Force -Recurse -ErrorAction SilentlyContinue
# Remove-Item "$env:PROGRAMDATA\Microsoft OneDrive" -Force -Recurse -ErrorAction SilentlyContinue
# If (Test-Path "$env:SYSTEMDRIVE\OneDriveTemp") {
# 	Remove-Item "$env:SYSTEMDRIVE\OneDriveTemp" -Force -Recurse -ErrorAction SilentlyContinue
# }
# If (!(Test-Path "HKCR:")) {
# 	New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT | Out-Null
# }
# Remove-Item -Path "HKCR:\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" -Recurse -ErrorAction SilentlyContinue
# Remove-Item -Path "HKCR:\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" -Recurse -ErrorAction SilentlyContinue

# Install OneDrive
# $onedrive = "$env:SYSTEMROOT\SysWOW64\OneDriveSetup.exe"
# If (!(Test-Path $onedrive)) {
# 	$onedrive = "$env:SYSTEMROOT\System32\OneDriveSetup.exe"
# }
# Start-Process $onedrive -NoNewWindow

# Uninstall default Microsoft applications
Write-Host "Uninstalling default Microsoft applications..."
Get-AppxPackage "Microsoft.3DBuilder" | Remove-AppxPackage
Get-AppxPackage "Microsoft.BingFinance" | Remove-AppxPackage
Get-AppxPackage "Microsoft.BingNews" | Remove-AppxPackage
Get-AppxPackage "Microsoft.BingSports" | Remove-AppxPackage
Get-AppxPackage "Microsoft.BingWeather" | Remove-AppxPackage
Get-AppxPackage "Microsoft.Getstarted" | Remove-AppxPackage
Get-AppxPackage "Microsoft.MicrosoftOfficeHub" | Remove-AppxPackage
Get-AppxPackage "Microsoft.MicrosoftSolitaireCollection" | Remove-AppxPackage
Get-AppxPackage "Microsoft.Office.OneNote" | Remove-AppxPackage
Get-AppxPackage "Microsoft.People" | Remove-AppxPackage
Get-AppxPackage "Microsoft.SkypeApp" | Remove-AppxPackage
Get-AppxPackage "Microsoft.WindowsMaps" | Remove-AppxPackage
Get-AppxPackage "Microsoft.WindowsPhone" | Remove-AppxPackage
Get-AppxPackage "Microsoft.WindowsSoundRecorder" | Remove-AppxPackage
Get-AppxPackage "Microsoft.XboxApp" | Remove-AppxPackage
Get-AppxPackage "Microsoft.ZuneMusic" | Remove-AppxPackage
Get-AppxPackage "Microsoft.ZuneVideo" | Remove-AppxPackage
Get-AppxPackage "Microsoft.AppConnector" | Remove-AppxPackage
Get-AppxPackage "Microsoft.ConnectivityStore" | Remove-AppxPackage
Get-AppxPackage "Microsoft.Office.Sway" | Remove-AppxPackage
Get-AppxPackage "Microsoft.Messaging" | Remove-AppxPackage
Get-AppxPackage "Microsoft.CommsPhone" | Remove-AppxPackage
Get-AppxPackage "9E2F88E3.Twitter" | Remove-AppxPackage
Get-AppxPackage "king.com.CandyCrushSodaSaga" | Remove-AppxPackage
Get-AppxPackage "Microsoft.WindowsFeedbackHub" | Remove-AppxPackage
Get-AppxPackage "Microsoft.Wallet" | Remove-AppxPackage
Get-AppxPackage "Microsoft.ScreenSketch" | Remove-AppxPackage
Get-AppxPackage "Microsoft.GetHelp" | Remove-AppxPackage
Get-AppxPackage "Microsoft.Xbox.TCUI" | Remove-AppxPackage
Get-AppxPackage "Microsoft.XboxGameOverlay" | Remove-AppxPackage
Get-AppxPackage "Microsoft.XboxSpeechToTextOverlay" | Remove-AppxPackage
Get-AppxPackage "Microsoft.MixedReality.Portal" | Remove-AppxPackage
Get-AppBackgroundTask "Microsoft.XboxIdentityProvider" | Remove-AppPackage




iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
choco install foxitreader --ia '/MERGETASKS="!desktopicon,setdefaultreader,displayinbrowser /COMPONENTS=*pdfviewer,*ffse,*installprint,*ffaddin,*ffspellcheck,!connectedpdf"' -fy
cinst 7zip, googlechrome, firefox, jre8, zoom, openvpn, zerotier-one -fy

#$secpasswd = ConvertTo-SecureString '5tJwQq5tH' -AsPlainText -Force
#$credh = New-Object System.Management.Automation.PSCredential ('it', $secpasswd)
#iwr -Credential $credh -Uri http://azurestdownload.com/dl/Forti.exe -UseBasicParsing -OutFile c:\temp\forti.exe

powercfg /change monitor-timeout-ac 25
powercfg /change standby-timeout-ac 300
powercfg /change monitor-timeout-dc 10
powercfg /change standby-timeout-dc 35

Get-AppxPackage -AllUsers *one* | Remove-AppxPackage
Get-AppxPackage -AllUsers *bing* | Remove-AppxPackage
Get-AppxPackage -AllUsers *zune* | Remove-AppxPackage
Get-AppxPackage -AllUsers *soli* | Remove-AppxPackage
Get-AppxPackage -AllUsers *officehub* | Remove-AppxPackage
Get-AppxPackage -AllUsers *skypeapp* | Remove-AppxPackage
Get-AppxPackage -AllUsers *twitter* | Remove-AppxPackage
Get-AppxPackage -AllUsers *candy* | Remove-AppxPackage
Get-AppxPackage -AllUsers *xbox* | Remove-AppxPackage

net user administrator az79709
net user administrator /active:yes

Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.pdf\' -Value Applications\foxitreader.exe -Name foxitreader.exe
Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.htm\' -Value ChromeHTML -Name ChromeHTML
Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.html\' -Value ChromeHTML -Name ChromeHTML

$code = "# Get the ID and security principal of the current user account
$myWindowsID=[System.Security.Principal.WindowsIdentity]::GetCurrent()
$myWindowsPrincipal=new-object System.Security.Principal.WindowsPrincipal($myWindowsID)
$adminRole=[System.Security.Principal.WindowsBuiltInRole]::Administrator
if ($myWindowsPrincipal.IsInRole($adminRole))

   {
   # We are running 'as Administrator' - so change the title and background color to indicate this
   $Host.UI.RawUI.WindowTitle = $myInvocation.MyCommand.Definition + '(Elevated)'
   $Host.UI.RawUI.BackgroundColor = 'DarkBlue'
   clear-host
   }
else
   {
   $newProcess = new-object System.Diagnostics.ProcessStartInfo 'PowerShell';
   $newProcess.Arguments = $myInvocation.MyCommand.Definition;
   $newProcess.Verb = 'runas';
   [System.Diagnostics.Process]::Start($newProcess);
   exit

   }

Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows nt\CurrentVersion\Winlogon' -Name cachedlogonscount -Value 0
Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows nt\CurrentVersion\Winlogon' -Name cachedlogonscount
Write-Host -NoNewLine 'Press any key to continue...'
$null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
"

C:\temp\bootstrap_files\Chronicall_4_2_10e.exe
C:\temp\bootstrap_files\Forti.exe


if(!((Get-WmiObject -Class Win32_ComputerSystem).PartOfDomain)){
	$u = "azurestandard.com\admin"
	$p = convertto-securestring -String "1/2.3,4m1m2,3.4/" -AsPlainText -Force
	$cred = new-object -typename System.Management.Automation.PSCredential -argumentlist $u, $p
	add-computer -domainname azurestandard.com -domaincredential $cred
}



Restart-Computer -Force
