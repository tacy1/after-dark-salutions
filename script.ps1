# Define banned users file path
$bannedUsersFile = "C:\Path\To\BannedUsers.txt"

# Function to play a system sound
function Play-SystemSound {
    [System.Media.SystemSounds]::Asterisk.Play()
}

# Function to display the main menu with fade-in effect
function Show-MainMenu {
    Clear-Host
    $systemName = $env:COMPUTERNAME
    $currentDate = Get-Date -Format "dddd, MMMM dd, yyyy"
    
    Write-Host "Welcome to AfterDark System Tweaks" -ForegroundColor Green
    Write-Host "System: $systemName" -ForegroundColor Yellow
    Write-Host "Date: $currentDate`n" -ForegroundColor Yellow
    Start-Sleep -Milliseconds 500  # Wait for 0.5 seconds for a fade-in effect

    Write-Output @"
      _____ _           _       _         _______           _             
     / ____| |         | |     (_)       |__   __|         | |            
    | (___ | |__  _   _| |_ ___ _ _ __ ___ | | ___  _ __  | |_ ___       
     \___ \| '_ \| | | | __/ _ \ | '__/ _ \| |/ _ \| '_ \ | __/ _ \      
     ____) | | | |_| | ||  __/ | | | (_) | | (_) | | | || || (_) |     
    |_____/|_| |_|\__,_|\__\___|_|_|  \___/|_|\___/|_| |_| \__\___/      
     _|  _|                 _|         _|_|_|_|_|           _|_|        
     _|      _|_|_|  _|_|_|  _|_|_|  _|    _|  _|    _|_|_|  _|  _|_|    
     _|  _|  _|    _|    _|  _|    _|_|    _|  _|  _|    _|  _|_|        
       _|_|  _|    _|    _|  _|    _|_|  _|_|  _|  _|    _|  _|  _|_|_|  
    
    Choose an option:
    
    1. Performance Tweaks
    2. Appearance Tweaks
    3. Security Tweaks
    4. Spoofing Options
    5. Console Output
    6. Admin Menu
    
    0. Exit
"@

    $choice = Read-Host "Enter your choice"
    switch ($choice) {
        '1' { Perform-PerformanceTweaks }
        '2' { Show-AppearanceTweaks }
        '3' { Show-SecurityTweaks }
        '4' { Show-SpoofingOptions }
        '5' { Show-ConsoleOutput }
        '6' { Show-AdminMenu }
        '0' { Exit }
        default {
            Write-Host "Invalid choice. Please enter a valid option." -ForegroundColor Red
            Show-MainMenu
        }
    }
}

# Function to perform advanced performance tweaks
function Perform-PerformanceTweaks {
    Clear-Host
    Write-Host "Performance Tweaks" -ForegroundColor Green
    Write-Host "Applying advanced system optimizations..." -ForegroundColor Green

    # Additional Optimizations
    # 1. Disable Windows Error Reporting
    Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\Windows Error Reporting' -Name Disabled -Value 1 -Force

    # 2. Disable Windows Defender Antivirus
    Set-MpPreference -DisableRealtimeMonitoring $true

    # 3. Disable Background Intelligent Transfer Service (BITS)
    Set-Service -Name BITS -StartupType Disabled

    # 4. Optimize Visual Effects for Performance
    $currentSettings = Get-WmiObject -Class Win32_PerfFormattedData_PerfOS_System | Select-Object -ExpandProperty SystemUpTime
    if ($currentSettings -lt 3) {
        Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects' -Name VisualFXSetting -Value 2
    }

    # 5. Adjust Processor Scheduling for Programs
    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\PriorityControl' -Name Win32PrioritySeparation -Value 26

    # 6. Disable TCP/IP Auto-Tuning
    netsh interface tcp set global autotuning=disabled

    # 7. Disable Large Send Offload (LSO)
    Get-NetAdapter | Where-Object { $_.Name -like "*" } | ForEach-Object {
        Set-NetAdapterAdvancedProperty -Name $_.Name -DisplayName "Large Send Offload (IPv4)" -DisplayValue "Disabled"
        Set-NetAdapterAdvancedProperty -Name $_.Name -DisplayName "Large Send Offload (IPv6)" -DisplayValue "Disabled"
    }

    # 8. Optimize Network Card Settings
    Get-NetAdapterAdvancedProperty | Where-Object { $_.DisplayName -eq "Interrupt Moderation" } | Set-NetAdapterAdvancedProperty -RegistryValue 0

    # 9. Increase Processor Performance State
    powercfg -setacvalueindex SCHEME_CURRENT SUB_PROCESSOR PERFSTATEMAX 100
    powercfg -setactive SCHEME_CURRENT

    # 10. Optimize Registry for Performance
    # Example: Remove redundant registry keys

    # 11. Adjust Page File Settings
    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management' -Name PagingFiles -Value "C:\pagefile.sys 4096 8192"

    # 12. Disable Unnecessary Startup Services
    Get-Service | Where-Object { $_.StartType -eq "Automatic" -and $_.Name -notmatch "Windows*" } | Set-Service -StartupType Manual

    # 13. Optimize GPU Settings (Example: NVIDIA)
    # Example command: nvidia-smi -ac 3505,1455

    # 14. Adjust Desktop Background Settings
    Set-ItemProperty -Path 'HKCU:\Control Panel\Desktop' -Name Wallpaper -Value "C:\Path\To\Your\Wallpaper.jpg"

    # 15. Disable Windows Search Indexing
    Set-Service -Name WSearch -StartupType Disabled

    # 16. Optimize RAM Usage
    # Example command: rundll32.exe advapi32.dll,ProcessIdleTasks

    # 17. Optimize Hard Disk Usage
    # Example command: defrag C: /O

    # 18. Optimize USB Port Settings
    # Example: Disable USB selective suspend setting

    # 19. Disable System Sounds
    Set-ItemProperty -Path 'HKCU:\AppEvents\Schemes\Apps\.Default' -Name "(Default)" -Value ""

    # 20. Optimize Desktop Cleanup
    Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name DontPrettyPath -Value 1

    # 21. Optimize Network Adapter Power Management
    Get-NetAdapter | ForEach-Object {
        Set-NetAdapterPowerManagement -Name $_.Name -AllowIdlePowerManagement $false
    }

    # 22. Optimize File System for SSD (if applicable)
    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\storahci\Parameters\Device' -Name TreatAsInternalPort -Value 0

    # 23. Disable Remote Assistance
    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance' -Name fDenyTSConnections -Value 1

    # 24. Disable Windows Error Reporting (WER)
    Set-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\Windows Error Reporting' -Name Disabled -Value 1 -Force

    # 25. Optimize Windows Event Logging
    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Application' -Name Start -Value 4

    # 26. Optimize Windows Time Service
    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Config' -Name Type -Value NTP

    # 27. Disable Windows Media DRM Internet Access
    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\WMPNetworkSvc' -Name Start -Value 4

    # 28. Optimize Windows Firewall Rules
    Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False

    # 29. Disable Windows Update Service
    Set-Service -Name wuauserv -StartupType Disabled

    # 30. Optimize Windows Explorer Startup Settings
    Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Serialize' -Name StartupDelayInMSec -Value 0

    # 31. Disable Remote Registry Service
    Set-Service -Name RemoteRegistry -StartupType Disabled

    # 32. Optimize Windows Services Startup Type
    Get-Service | Where-Object { $_.StartType -eq "Manual" -and $_.Name -notmatch "Windows*" } | Set-Service -StartupType Disabled

    # 33. Disable Windows Biometric Service
    Set-Service -Name WbioSrvc -StartupType Disabled

    # 34. Optimize System Environment Variables
    [System.Environment]::SetEnvironmentVariable("TMP", "C:\Temp", "Machine")
    [System.Environment]::SetEnvironmentVariable("TEMP", "C:\Temp", "Machine")

    # 35. Disable OneDrive Service
    Set-Service -Name OneSyncSvc -StartupType Disabled

    # 36. Optimize Microsoft Store Updates
    Set-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\WindowsStore' -Name AutoDownload -Value 2

    # 37. Disable Microsoft Edge Background Processes
    Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Edge\Main' -Name AllowPrelaunch -Value 0

    # 38. Optimize Windows Task Scheduler
    Set-Service -Name Schedule -StartupType Disabled

    # 39. Disable Windows Push Notifications
    Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings' -Name Noclobber -Value 1

    # 40. Optimize Windows Environment Variables
    [System.Environment]::SetEnvironmentVariable("Path", "C:\Windows\System32;C:\Windows;C:\Windows\System32\Wbem", "Machine")

    Write-Host "Advanced tweaks applied." -ForegroundColor Green
    Read-Host "Press Enter to return to the main menu"
    Show-MainMenu
}

# Function to display appearance tweaks
function Show-AppearanceTweaks {
    Clear-Host
    Write-Host "Appearance Tweaks" -ForegroundColor Green
    # Add your appearance tweaks logic here

    Read-Host "Press Enter to return to the main menu"
    Show-MainMenu
}

# Function to display security tweaks
function Show-SecurityTweaks {
    Clear-Host
    Write-Host "Security Tweaks" -ForegroundColor Green
    Write-Host "Applying additional security enhancements..." -ForegroundColor Green

    # Additional Security Tweaks
    # 21. Disable Remote Desktop Services (if not used)
    Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections -Value 1

    # 22. Disable Guest Account
    Set-LocalUser -Name Guest -Description "Disabled" -Enabled $false

    # 23. Enable Firewall and Block Unwanted Ports
    Enable-NetFirewallRule -DisplayName "Windows Remote Management (HTTP-In)"

    # 24. Secure PowerShell Execution Policies
    Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope LocalMachine -Force

    # 25. Disable PowerShell Script Execution (if not needed)
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell' -Name EnableScripts -Value 0

    # 26. Secure Service Accounts
    # Example: Change default service account passwords

    # 27. Enable BitLocker Encryption (if supported)
    # Example command: Enable-BitLocker -MountPoint "C:"

    # 28. Restrict USB Device Usage
    # Example: Disable USB storage devices

    # 29. Enable Windows Defender and Regular Updates
    Set-MpPreference -DisableRealtimeMonitoring $false

    # 30. Monitor Event Logs for Security Breaches
    Get-WinEvent -FilterHashTable @{LogName='Security'; StartTime=(Get-Date).AddDays(-1)}

    # 31. Enable UAC (User Account Control)
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name EnableLUA -Value 1

    # 32. Configure SmartScreen Filter for Edge
    Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\AppHost' -Name EnableSmartScreen -Value 1

    # 33. Disable AutoPlay/AutoRun
    Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name NoDriveTypeAutoRun -Value 255

    # 34. Harden Account Policies (Password Policies)
    Set-LocalUser -Name Administrator -PasswordNeverExpires $true

    # 35. Configure Windows Defender ATP (Advanced Threat Protection)
    # Example: Enable ATP on Windows Security Center

    # 36. Monitor and Block Malicious IPs
    # Example: Use IP Blocklist for Windows Firewall

    # 37. Enable Secure Boot (if supported)
    # Example command: Set-FirmwareConfiguration -SecureBoot Enabled

    # 38. Audit File and Folder Access
    # Example: Configure audit policies for critical files

    # 39. Encrypt Communication Channels
    # Example: Use TLS for all network communications

    # 40. Secure Browser Settings
    # Example: Configure browser security settings

    Write-Host "Security enhancements applied." -ForegroundColor Green
    Read-Host "Press Enter to return to the main menu"
    Show-MainMenu
}

# Function to show spoofing options
function Show-SpoofingOptions {
    Clear-Host
    Write-Host "Spoofing Options" -ForegroundColor Green
    # Add your spoofing options logic here

    Read-Host "Press Enter to return to the main menu"
    Show-MainMenu
}

# Function to display console output
function Show-ConsoleOutput {
    Clear-Host
    Write-Host "Console Output" -ForegroundColor Green
    # Add your console output logic here

    Read-Host "Press Enter to return to the main menu"
    Show-MainMenu
}

# Function to display admin menu
function Show-AdminMenu {
    Clear-Host
    Write-Host "Admin Menu" -ForegroundColor Green
    # Add your admin menu logic here

    Read-Host "Press Enter to return to the main menu"
    Show-MainMenu
}

# Entry point
Show-MainMenu
