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
    [Environment]::SetEnvironmentVariable("TEMP", "C:\Temp", "Machine")

    # 35. Disable File and Printer Sharing
    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name AutoShareWks -Value 0

    Write-Host "Performance tweaks applied successfully." -ForegroundColor Green
    Pause
    Show-MainMenu
}

# Function to show appearance tweaks menu
function Show-AppearanceTweaks {
    Clear-Host
    Write-Host "Appearance Tweaks" -ForegroundColor Green

    # Add your appearance tweaks options here
    # Example:
    # Write-Host "1. Change Theme"
    # Write-Host "2. Adjust Font Size"
    # Write-Host "3. Change Desktop Background"
    # Write-Host "4. Adjust Color Settings"

    Pause
    Show-MainMenu
}

# Function to show security tweaks menu
function Show-SecurityTweaks {
    Clear-Host
    Write-Host "Security Tweaks" -ForegroundColor Green

    # Add your security tweaks options here
    # Example:
    # Write-Host "1. Enable Firewall"
    # Write-Host "2. Disable Guest Account"
    # Write-Host "3. Enable BitLocker"
    # Write-Host "4. Enable Windows Defender"

    Pause
    Show-MainMenu
}

# Function to show spoofing options menu
function Show-SpoofingOptions {
    Clear-Host
    Write-Host "Spoofing Options" -ForegroundColor Green

    # Add your spoofing options here
    # Example:
    # Write-Host "1. Spoof MAC Address"
    # Write-Host "2. Spoof IP Address"
    # Write-Host "3. Spoof Device ID"

    Pause
    Show-MainMenu
}

# Function to show console output
function Show-ConsoleOutput {
    Clear-Host
    Write-Host "Console Output" -ForegroundColor Green

    # Add your console output options here
    # Example:
    # Write-Host "1. View System Logs"
    # Write-Host "2. View Performance Metrics"
    # Write-Host "3. View Network Traffic"

    Pause
    Show-MainMenu
}

# Function to show admin menu
function Show-AdminMenu {
    Clear-Host
    Write-Host "Admin Menu" -ForegroundColor Green

    # Add your admin menu options here
    # Example:
    # Write-Host "1. Manage Users"
    # Write-Host "2. Manage Services"
    # Write-Host "3. Backup System"

    Pause
    Show-MainMenu
}

# Function to handle user input pause
function Pause {
    Write-Host "`nPress any key to continue..."
    $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
}

# Function to handle banned users
function Handle-BannedUsers {
    param (
        [string]$userName
    )

    if ($userName -eq "BannedUser") {
        Write-Host "User $userName is banned from using this system." -ForegroundColor Red
        Pause
        Show-MainMenu
    } else {
        Write-Host "Welcome, $userName!" -ForegroundColor Green
        Start-Sleep -Seconds 1
        Show-MainMenu
    }
}

# Main execution starts here
Clear-Host
Write-Host "Enter your username:"
$userName = Read-Host

# Check if user is banned
$users = Get-Content $bannedUsersFile -ErrorAction SilentlyContinue
if ($users -contains $userName) {
    Handle-BannedUsers -userName $userName
} else {
    Write-Host "Validating credentials..." -ForegroundColor Yellow
    Start-Sleep -Seconds 2  # Simulate authentication process

    Write-Host "Welcome, $userName!" -ForegroundColor Green
    Start-Sleep -Seconds 1
    Show-MainMenu
}
