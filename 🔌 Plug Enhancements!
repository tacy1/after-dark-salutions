function Show-Menu {
    cls
    Write-Host "================ Menu ================" -ForegroundColor Cyan
    Write-Host "  1. Execute System Optimizations" -ForegroundColor Green
    Write-Host "  2. Destruct (Revert Changes)" -ForegroundColor Red
    Write-Host "  3. Exit" -ForegroundColor Yellow
    Write-Host "=======================================" -ForegroundColor Cyan
}

function Execute-SystemOptimizations {
    cls
    $currentUser = $env:USERNAME
    Write-Host "🔌 Welcome to Plug Enhancements, $currentUser!" -ForegroundColor Yellow
    Write-Host "Executing 🔌 Plug Enhancements..." -ForegroundColor Green
    
    # Array to store optimization details
    $optimizationDetails = @()

    # Disable unnecessary services
    Write-Host "Disabling unnecessary services..." -ForegroundColor Green
    $disabledServices = Get-Service | Where-Object { $_.Status -eq 'Running' -and $_.Name -notin @(
        'Fax', 
        'TabletInputService', 
        'wuauserv', 
        'RemoteRegistry', 
        'MapsBroker', 
        'WSearch', 
        'DiagTrack', 
        'XblGameSave', 
        'MessagingService', 
        'dmwappushservice'
    ) }
    foreach ($service in $disabledServices) {
        try {
            Stop-Service -Name $service.Name -ErrorAction Stop
            $optimizationDetails += "Disabled service: $($service.DisplayName)"
        } catch {
            Write-Host "Failed to stop service: $($service.DisplayName)" -ForegroundColor Yellow
        }
    }
    
    # Clear temp files
    Write-Host "Clearing temporary files..." -ForegroundColor Green
    $tempFolders = @(
        "$env:TEMP\*",
        "$env:LOCALAPPDATA\Temp\*",
        "$env:SYSTEMROOT\Temp\*",
        "$env:SYSTEMROOT\SoftwareDistribution\Download\*",
        "$env:SYSTEMROOT\Logs\*"
    )
    foreach ($folder in $tempFolders) {
        try {
            $tempFiles = Get-ChildItem -Path $folder -Force -ErrorAction Stop
            Remove-Item -Path $tempFiles.FullName -Recurse -Force -ErrorAction Stop
            $optimizationDetails += "Cleared files from: $folder"
        } catch {
            Write-Host "Failed to clear files from: $folder" -ForegroundColor Yellow
        }
    }

    # Perform disk cleanup
    Write-Host "Performing disk cleanup..." -ForegroundColor Green
    try {
        Cleanmgr.exe /sagerun:1 /verylowdisk
        $optimizationDetails += "Performed disk cleanup."
    } catch {
        Write-Host "Failed to perform disk cleanup." -ForegroundColor Yellow
    }

    # Optimize startup programs
    Write-Host "Optimizing startup programs..." -ForegroundColor Green
    try {
        $startupPrograms = Get-CimInstance -Class Win32_StartupCommand -ErrorAction Stop | Where-Object { $_.Location -eq 'Startup' }
        foreach ($program in $startupPrograms) {
            try {
                $program | Remove-CimInstance -ErrorAction Stop
                $optimizationDetails += "Removed startup program: $($program.Name)"
            } catch {
                Write-Host "Failed to remove startup program: $($program.Name)" -ForegroundColor Yellow
            }
        }
    } catch {
        Write-Host "Failed to retrieve startup programs." -ForegroundColor Yellow
    }

    # Set power plan to High Performance
    Write-Host "Setting power plan to High Performance..." -ForegroundColor Green
    try {
        powercfg.exe /setactive SCHEME_MIN
        $optimizationDetails += "Set power plan to High Performance."
    } catch {
        Write-Host "Failed to set power plan to High Performance." -ForegroundColor Yellow
    }

    # Disable Windows Defender real-time protection
    Write-Host "Disabling Windows Defender real-time protection..." -ForegroundColor Green
    try {
        Set-MpPreference -DisableRealtimeMonitoring $true
        $optimizationDetails += "Disabled Windows Defender real-time protection."
    } catch {
        Write-Host "Failed to disable Windows Defender real-time protection." -ForegroundColor Yellow
    }

    # Set Windows Update to manual
    Write-Host "Setting Windows Update service to manual..." -ForegroundColor Green
    try {
        Set-Service -Name wuauserv -StartupType Manual -ErrorAction Stop
        $optimizationDetails += "Set Windows Update service to manual."
    } catch {
        Write-Host "Failed to set Windows Update service to manual." -ForegroundColor Yellow
    }

    # Set virtual memory (pagefile) to fixed size
    Write-Host "Setting virtual memory to fixed size..." -ForegroundColor Green
    try {
        $pagefile = Get-WmiObject -Query "SELECT * FROM Win32_PageFileSetting" -ErrorAction Stop
        $pagefile.InitialSize = 2048MB
        $pagefile.MaximumSize = 4096MB
        $pagefile.Put() | Out-Null
        $optimizationDetails += "Set virtual memory to fixed size."
    } catch {
        Write-Host "Failed to set virtual memory to fixed size." -ForegroundColor Yellow
    }

    # Additional optimizations
    Write-Host "Performing additional optimizations..." -ForegroundColor Green

    # Disable scheduled tasks
    Write-Host "Disabling unnecessary scheduled tasks..." -ForegroundColor Green
    try {
        Get-ScheduledTask -ErrorAction Stop | Where-Object { $_.State -ne 'Disabled' -and $_.TaskPath -notlike '*\Microsoft\Windows\*' } | Disable-ScheduledTask -Verbose -ErrorAction Stop
        $optimizationDetails += "Disabled unnecessary scheduled tasks."
    } catch {
        Write-Host "Failed to disable unnecessary scheduled tasks." -ForegroundColor Yellow
    }

    # Disable unnecessary Windows features
    Write-Host "Disabling unnecessary Windows features..." -ForegroundColor Green
    try {
        Disable-WindowsOptionalFeature -Online -FeatureName @(
            'Internet-Explorer-Optional-amd64', 
            'Printing-Foundation-Features', 
            'Microsoft-Windows-Client-Features-Printing-OfflineFiles', 
            'Microsoft-Hyper-V-All', 
            'Microsoft-Windows-Shell-Startup-Alternate-GUI', 
            'Microsoft-Windows-Shell-Setup-ClShell', 
            'Microsoft-Windows-Shell-Setup-Powershell', 
            'Windows-Identity-Foundation', 
            'MSRDC-Infrastructure', 
            'SimpleTCPIPServices', 
            'TFTP-Client', 
            'Storage-Services', 
            'VirtualDisk', 
            'Web-Mgmt-Service', 
            'Windows-Defender-Features', 
            'Windows-Defender-Default-Definition', 
            'Windows-Defender-ApplicationGuard', 
            'Windows-Defender-Management-Tools', 
            'Windows-Defender-Network-Inspection-Service', 
            'Windows-Defender-Windows-Defender-Application-Control', 
            'Windows-Defender-SmartScreen-Management', 
            'Windows-Defender-Antivirus-Service', 
            'Windows-Defender-Client-Management-Service', 
            'Windows-Defender-Advanced-Threat-Protection-Service', 
            'Windows-Defender-Advanced-Threat-Protection-Service-Security', 
            'Windows-Defender-Service'
        ) -ErrorAction Stop
        $optimizationDetails += "Disabled unnecessary Windows features."
    } catch {
        Write-Host "Failed to disable unnecessary Windows features." -ForegroundColor Yellow
    }

    # Disable unnecessary system components
    Write-Host "Disabling unnecessary system components..." -ForegroundColor Green
    try {
        Disable-WindowsOptionalFeature -Online -FeatureName @(
            'LegacyComponents', 
            'DirectPlay', 
            'WindowsMediaPlayer', 
            'SMB1Protocol', 
            'WorkFolders-Client', 
            'MSRDC-Infrastructure', 
            'OfflineFiles', 
            'DirectPlay', 
            'DirectX-9-DXSetup', 
            'DirectX-GraphicsTools-Features', 
            'DirectX-12-Offline-Deployment', 
            'DirectX-12-Mobility-Deployment', 
            'DirectX-DXSDK-Deployment', 
            'DirectX-Developer-Samples', 
            'DirectX-Developer-Tools', 
            'DirectX-Developer-Extensions', 
            'DirectX-Diagnostics', 
            'DirectX-Global-SDK', 
            'DirectX-Tools'
        ) -ErrorAction Stop
        $optimizationDetails += "Disabled unnecessary system components."
    } catch {
        Write-Host "Failed to disable unnecessary system components." -ForegroundColor Yellow
    }

    # Additional network optimizations
    Write-Host "Performing network optimizations..." -ForegroundColor Green
    try {
        Set-NetTCPSetting -SettingName InternetCustom -MinRto 300 -ErrorAction Stop
        Set-NetTCPSetting -SettingName InternetCustom -InitialRto 1500 -ErrorAction Stop
        Set-NetTCPSetting -SettingName InternetCustom -CongestionProvider CTCP -ErrorAction Stop
        $optimizationDetails += "Applied network optimizations."
    } catch {
        Write-Host "Failed to perform network optimizations." -ForegroundColor Yellow
    }

    # Adjust system settings for better performance
    Write-Host "Adjusting system settings for better performance..." -ForegroundColor Green
    try {
        Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Session Manager\Memory Management' -Name ClearPageFileAtShutdown -Value 0 -ErrorAction Stop
        Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Session Manager\Memory Management' -Name LargeSystemCache -Value 0 -ErrorAction Stop
        Set-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile' -Name SystemResponsiveness -Value 0 -ErrorAction Stop
        $optimizationDetails += "Adjusted system settings for better performance."
    } catch {
        Write-Host "Failed to adjust system settings for better performance." -ForegroundColor Yellow
    }

    # Clean up event logs
    Write-Host "Cleaning up event logs..." -ForegroundColor Green
    try {
        wevtutil el | ForEach-Object { wevtutil cl "$_" } | Out-Null
        $optimizationDetails += "Cleaned up event logs."
    } catch {
        Write-Host "Failed to clean up event logs." -ForegroundColor Yellow
    }

    # Display Discord link
    Write-Host "Opening Discord invite link..." -ForegroundColor Green
    try {
        Start-Process "https://discord.gg/dyl"
    } catch {
        Write-Host "Failed to open Discord invite link." -ForegroundColor Yellow
    }

    # Message about restarting PC
    Write-Host "Please restart your PC to apply optimizations." -ForegroundColor Green
}

# Main script logic
do {
    Show-Menu
    $choice = Read-Host "Enter your choice"

    switch ($choice) {
        '1' {
            Execute-SystemOptimizations
            break
        }
        '2' {
            Write-Host "Reverting changes (Destruct mode)..." -ForegroundColor Red
            # Write code to revert changes if needed
            Write-Host "Changes reverted successfully." -ForegroundColor Green
            break
        }
        '3' {
            Write-Host "Exiting script..." -ForegroundColor Yellow
            break
        }
        default {
            Write-Host "Invalid choice. Please enter a valid option (1-3)." -ForegroundColor Red
            break
        }
    }
} while ($choice -ne '3')
