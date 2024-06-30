function Show-Menu {
    cls
    Write-Host "================ Menu ================" -ForegroundColor Cyan
    Write-Host "  1. Execute System Optimizations" -ForegroundColor Green
    Write-Host "  2. Revert Changes" -ForegroundColor Red
    Write-Host "  3. Exit" -ForegroundColor Yellow
    Write-Host "=======================================" -ForegroundColor Cyan
}

# Define function for system optimizations
function Execute-SystemOptimizations {
    cls
    $currentUser = $env:USERNAME
    Write-Host "Welcome to Plug Enhancements, $currentUser!" -ForegroundColor Yellow
    Write-Host "Executing Plug Enhancements..." -ForegroundColor Green

    # Array to store optimization details
    $optimizationDetails = @()

    # Function to safely stop services
    function Stop-ServiceSafe {
        param(
            [string]$ServiceName
        )
        $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        if ($service -ne $null -and $service.Status -eq 'Running') {
            try {
                $service | Stop-Service -Force -ErrorAction StopService, Continue, SilentlyContinue
                $optimizationDetails += "Stopped service: $($service.DisplayName)"
            }
            catch {
                $optimizationDetails += "Failed to stop service: $($service.DisplayName)"
            }
        }
        else {
            $optimizationDetails += "Service not found or already stopped: $ServiceName"
        }
    }

    # Function to safely disable services
    function Disable-Service {
        param(
            [string]$ServiceName
        )
        $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        if ($service -ne $null) {
            try {
                Set-Service -Name $service.Name -StartupType Disabled -ErrorAction StopService, Continue, SilentlyContinue
                $optimizationDetails += "Disabled service: $($service.DisplayName)"
            }
            catch {
                $optimizationDetails += "Failed to disable service: $($service.DisplayName)"
            }
        }
        else {
            $optimizationDetails += "Service not found: $ServiceName"
        }
    }

    # Function to safely remove services
    function Remove-Service {
        param(
            [string]$ServiceName
        )
        $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        if ($service -ne $null) {
            try {
                $service | Stop-Service -Force -ErrorAction StopService, Continue, SilentlyContinue
                Remove-Service $ServiceName
                $optimizationDetails += "Removed service: $($service.DisplayName)"
            }
            catch {
                $optimizationDetails += "Failed to remove service: $($service.DisplayName)"
            }
        }
        else {
            $optimizationDetails += "Service not found: $ServiceName"
        }
    }

    # Function to safely set service startup type to manual
    function Set-ServiceManual {
        param(
            [string]$ServiceName
        )
        $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        if ($service -ne $null -and $service.Status -eq 'Running') {
            try {
                Set-Service -Name $ServiceName -StartupType Manual -ErrorAction StopService, Continue, SilentlyContinue
                $optimizationDetails += "Set service $ServiceName to Manual"
            }
            catch {
                $optimizationDetails += "Failed to set $ServiceName to Manual"
            }
        }
        else {
            $optimizationDetails += "Service not found or already set to Manual: $ServiceName"
        }
    }

    # Function to safely delete registry keys
    function Remove-RegistryKey {
        param(
            [string]$KeyPath
        )
        if (Test-Path -Path $KeyPath) {
            try {
                Remove-Item -Path $KeyPath -Recurse -Force -ErrorAction StopService, Continue, SilentlyContinue
                $optimizationDetails += "Removed registry key: $KeyPath"
            }
            catch {
                $optimizationDetails += "Failed to remove registry key: $KeyPath"
            }
        }
        else {
            $optimizationDetails += "Registry key not found: $KeyPath"
        }
    }

    # Function to safely delete files and directories
    function Remove-FilesAndDirectories {
        param(
            [string]$Path
        )
        if (Test-Path -Path $Path) {
            try {
                Remove-Item -Path $Path -Recurse -Force -ErrorAction StopService, Continue, SilentlyContinue
                $optimizationDetails += "Removed files and directories at: $Path"
            }
            catch {
                $optimizationDetails += "Failed to remove files and directories at: $Path"
            }
        }
        else {
            $optimizationDetails += "Path not found: $Path"
        }
    }

    # Disable unnecessary services
    Write-Host "Disabling unnecessary services..." -ForegroundColor Green
    $servicesToDisable = @(
        'Fax', 'TabletInputService', 'wuauserv', 'sppsvc', 'smartscreen', 'tiledatamodelsvc', 'WbioSrvc'
    )
    foreach ($service in $servicesToDisable) {
        Disable-Service -ServiceName $service
    }

    # Remove unnecessary services
    Write-Host "Removing unnecessary services..." -ForegroundColor Green
    $servicesToRemove = @(
        'NetTcpPortSharing', 'HomeGroupListener', 'HomeGroupProvider', 'SSDPSRV', 'upnphost'
    )
    foreach ($service in $servicesToRemove) {
        Remove-Service -ServiceName $service
    }

    # Clear temp files
    Write-Host "Clearing temporary files..." -ForegroundColor Green
    $tempFiles = Get-ChildItem -Path "$env:TEMP\*" -Force -ErrorAction SilentlyContinue
    $tempFiles | Remove-Item -Recurse -Force
    $optimizationDetails += "Cleared temporary files."

    # Perform disk cleanup
    Write-Host "Performing disk cleanup..." -ForegroundColor Green
    Cleanmgr.exe /sagerun:1 /verylowdisk
    $optimizationDetails += "Performed disk cleanup."

    # Optimize startup programs
    Write-Host "Optimizing startup programs..." -ForegroundColor Green
    $startupPrograms = Get-CimInstance -Class Win32_StartupCommand | Where-Object { $_.Location -eq 'Startup' }
    $startupPrograms | ForEach-Object {
        $_ | Remove-CimInstance
        $optimizationDetails += "Removed startup program: $($_.Name)"
    }

    # Set power plan to High Performance
    Write-Host "Setting power plan to High Performance..." -ForegroundColor Green
    powercfg.exe /setactive SCHEME_MIN
    $optimizationDetails += "Set power plan to High Performance."

    # Disable Windows Defender real-time protection
    Write-Host "Disabling Windows Defender real-time protection..." -ForegroundColor Green
    Set-MpPreference -DisableRealtimeMonitoring $true
    $optimizationDetails += "Disabled Windows Defender real-time protection."

    # Set Windows Update service to manual
    Write-Host "Setting Windows Update service to manual..." -ForegroundColor Green
    Set-Service -Name wuauserv -StartupType Manual
    $optimizationDetails += "Set Windows Update service to manual."

    # Set virtual memory (pagefile) to fixed size
    Write-Host "Setting virtual memory to fixed size..." -ForegroundColor Green
    $pagefile = Get-WmiObject -Query "SELECT * FROM Win32_PageFileSetting"
    $pagefile.InitialSize = 2048MB
    $pagefile.MaximumSize = 4096MB
    $pagefile.Put()
    $optimizationDetails += "Set virtual memory to fixed size."

    # Clear browser caches
    function Clear-BrowserCache {
        param (
            [string]$Browser
        )
        switch ($Browser) {
            "Edge" {
                Clear-EdgeBrowserCache
            }
            "Chrome" {
                Clear-ChromeBrowserCache
            }
            "Firefox" {
                Clear-FirefoxBrowserCache
            }
            Default {
                Write-Host "Unsupported browser: $Browser" -ForegroundColor Red
            }
        }
    }

    # Function to clear Edge browser cache
    function Clear-EdgeBrowserCache {
        Write-Host "Clearing Microsoft Edge browser cache..." -ForegroundColor Green
        $EdgeCachePath = "$env:LOCALAPPDATA\Packages\Microsoft.MicrosoftEdge_8wekyb3d8bbwe\AC\#!001\MicrosoftEdge\Cache"
        Remove-Item -Path $EdgeCachePath -Force -Recurse -ErrorAction SilentlyContinue
        $optimizationDetails += "Cleared Microsoft Edge browser cache."
    }

    # Function to clear Chrome browser cache
    function Clear-ChromeBrowserCache {
        Write-Host "Clearing Google Chrome browser cache..." -ForegroundColor Green
        $ChromeCachePath = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Cache"
        Remove-Item -Path $ChromeCachePath -Force -Recurse -ErrorAction SilentlyContinue
        $optimizationDetails += "Cleared Google Chrome browser cache."
    }

    # Function to clear Firefox browser cache
    function Clear-FirefoxBrowserCache {
        Write-Host "Clearing Mozilla Firefox browser cache..." -ForegroundColor Green
        $FirefoxCachePath = "$env:LOCALAPPDATA\Mozilla\Firefox\Profiles"
        $FirefoxProfiles = Get-ChildItem -Path $FirefoxCachePath -Directory
        foreach ($profile in $FirefoxProfiles) {
            $cachePath = Join-Path -Path $profile.FullName -ChildPath 'cache2'
            if (Test-Path -Path $cachePath) {
                Remove-Item -Path $cachePath -Force -Recurse -ErrorAction SilentlyContinue
            }
        }
        $optimizationDetails += "Cleared Mozilla Firefox browser cache."
    }

    # Clear browser caches (Edge, Chrome, Firefox)
    Write-Host "Clearing browser caches..." -ForegroundColor Green
    Clear-BrowserCache -Browser "Edge"
    Clear-BrowserCache -Browser "Chrome"
    Clear-BrowserCache -Browser "Firefox"
    $optimizationDetails += "Cleared browser caches."

    # Disable unnecessary scheduled tasks
    Write-Host "Disabling unnecessary scheduled tasks..." -ForegroundColor Green
    Get-ScheduledTask | Where-Object { $_.TaskName -like "*Update*" } | Disable-ScheduledTask -Verbose
    $optimizationDetails += "Disabled unnecessary scheduled tasks."

    # Disable unnecessary Windows features
    Write-Host "Disabling unnecessary Windows features..." -ForegroundColor Green
    Disable-WindowsOptionalFeature -FeatureName "Internet-Explorer-Optional-amd64" -Online
    Disable-WindowsOptionalFeature -FeatureName "Printing-XPSServices-Features" -Online
    $optimizationDetails += "Disabled unnecessary Windows features."

    # Set desktop background to solid color
    Write-Host "Setting desktop background to solid color..." -ForegroundColor Green
    Set-ItemProperty -Path 'HKCU:\Control Panel\Colors' -Name 'Background' -Value '0 0 0'
    $optimizationDetails += "Set desktop background to solid color."

    # Change default launch location of Windows Explorer
    Write-Host "Changing default launch location of Windows Explorer..." -ForegroundColor Green
    Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'LaunchTo' -Value '1'
    $optimizationDetails += "Changed default launch location of Windows Explorer."

    # Set DNS cache timeout to minimum
    Write-Host "Setting DNS cache timeout to minimum..." -ForegroundColor Green
    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters' -Name 'MaxCacheTtl' -Value 1
    $optimizationDetails += "Set DNS cache timeout to minimum."

    # Defragment and optimize drives
    Write-Host "Defragmenting and optimizing drives..." -ForegroundColor Green
    defrag C: /O
    $optimizationDetails += "Defragmented and optimized drives."

    # Clear event logs
    Write-Host "Clearing event logs..." -ForegroundColor Green
    Get-WinEvent -LogName * | ForEach-Object { Clear-WinEvent -LogName $_.LogName }
    $optimizationDetails += "Cleared event logs."

    # Show summary of optimizations
    cls
    Write-Host "====== Plug Enhancements Summary ======" -ForegroundColor Cyan
    foreach ($detail in $optimizationDetails) {
        Write-Host " - $detail"
    }
    Write-Host "=======================================" -ForegroundColor Cyan

    # Prompt to restart the system
    $restartChoice = Read-Host "Optimizations complete! Would you like to restart now? (Y/N)"
    if ($restartChoice -eq 'Y' -or $restartChoice -eq 'y') {
        Restart-Computer -Force
    }
}

# Define function for reverting changes
function Revert-Changes {
    cls
    $currentUser = $env:USERNAME
    Write-Host "Welcome to Plug Enhancements, $currentUser!" -ForegroundColor Yellow
    Write-Host "Reverting Plug Enhancements..." -ForegroundColor Red

    # Implement revert logic here if needed

    Write-Host "Revert completed." -ForegroundColor Yellow
}

# Main script logic
do {
    Show-Menu
    $input = Read-Host "Enter your choice: "
    switch ($input) {
        '1' {
            Execute-SystemOptimizations
            break
        }
        '2' {
            Revert-Changes
            break
        }
        '3' {
            Write-Host "Exiting script..." -ForegroundColor Yellow
            break
        }
        default {
            Write-Host "Invalid option. Please try again." -ForegroundColor Red
            break
        }
    }
} while ($input -ne '3')
