# ========== Configuration ==========
$searchRoot = "C:\Windows\System32\DriverStore\FileRepository"
$dllName = "nvxdapix.dll"
$replacementDll = "$HOME\Desktop\nvxdapix.dll"  # Path to the patched DLL
$logFile = "$HOME\dll_replacement_log.txt"
# ===================================

# Search for the DLL
Write-Host "Searching for $dllName in $searchRoot..."
$dllPath = Get-ChildItem -Path $searchRoot -Recurse -Filter $dllName -ErrorAction SilentlyContinue | Select-Object -First 1

# Kill the NV service before attempting to replace the DLL
Stop-Service NVDisplay.ContainerLocalSystem

if ($dllPath) {
    $fullPath = $dllPath.FullName
    Write-Host "Found DLL: $fullPath"
    Add-Content -Path $logFile -Value "Found $dllName at: $fullPath"

    # Take ownership
    takeown /F $fullPath | Out-Null

    # Find "Admin Group" to support all locales e.g. "EN: administrators", "DE: Administratoren", ...
    $adminGroup = ([System.Security.Principal.SecurityIdentifier] "S-1-5-32-544").Translate([System.Security.Principal.NTAccount]).Value
    $adminGroupName = $adminGroup.Split('\')[1]

    # Grant full control to administrators
    $permission = "$adminGroupName`:F"
    icacls $fullPath /grant  $permission | Out-Null

    # Attempt to stop processes using the DLL (optional: may not apply to DriverStore)
    Get-Process | Where-Object {
        $_.Modules | Where-Object { $_.FileName -eq $fullPath }
    } | ForEach-Object {
        Write-Host "Stopping process: $($_.Name) (PID: $($_.Id))"
        Stop-Process -Id $_.Id -Force
    }

    # Replace the DLL
    Copy-Item -Path $replacementDll -Destination $fullPath -Force
    Write-Host "Replaced $dllName successfully."
    Add-Content -Path $logFile -Value "Replaced $dllName at $fullPath on $(Get-Date)"
} else {
    Write-Host "DLL not found."
    Add-Content -Path $logFile -Value "Failed to find $dllName in $searchRoot on $(Get-Date)"
}

# Start the service after the replacement
Start-Service NVDisplay.ContainerLocalSystem