# Check if running as Administrator
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "Error: This script requires administrative privileges. Please run PowerShell as Administrator." -ForegroundColor Red
    exit 1
}

# Function to take ownership of a registry key
function Take-RegistryOwnership {
    param (
        [string]$RegPath
    )
    try {
        $regKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($RegPath, [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree, [System.Security.AccessControl.RegistryRights]::TakeOwnership)
        $acl = $regKey.GetAccessControl()
        $admin = New-Object System.Security.Principal.NTAccount("Administrators")
        $acl.SetOwner($admin)
        $regKey.SetAccessControl($acl)

        # Grant Full Control to Administrators
        $rule = New-Object System.Security.AccessControl.RegistryAccessRule($admin, "FullControl", "Allow")
        $acl.AddAccessRule($rule)
        $regKey.SetAccessControl($acl)
        Write-Host "Ownership and Full Control granted for $RegPath" -ForegroundColor Green
    } catch {
        Write-Host "Failed to take ownership of $RegPath. Error: $_" -ForegroundColor Red
    } finally {
        if ($regKey) { $regKey.Close() }
    }
}

# Function to enable Echo Cancellation and Noise Suppression for all audio devices
function Enable-AECAndNoiseSuppression {
    $renderDevicesKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\MMDevices\Audio\Render"

    # Get all audio devices under the Render key
    $audioDevices = Get-ChildItem -Path $renderDevicesKey

    foreach ($device in $audioDevices) {
        $fxPropertiesKey = "$($device.PSPath)\FxProperties"

        # Check if the FxProperties key exists, if not, create it
        if (!(Test-Path $fxPropertiesKey)) {
            New-Item -Path $fxPropertiesKey -Force
            Write-Host "Created FxProperties key for device: $($device.PSChildName)" -ForegroundColor Green
        }

        # Take ownership and set permissions for the FxProperties key
        Take-RegistryOwnership -RegPath ($fxPropertiesKey -replace 'HKEY_LOCAL_MACHINE\\', '')

        # Define the keys and values for AEC and Noise Suppression
        $aecKey = "{1c7b1faf-caa2-451b-b0a4-87b19a93556a},6"
        $noiseSuppressionKey = "{e0f158e1-cb04-43d5-b6cc-3eb27e4db2a1},3"
        $enableValue = 1  # 1 = Enable, 0 = Disable

        # Set Acoustic Echo Cancellation (AEC)
        $currentAECValue = Get-ItemProperty -Path $fxPropertiesKey -Name $aecKey -ErrorAction SilentlyContinue
        if ($currentAECValue.$aecKey -ne $enableValue) {
            try {
                Set-ItemProperty -Path $fxPropertiesKey -Name $aecKey -Value $enableValue -ErrorAction Stop
                Write-Host "Acoustic Echo Cancellation set to enabled for device: $($device.PSChildName)" -ForegroundColor Yellow
            } catch {
                Write-Host "Failed to set Acoustic Echo Cancellation for device: $($device.PSChildName). Error: $_" -ForegroundColor Red
            }
        } else {
            Write-Host "Acoustic Echo Cancellation already enabled for device: $($device.PSChildName)" -ForegroundColor Cyan
        }

        # Set Noise Suppression
        $currentNoiseSuppressionValue = Get-ItemProperty -Path $fxPropertiesKey -Name $noiseSuppressionKey -ErrorAction SilentlyContinue
        if ($currentNoiseSuppressionValue.$noiseSuppressionKey -ne $enableValue) {
            try {
                Set-ItemProperty -Path $fxPropertiesKey -Name $noiseSuppressionKey -Value $enableValue -ErrorAction Stop
                Write-Host "Noise Suppression set to enabled for device: $($device.PSChildName)" -ForegroundColor Yellow
            } catch {
                Write-Host "Failed to set Noise Suppression for device: $($device.PSChildName). Error: $_" -ForegroundColor Red
            }
        } else {
            Write-Host "Noise Suppression already enabled for device: $($device.PSChildName)" -ForegroundColor Cyan
        }
    }
}

# Run the function
Enable-AECAndNoiseSuppression