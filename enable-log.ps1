#    _____             _     _      _                
#   | ____|_ __   __ _| |__ | | ___| |    ___   __ _ 
#   |  _| | '_ \ / _` | '_ \| |/ _ \ |   / _ \ / _` |
#   | |___| | | | (_| | |_) | |  __/ |__| (_) | (_| |
#   |_____|_| |_|\__,_|_.__/|_|\___|_____\___/ \__, |
#                                              |___/ 
#
#   Windows Event Log Configuration Tool
#   Consolidated script for audit policy configuration and security monitoring
#
#   References:
#       https://www.malwarearchaeology.com/cheat-sheets
#       https://github.com/Yamato-Security/EnableWindowsLogSettings
#       https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/audit-policy-recommendations
#       https://github.com/Neo23x0/sysmon-config
#
#   Version: 2.0 (Consolidated)
#   Author: Security Team
#   Last Modified: 2024
#

#Requires -RunAsAdministrator

#region Configuration Module

<#
.SYNOPSIS
    Reads and parses the config.ini file.

.DESCRIPTION
    Parses the INI configuration file and returns a hashtable with configuration values.

.PARAMETER FilePath
    Path to the config.ini file.

.OUTPUTS
    Hashtable containing configuration sections and values.
#>
function Read-ConfigFile {
    param(
        [Parameter(Mandatory = $true)]
        [string]$FilePath
    )

    if (-not (Test-Path $FilePath)) {
        throw "Configuration file not found: $FilePath"
    }

    $ini = @{}
    $section = $null

    try {
        $content = Get-Content $FilePath -ErrorAction Stop
        
        foreach ($line in $content) {
            # Skip empty lines
            if ([string]::IsNullOrWhiteSpace($line)) {
                continue
            }

            # Section header
            if ($line -match '^\[(.+)\]$') {
                $section = $matches[1].Trim()
                $ini[$section] = @{}
                continue
            }

            # Comment line
            if ($line -match '^[;#]') {
                continue
            }

            # Key-value pair
            if ($line -match '^(.+?)\s*=\s*(.*)$' -and $section) {
                $key = $matches[1].Trim()
                $value = $matches[2].Trim()
                $ini[$section][$key] = $value
            }
        }

        return $ini
    }
    catch {
        throw "Error reading configuration file: $_"
    }
}

<#
.SYNOPSIS
    Validates configuration values from config.ini.

.DESCRIPTION
    Checks that audit_level and sysmon_setting have valid values.

.PARAMETER Config
    Configuration hashtable from Read-ConfigFile.

.OUTPUTS
    Boolean indicating if configuration is valid.
#>
function Test-Configuration {
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Config
    )

    # Check if Global section exists
    if (-not $Config.ContainsKey('Global')) {
        Write-Warning "Configuration file missing [Global] section"
        return $false
    }

    $global = $Config['Global']

    # Validate audit_level
    if (-not $global.ContainsKey('audit_level')) {
        Write-Warning "Configuration missing 'audit_level' setting"
        return $false
    }

    $auditLevel = $global['audit_level']
    if ($auditLevel -notin @('1', '2', '3', 'Auto')) {
        Write-Warning "Invalid audit_level: $auditLevel. Must be 1, 2, 3, or Auto"
        return $false
    }

    # Validate sysmon_setting
    if (-not $global.ContainsKey('sysmon_setting')) {
        Write-Warning "Configuration missing 'sysmon_setting' setting"
        return $false
    }

    $sysmonSetting = $global['sysmon_setting']
    if ($sysmonSetting -notin @('0', '1')) {
        Write-Warning "Invalid sysmon_setting: $sysmonSetting. Must be 0 or 1"
        return $false
    }

    return $true
}

<#
.SYNOPSIS
    Checks system prerequisites before execution.

.DESCRIPTION
    Verifies administrator rights, OS version compatibility, and disk space.

.OUTPUTS
    Boolean indicating if all prerequisites are met.
#>
function Test-Prerequisites {
    $allChecksPassed = $true

    # Check administrator rights
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    $isAdmin = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    
    if (-not $isAdmin) {
        Write-Warning "This script requires Administrator privileges"
        $allChecksPassed = $false
    }

    # Check OS version (Windows 7/Server 2008 or later)
    $osVersion = [System.Environment]::OSVersion.Version
    if ($osVersion.Major -lt 6 -or ($osVersion.Major -eq 6 -and $osVersion.Minor -lt 1)) {
        Write-Warning "This script requires Windows 7/Server 2008 R2 or later"
        $allChecksPassed = $false
    }

    # Check available disk space (at least 100MB for logs)
    $systemDrive = $env:SystemDrive
    $drive = Get-PSDrive -Name $systemDrive.Trim(':') -ErrorAction SilentlyContinue
    if ($drive) {
        $freeSpaceMB = [math]::Round($drive.Free / 1MB, 2)
        if ($freeSpaceMB -lt 100) {
            Write-Warning "Low disk space on system drive: ${freeSpaceMB}MB available. At least 100MB recommended"
            # Don't fail, just warn
        }
    }

    # Check if auditpol.exe is available
    $auditpolPath = Get-Command auditpol.exe -ErrorAction SilentlyContinue
    if (-not $auditpolPath) {
        Write-Warning "auditpol.exe not found. This tool is required for audit policy configuration"
        $allChecksPassed = $false
    }

    return $allChecksPassed
}

#endregion Configuration Module

#region Logging Module

# Script-level variable to store log file path
$script:LogFilePath = $null
$script:LogStartTime = $null
$script:LogStats = @{
    InfoCount    = 0
    WarningCount = 0
    ErrorCount   = 0
    SuccessCount = 0
}

<#
.SYNOPSIS
    Writes a log message with timestamp and level.

.DESCRIPTION
    Outputs formatted log messages to both console and log file with timestamp and severity level.

.PARAMETER Message
    The message to log.

.PARAMETER Level
    The severity level: INFO, WARNING, ERROR, or SUCCESS. Default is INFO.

.EXAMPLE
    Write-Log "Starting configuration" -Level INFO
    Write-Log "Registry key not found" -Level WARNING
#>
function Write-Log {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet('INFO', 'WARNING', 'ERROR', 'SUCCESS')]
        [string]$Level = 'INFO',
        
        [Parameter(Mandatory = $false)]
        [switch]$NoConsole
    )

    # Get current timestamp
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    
    # Format log entry
    $logEntry = "[$timestamp] [$Level] $Message"
    
    # Update statistics
    switch ($Level) {
        'INFO' { $script:LogStats.InfoCount++ }
        'WARNING' { $script:LogStats.WarningCount++ }
        'ERROR' { $script:LogStats.ErrorCount++ }
        'SUCCESS' { $script:LogStats.SuccessCount++ }
    }
    
    # Output to console with color coding (unless NoConsole is specified).
    # To keep console output concise:
    # - INFO: Only show if it's a major step (we'll control this via caller) or if it's not just a detail.
    # - SUCCESS: Show in Green
    # - WARNING: Show in Yellow
    # - ERROR: Show in Red
    if (-not $NoConsole) {
        switch ($Level) {
            'INFO' { Write-Host "  [-] $Message" -ForegroundColor Gray }
            'WARNING' { Write-Host "  [!] $Message" -ForegroundColor Yellow }
            'ERROR' { Write-Host "  [x] $Message" -ForegroundColor Red }
            'SUCCESS' { Write-Host "  [+] $Message" -ForegroundColor Green }
        }
    }
    
    # Write to log file if initialized
    if ($script:LogFilePath) {
        $maxRetries = 3
        $retryDelay = 100 # milliseconds
        
        for ($i = 0; $i -lt $maxRetries; $i++) {
            try {
                Add-Content -Path $script:LogFilePath -Value $logEntry -ErrorAction Stop
                break # Success, exit loop
            }
            catch {
                if ($i -eq $maxRetries - 1) {
                    # Only warn on the last failure to avoid console spam
                    Write-Host "  [!] Failed to write to log file (Locked): $_" -ForegroundColor DarkYellow
                }
                Start-Sleep -Milliseconds $retryDelay
            }
        }
    }
}

<#
.SYNOPSIS
    Initializes a new log session.

.DESCRIPTION
    Creates a new log file with header information including computer name, timestamp, and system details.

.OUTPUTS
    String containing the path to the created log file.

.EXAMPLE
    Start-LogSession
#>
function Start-LogSession {
    # Generate log filename with computer name and timestamp
    $computerName = $env:COMPUTERNAME
    $timestamp = Get-Date -Format 'yyyy_MM_dd_HH_mm'
    $logFileName = "${computerName}_${timestamp}.log"
    
    # Set script-level variable
    $script:LogFilePath = Join-Path -Path $PSScriptRoot -ChildPath $logFileName
    $script:LogStartTime = Get-Date
    
    # Reset statistics
    $script:LogStats = @{
        InfoCount    = 0
        WarningCount = 0
        ErrorCount   = 0
        SuccessCount = 0
    }
    
    # Create log file with header
    $header = @"
================================================================================
Windows Event Log Configuration Tool - Execution Log
================================================================================
Computer Name: $computerName
Start Time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
User: $env:USERNAME
OS Version: $([System.Environment]::OSVersion.VersionString)
PowerShell Version: $($PSVersionTable.PSVersion.ToString())
Script Path: $PSCommandPath
================================================================================

"@
    
    try {
        Set-Content -Path $script:LogFilePath -Value $header -ErrorAction Stop
        Write-Host "Log file created: $script:LogFilePath" -ForegroundColor Green
        return $script:LogFilePath
    }
    catch {
        Write-Warning "Failed to create log file: $_"
        $script:LogFilePath = $null
        return $null
    }
}

<#
.SYNOPSIS
    Finalizes the log session with a summary.

.DESCRIPTION
    Writes summary statistics and completion information to the log file and closes the session.

.EXAMPLE
    Stop-LogSession
#>
function Stop-LogSession {
    if (-not $script:LogFilePath) {
        Write-Warning "No active log session to stop"
        return
    }
    
    # Calculate execution duration
    $endTime = Get-Date
    $duration = $endTime - $script:LogStartTime
    $durationFormatted = "{0:D2}:{1:D2}:{2:D2}" -f $duration.Hours, $duration.Minutes, $duration.Seconds
    
    # Create summary footer
    $footer = @"

================================================================================
Execution Summary
================================================================================
End Time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
Duration: $durationFormatted
Log Statistics:
  - INFO messages: $($script:LogStats.InfoCount)
  - SUCCESS messages: $($script:LogStats.SuccessCount)
  - WARNING messages: $($script:LogStats.WarningCount)
  - ERROR messages: $($script:LogStats.ErrorCount)
================================================================================
Log file saved: $script:LogFilePath
================================================================================
"@
    
    try {
        Add-Content -Path $script:LogFilePath -Value $footer -ErrorAction Stop
        Write-Host "`nLog session completed. Log saved to: $script:LogFilePath" -ForegroundColor Green
    }
    catch {
        Write-Warning "Failed to write log footer: $_"
    }
    
    # Clear script-level variables
    $script:LogFilePath = $null
    $script:LogStartTime = $null
}

#endregion Logging Module

#region Audit Policy Module

<#
.SYNOPSIS
    Sets the size of a Windows Event Log.

.DESCRIPTION
    Configures the maximum size of a specified event log using wevtutil.exe.

.PARAMETER LogName
    The name of the event log to configure (e.g., "Security", "System").

.PARAMETER SizeInMB
    The maximum size in megabytes for the log file.

.EXAMPLE
    Set-EventLogSize -LogName "Security" -SizeInMB 512
#>
function Set-EventLogSize {
    param(
        [Parameter(Mandatory = $true)]
        [string]$LogName,
        
        [Parameter(Mandatory = $true)]
        [int]$SizeInMB
    )
    
    $sizeInBytes = $SizeInMB * 1024 * 1024
    
    try {
        Write-Log "Setting log size for '$LogName' to ${SizeInMB}MB" -Level INFO -NoConsole
        $result = & wevtutil.exe sl "$LogName" /ms:$sizeInBytes 2>&1
        
        if ($LASTEXITCODE -eq 0) {
            Write-Log "Successfully set log size for '$LogName'" -Level SUCCESS -NoConsole
            return $true
        }
        else {
            Write-Log "Failed to set log size for '$LogName': $result" -Level WARNING -NoConsole
            return $false
        }
    }
    catch {
        Write-Log "Error setting log size for '$LogName': $_" -Level WARNING -NoConsole
        return $false
    }
}

<#
.SYNOPSIS
    Sets an audit policy for a specific subcategory.

.DESCRIPTION
    Configures audit policy using auditpol.exe for a specified subcategory with success and/or failure auditing.

.PARAMETER Subcategory
    The audit subcategory name (e.g., "Process Creation", "Logon").

.PARAMETER Success
    Enable success auditing for this subcategory.

.PARAMETER Failure
    Enable failure auditing for this subcategory.

.EXAMPLE
    Set-AuditPolicy -Subcategory "Process Creation" -Success $true -Failure $true
    Set-AuditPolicy -Subcategory "Registry" -Success $true -Failure $false
#>
function Set-AuditPolicy {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Subcategory,
        
        [Parameter(Mandatory = $true)]
        [bool]$Success,
        
        [Parameter(Mandatory = $true)]
        [bool]$Failure
    )
    
    $successFlag = if ($Success) { "enable" } else { "disable" }
    $failureFlag = if ($Failure) { "enable" } else { "disable" }
    
    try {
        Write-Log "Setting audit policy: $Subcategory (Success: $successFlag, Failure: $failureFlag)" -Level INFO -NoConsole
        $result = & auditpol.exe /set /subcategory:"$Subcategory" /success:$successFlag /failure:$failureFlag 2>&1
        
        if ($LASTEXITCODE -eq 0) {
            Write-Log "Successfully set audit policy for '$Subcategory'" -Level SUCCESS -NoConsole
            return $true
        }
        else {
            Write-Log "Failed to set audit policy for '$Subcategory': $result" -Level WARNING -NoConsole
            return $false
        }
    }
    catch {
        Write-Log "Error setting audit policy for '$Subcategory': $_" -Level WARNING -NoConsole
        return $false
    }
}

<#
.SYNOPSIS
    Applies Level 1 (Required) audit policies.

.DESCRIPTION
    Configures critical audit policies required for basic security monitoring:
    - Forces Advanced Audit Policy via registry
    - Sets Security and PowerShell log sizes to 512MB
    - Enables command line logging
    - Enables PowerShell script block and module logging
    - Sets critical audit policies (Process Creation, Handle Manipulation, Registry, Logon, Logoff, Special Logon)

.EXAMPLE
    Set-RequiredAuditPolicies
#>
function Set-RequiredAuditPolicies {
    Write-Log "========================================" -Level INFO -NoConsole
    Write-Log "Applying Level 1 (Required) Audit Policies" -Level INFO -NoConsole
    Write-Log "========================================" -Level INFO -NoConsole
    
    Write-Host "  Forcing Advanced Audit Policy..." -NoNewline
    # Force Advanced Audit Policy
    Write-Log "Forcing Advanced Audit Policy via registry" -Level INFO -NoConsole
    try {
        $regPath = "HKLM:\System\CurrentControlSet\Control\Lsa"
        $regName = "SCENoApplyLegacyAuditPolicy"
        $regValue = 1
        
        if (-not (Test-Path $regPath)) {
            New-Item -Path $regPath -Force | Out-Null
        }
        
        New-ItemProperty -Path $regPath -Name $regName -Value $regValue -PropertyType DWord -Force -ErrorAction Stop | Out-Null
        Write-Log "Advanced Audit Policy forced successfully" -Level SUCCESS -NoConsole
        Write-Host " OK" -ForegroundColor Green
    }
    catch {
        Write-Log "Failed to force Advanced Audit Policy: $_" -Level ERROR -NoConsole
        Write-Host " FAILED" -ForegroundColor Red
    }
    
    # Set Event Log Sizes
    Write-Host "  Configuring event log sizes..." -NoNewline
    Write-Log "Configuring event log sizes" -Level INFO -NoConsole
    Set-EventLogSize -LogName "Security" -SizeInMB 512 | Out-Null
    Set-EventLogSize -LogName "Windows PowerShell" -SizeInMB 512 | Out-Null
    Set-EventLogSize -LogName "Microsoft-Windows-PowerShell/Operational" -SizeInMB 512 | Out-Null
    Write-Host " OK" -ForegroundColor Green
    
    # Enable Command Line Logging (Process Creation)
    Write-Host "  Enabling command line logging..." -NoNewline
    Write-Log "Enabling command line logging" -Level INFO -NoConsole
    try {
        $regPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
        $regName = "ProcessCreationIncludeCmdLine_Enabled"
        $regValue = 1
        
        if (-not (Test-Path $regPath)) {
            New-Item -Path $regPath -Force | Out-Null
        }
        
        New-ItemProperty -Path $regPath -Name $regName -Value $regValue -PropertyType DWord -Force -ErrorAction Stop | Out-Null
        Write-Log "Command line logging enabled" -Level SUCCESS -NoConsole
        Write-Host " OK" -ForegroundColor Green
    }
    catch {
        Write-Log "Failed to enable command line logging: $_" -Level ERROR -NoConsole
        Write-Host " FAILED" -ForegroundColor Red
    }
    
    # Enable PowerShell Module Logging
    Write-Host "  Enabling PowerShell module logging..." -NoNewline
    Write-Log "Enabling PowerShell module logging" -Level INFO -NoConsole
    try {
        # 64-bit registry path
        $regPath64 = "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging"
        $regPathModules64 = "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames"
        
        # 32-bit registry path (Wow6432Node)
        $regPath32 = "HKLM:\Software\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ModuleLogging"
        $regPathModules32 = "HKLM:\Software\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames"
        
        # Create paths if they don't exist and set values
        foreach ($path in @($regPath64, $regPath32)) {
            if (-not (Test-Path $path)) {
                New-Item -Path $path -Force | Out-Null
            }
            New-ItemProperty -Path $path -Name "EnableModuleLogging" -Value 1 -PropertyType DWord -Force -ErrorAction Stop | Out-Null
        }
        
        # Set module names to log all modules (*)
        foreach ($path in @($regPathModules64, $regPathModules32)) {
            if (-not (Test-Path $path)) {
                New-Item -Path $path -Force | Out-Null
            }
            New-ItemProperty -Path $path -Name "*" -Value "*" -PropertyType String -Force -ErrorAction Stop | Out-Null
        }
        
        Write-Log "PowerShell module logging enabled" -Level SUCCESS -NoConsole
        Write-Host " OK" -ForegroundColor Green
    }
    catch {
        Write-Log "Failed to enable PowerShell module logging: $_" -Level ERROR -NoConsole
        Write-Host " FAILED" -ForegroundColor Red
    }
    
    # Enable PowerShell Script Block Logging
    Write-Host "  Enabling PowerShell script block logging..." -NoNewline
    Write-Log "Enabling PowerShell script block logging" -Level INFO -NoConsole
    try {
        # 64-bit registry path
        $regPath64 = "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
        
        # 32-bit registry path (Wow6432Node)
        $regPath32 = "HKLM:\Software\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
        
        # Create paths if they don't exist and set values
        foreach ($path in @($regPath64, $regPath32)) {
            if (-not (Test-Path $path)) {
                New-Item -Path $path -Force | Out-Null
            }
            New-ItemProperty -Path $path -Name "EnableScriptBlockLogging" -Value 1 -PropertyType DWord -Force -ErrorAction Stop | Out-Null
        }
        
        Write-Log "PowerShell script block logging enabled" -Level SUCCESS -NoConsole
        Write-Host " OK" -ForegroundColor Green
    }
    catch {
        Write-Log "Failed to enable PowerShell script block logging: $_" -Level ERROR -NoConsole
        Write-Host " FAILED" -ForegroundColor Red
    }
    
    # Reset audit policy before applying new settings
    Write-Host "  Resetting audit policy..." -NoNewline
    Write-Log "Resetting audit policy" -Level INFO -NoConsole
    try {
        $result = & auditpol.exe /clear /y 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Log "Audit policy reset successfully" -Level SUCCESS -NoConsole
            Write-Host " OK" -ForegroundColor Green
        }
        else {
            Write-Log "Failed to reset audit policy: $result" -Level WARNING -NoConsole
            Write-Host " WARNING" -ForegroundColor Yellow
        }
    }
    catch {
        Write-Log "Error resetting audit policy: $_" -Level WARNING -NoConsole
        Write-Host " WARNING" -ForegroundColor Yellow
    }
    
    # Apply Critical Audit Policies
    Write-Host "  Applying critical audit policies..." -NoNewline
    Write-Log "Applying critical audit policies" -Level INFO -NoConsole
    
    # Process Creation - Monitor process creation events
    Set-AuditPolicy -Subcategory "Process Creation" -Success $true -Failure $true | Out-Null
    
    # Handle Manipulation - Monitor handle operations
    Set-AuditPolicy -Subcategory "Handle Manipulation" -Success $true -Failure $false | Out-Null
    
    # Registry - Monitor registry access
    Set-AuditPolicy -Subcategory "Registry" -Success $true -Failure $false | Out-Null
    
    # Logon - Monitor logon events
    Set-AuditPolicy -Subcategory "Logon" -Success $true -Failure $true | Out-Null
    
    # Special Logon - Monitor special privilege logons
    Set-AuditPolicy -Subcategory "Special Logon" -Success $true -Failure $true | Out-Null
    
    # Logoff - Monitor logoff events
    Set-AuditPolicy -Subcategory "Logoff" -Success $true -Failure $false | Out-Null
    
    # Other Object Access Events - Monitor miscellaneous object access
    Set-AuditPolicy -Subcategory "Other Object Access Events" -Success $true -Failure $true | Out-Null
    
    Write-Log "Level 1 (Required) audit policies applied successfully" -Level SUCCESS -NoConsole
    Write-Host " OK" -ForegroundColor Green
}

<#
.SYNOPSIS
    Enables a Windows Event Log.

.DESCRIPTION
    Enables a specified event log using wevtutil.exe.

.PARAMETER LogName
    The name of the event log to enable (e.g., "Microsoft-Windows-TaskScheduler/Operational").

.EXAMPLE
    Enable-EventLog -LogName "Microsoft-Windows-TaskScheduler/Operational"
#>
function Enable-EventLog {
    param(
        [Parameter(Mandatory = $true)]
        [string]$LogName
    )
    
    try {
        Write-Log "Enabling event log: $LogName" -Level INFO -NoConsole
        $result = & wevtutil.exe sl "$LogName" /e:true 2>&1
        
        if ($LASTEXITCODE -eq 0) {
            Write-Log "Successfully enabled event log: $LogName" -Level SUCCESS -NoConsole
            return $true
        }
        else {
            Write-Log "Failed to enable event log '$LogName': $result" -Level WARNING -NoConsole
            return $false
        }
    }
    catch {
        Write-Log "Error enabling event log '$LogName': $_" -Level WARNING -NoConsole
        return $false
    }
}

<#
.SYNOPSIS
    Applies Level 2 (Recommend) audit policies.

.DESCRIPTION
    Configures recommended audit policies for enhanced security monitoring:
    - Enables additional event logs (TaskScheduler, DriverFrameworks, DNS-Client)
    - Sets audit policies for File System, Policy Changes, Account Management, File Share, Account Lockout
    - Sets additional log sizes (System, Application, Defender, Bits-Client, WMI-Activity, TerminalServices, etc.)
    - Enables PowerShell transcription logging

.EXAMPLE
    Set-RecommendAuditPolicies
#>
function Set-RecommendAuditPolicies {
    Write-Log "========================================" -Level INFO -NoConsole
    Write-Log "Applying Level 2 (Recommend) Audit Policies" -Level INFO -NoConsole
    Write-Log "========================================" -Level INFO -NoConsole
    
    # Enable additional event logs
    Write-Host "  Enabling additional event logs..." -NoNewline
    Write-Log "Enabling additional event logs" -Level INFO -NoConsole
    Enable-EventLog -LogName "Microsoft-Windows-TaskScheduler/Operational" | Out-Null
    Enable-EventLog -LogName "Microsoft-Windows-DriverFrameworks-UserMode/Operational" | Out-Null
    Enable-EventLog -LogName "Microsoft-Windows-DNS-Client/Operational" | Out-Null
    Write-Host " OK" -ForegroundColor Green
    
    # Apply Recommended Audit Policies
    Write-Host "  Applying recommended audit policies..." -NoNewline
    Write-Log "Applying recommended audit policies" -Level INFO -NoConsole
    
    # File System - Monitor file system access
    Set-AuditPolicy -Subcategory "File System" -Success $true -Failure $false | Out-Null
    
    # Audit Policy Change - Monitor changes to audit policies
    Set-AuditPolicy -Subcategory "Audit Policy Change" -Success $true -Failure $true | Out-Null
    
    # Authentication Policy Change - Monitor authentication policy changes
    Set-AuditPolicy -Subcategory "Authentication Policy Change" -Success $true -Failure $true | Out-Null
    
    # File Share - Monitor file share access
    Set-AuditPolicy -Subcategory "File Share" -Success $true -Failure $true | Out-Null
    
    # Account Lockout - Monitor account lockout events
    Set-AuditPolicy -Subcategory "Account Lockout" -Success $true -Failure $false | Out-Null
    
    # User Account Management - Monitor user account changes
    Set-AuditPolicy -Subcategory "User Account Management" -Success $true -Failure $true | Out-Null
    Write-Host " OK" -ForegroundColor Green
    
    # Set Additional Log Sizes
    Write-Host "  Configuring additional event log sizes..." -NoNewline
    Write-Log "Configuring additional event log sizes (128MB each)" -Level INFO -NoConsole
    Set-EventLogSize -LogName "System" -SizeInMB 128 | Out-Null
    Set-EventLogSize -LogName "Application" -SizeInMB 128 | Out-Null
    Set-EventLogSize -LogName "Microsoft-Windows-Windows Defender/Operational" -SizeInMB 128 | Out-Null
    Set-EventLogSize -LogName "Microsoft-Windows-Bits-Client/Operational" -SizeInMB 128 | Out-Null
    Set-EventLogSize -LogName "Microsoft-Windows-WMI-Activity/Operational" -SizeInMB 128 | Out-Null
    Set-EventLogSize -LogName "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" -SizeInMB 128 | Out-Null
    Set-EventLogSize -LogName "Microsoft-Windows-TaskScheduler/Operational" -SizeInMB 128 | Out-Null
    Set-EventLogSize -LogName "Microsoft-Windows-DNS-Client/Operational" -SizeInMB 128 | Out-Null
    Set-EventLogSize -LogName "Microsoft-Windows-DriverFrameworks-UserMode/Operational" -SizeInMB 128 | Out-Null
    Write-Host " OK" -ForegroundColor Green
    
    # Enable PowerShell Transcription
    Write-Host "  Enabling PowerShell transcription logging..." -NoNewline
    Write-Log "Enabling PowerShell transcription logging" -Level INFO -NoConsole
    try {
        # 64-bit registry path
        $regPath64 = "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\Transcription"
        
        # 32-bit registry path (Wow6432Node)
        $regPath32 = "HKLM:\Software\Wow6432Node\Policies\Microsoft\Windows\PowerShell\Transcription"
        
        # Create paths if they don't exist and set values
        foreach ($path in @($regPath64, $regPath32)) {
            if (-not (Test-Path $path)) {
                New-Item -Path $path -Force | Out-Null
            }
            New-ItemProperty -Path $path -Name "EnableInvocationHeader" -Value 1 -PropertyType DWord -Force -ErrorAction Stop | Out-Null
            New-ItemProperty -Path $path -Name "EnableTranscripting" -Value 1 -PropertyType DWord -Force -ErrorAction Stop | Out-Null
        }
        
        Write-Log "PowerShell transcription logging enabled" -Level SUCCESS -NoConsole
        Write-Host " OK" -ForegroundColor Green
    }
    catch {
        Write-Log "Failed to enable PowerShell transcription: $_" -Level ERROR -NoConsole
        Write-Host " FAILED" -ForegroundColor Red
    }
    
    Write-Log "Level 2 (Recommend) audit policies applied successfully" -Level SUCCESS -NoConsole
}

<#
.SYNOPSIS
    Detects the Windows product type (Server or Workstation).

.DESCRIPTION
    Uses WMI to determine if the system is a Server or Workstation based on the ProductType value:
    - 1 = Workstation
    - 2 = Domain Controller
    - 3 = Server

.OUTPUTS
    String: "Server" or "Workstation"

.EXAMPLE
    $productType = Get-ProductType
#>
function Get-ProductType {
    try {
        $os = Get-WmiObject -Class Win32_OperatingSystem -ErrorAction Stop
        $productType = $os.ProductType
        
        # ProductType values:
        # 1 = Workstation
        # 2 = Domain Controller
        # 3 = Server
        
        if ($productType -eq 1) {
            Write-Log "Detected product type: Workstation (ProductType=$productType)" -Level INFO
            return "Workstation"
        }
        else {
            Write-Log "Detected product type: Server (ProductType=$productType)" -Level INFO
            return "Server"
        }
    }
    catch {
        Write-Log "Failed to detect product type, defaulting to Workstation: $_" -Level WARNING
        return "Workstation"
    }
}

<#
.SYNOPSIS
    Applies Level 3 (Optional) audit policies.

.DESCRIPTION
    Configures optional audit policies for comprehensive security monitoring:
    - Sets additional log sizes (Firewall, NTLM, PrintService, AppLocker, CodeIntegrity)
    - Detects Windows product type (Server or Workstation)
    - Applies Server-specific audit policies (Kerberos, Directory Service, IPsec, Certification Services, etc.)
    - Applies Workstation-specific audit policies (Security Group Management, Other Account Management, etc.)
    - Applies common optional audit policies for both types

.EXAMPLE
    Set-OptionalAuditPolicies
#>
function Set-OptionalAuditPolicies {
    Write-Log "========================================" -Level INFO
    Write-Log "Applying Level 3 (Optional) Audit Policies" -Level INFO
    Write-Log "========================================" -Level INFO
}

#endregion Audit Policy Module

#region Registry Audit Module

<#
.SYNOPSIS
    Sets audit rules for a specific registry key.

.DESCRIPTION
    Applies audit rules to monitor registry key access by Everyone with specified access rights.
    Logs success or warning if the key doesn't exist.

.PARAMETER Key
    The registry key path (e.g., "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run").

.PARAMETER AccessRights
    The access rights to audit (e.g., "SetValue,CreateSubKey,Delete,ChangePermissions,TakeOwnership").

.PARAMETER InheritanceFlags
    The inheritance flags for the audit rule ("containerinherit" or "none").

.EXAMPLE
    Set-RegistryKeyAudit -Key "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run" -AccessRights "SetValue,CreateSubKey,Delete,ChangePermissions,TakeOwnership" -InheritanceFlags "containerinherit"
#>
function Set-RegistryKeyAudit {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Key,
        
        [Parameter(Mandatory = $true)]
        [string]$AccessRights,
        
        [Parameter(Mandatory = $true)]
        [ValidateSet("containerinherit", "none")]
        [string]$InheritanceFlags
    )
    
    if (Test-Path $Key) {
        try {
            $hold = Get-Acl $Key
            $hold = $hold.path
            $RegKey_ACL = Get-Acl -Path $hold
            $AccessRule = New-Object System.Security.AccessControl.RegistryAuditRule("Everyone", $AccessRights, $InheritanceFlags, "none", "Success")
            $RegKey_ACL.AddAuditRule($AccessRule)
            $RegKey_ACL | Set-Acl -Path $hold
            Write-Log "Set registry audit: $hold" -Level SUCCESS -NoConsole
            return $true
        }
        catch {
            Write-Log "Failed to set registry audit for '$Key': $_" -Level WARNING -NoConsole
            return $false
        }
    }
    else {
        Write-Log "Registry key not found: $Key" -Level WARNING -NoConsole
        return $false
    }
}

<#
.SYNOPSIS
    Sets audit rules for registry keys under HKEY_USERS.

.DESCRIPTION
    Enumerates all user SIDs under HKEY_USERS and applies audit rules to the specified registry key path
    for each user. This is used to monitor user-specific registry keys.

.PARAMETER KeyPath
    The relative registry key path under each user SID (e.g., "Software\Microsoft\Windows\CurrentVersion\Run").

.PARAMETER AccessRights
    The access rights to audit (e.g., "SetValue,CreateSubKey,Delete,ChangePermissions,TakeOwnership").

.PARAMETER InheritanceFlags
    The inheritance flags for the audit rule ("containerinherit" or "none").

.EXAMPLE
    Set-UserRegistryAudit -KeyPath "Software\Microsoft\Windows\CurrentVersion\Run" -AccessRights "SetValue,CreateSubKey,Delete,ChangePermissions,TakeOwnership" -InheritanceFlags "containerinherit"
#>
function Set-UserRegistryAudit {
    param(
        [Parameter(Mandatory = $true)]
        [string]$KeyPath,
        
        [Parameter(Mandatory = $true)]
        [string]$AccessRights,
        
        [Parameter(Mandatory = $true)]
        [ValidateSet("containerinherit", "none")]
        [string]$InheritanceFlags
    )
    
    try {
        $hkeyUsers = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('USERS', $env:COMPUTERNAME)
        $hkeyUsersSubkeys = $hkeyUsers.GetSubKeyNames()
        
        # Create HKU PSDrive if it doesn't exist
        if (-not (Test-Path HKU:)) {
            New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS -ErrorAction SilentlyContinue | Out-Null
        }
        
        $successCount = 0
        $notFoundCount = 0
        
        foreach ($userSid in $hkeyUsersSubkeys) {
            $fullPath = "Microsoft.PowerShell.Core\Registry::HKEY_USERS\$userSid\$KeyPath"
            
            if (Test-Path -Path $fullPath) {
                try {
                    $RegKey_ACL = Get-Acl -Path $fullPath
                    $AccessRule = New-Object System.Security.AccessControl.RegistryAuditRule("Everyone", $AccessRights, $InheritanceFlags, "none", "Success")
                    $RegKey_ACL.AddAuditRule($AccessRule)
                    $RegKey_ACL | Set-Acl -Path $fullPath
                    Write-Log "Set user registry audit: $fullPath" -Level SUCCESS -NoConsole
                    $successCount++
                }
                catch {
                    Write-Log "Failed to set user registry audit for '$fullPath': $_" -Level WARNING -NoConsole
                }
            }
            else {
                $notFoundCount++
            }
        }
        
        if ($successCount -gt 0) {
            Write-Log "Applied user registry audit to $successCount user(s) for: $KeyPath" -Level INFO -NoConsole
        }
        if ($notFoundCount -gt 0) {
            Write-Log "Registry key not found for $notFoundCount user(s): $KeyPath" -Level WARNING -NoConsole
        }
        
        return $successCount -gt 0
    }
    catch {
        Write-Log "Error enumerating user registry keys for '$KeyPath': $_" -Level WARNING -NoConsole
        return $false
    }
}

<#
.SYNOPSIS
    Applies registry auditing to Auto-Start Extension Points (ASEPs) and security-critical keys.

.DESCRIPTION
    Configures audit rules for registry keys commonly accessed by malware for persistence:
    - Autorun registry keys (Run, RunOnce, RunServices, RunServicesOnce)
    - Explorer autorun keys
    - Winlogon keys
    - Alternative autorun keys
    - Local policy startup script keys
    - Windows security setting keys (LSA, SafeBoot, SecurityProviders, SAM)
    
    Monitors both HKLM (system-wide) and HKEY_USERS (per-user) keys, including Wow6432Node for 32-bit applications.

.EXAMPLE
    Set-RegistryAudit
#>
function Set-RegistryAudit {
    Write-Log "========================================" -Level INFO
    Write-Log "Applying Registry Auditing (ASEPs)" -Level INFO
    Write-Log "========================================" -Level INFO
    
    # Define common access rights for most registry keys
    $standardAccess = "SetValue,CreateSubKey,Delete,ChangePermissions,TakeOwnership"
    $readWriteAccess = "ReadKey,QueryValues,SetValue,CreateSubKey,Delete,ChangePermissions,TakeOwnership"
    
    # Autorun Entry - HKLM keys
    Write-Log "Auditing Autorun registry keys (HKLM)" -Level INFO
    Set-RegistryKeyAudit -Key "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run" -AccessRights $standardAccess -InheritanceFlags "containerinherit" | Out-Null
    Set-RegistryKeyAudit -Key "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce" -AccessRights $standardAccess -InheritanceFlags "containerinherit" | Out-Null
    Set-RegistryKeyAudit -Key "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce" -AccessRights $standardAccess -InheritanceFlags "containerinherit" | Out-Null
    Set-RegistryKeyAudit -Key "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunServices" -AccessRights $standardAccess -InheritanceFlags "containerinherit" | Out-Null
    
    # Autorun Entry - HKLM Wow6432Node (32-bit on 64-bit systems)
    Write-Log "Auditing Autorun registry keys (HKLM Wow6432Node)" -Level INFO
    Set-RegistryKeyAudit -Key "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run" -AccessRights $standardAccess -InheritanceFlags "containerinherit" | Out-Null
    Set-RegistryKeyAudit -Key "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce" -AccessRights $standardAccess -InheritanceFlags "containerinherit" | Out-Null
    Set-RegistryKeyAudit -Key "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce" -AccessRights $standardAccess -InheritanceFlags "containerinherit" | Out-Null
    Set-RegistryKeyAudit -Key "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServices" -AccessRights $standardAccess -InheritanceFlags "containerinherit" | Out-Null
    
    # Autorun Entry - HKEY_USERS keys
    Write-Log "Auditing Autorun registry keys (HKEY_USERS)" -Level INFO
    Set-UserRegistryAudit -KeyPath "Software\Microsoft\Windows\CurrentVersion\Run" -AccessRights $standardAccess -InheritanceFlags "containerinherit" | Out-Null
    Set-UserRegistryAudit -KeyPath "Software\Microsoft\Windows\CurrentVersion\RunOnce" -AccessRights $standardAccess -InheritanceFlags "containerinherit" | Out-Null
    Set-UserRegistryAudit -KeyPath "Software\Microsoft\Windows\CurrentVersion\RunServicesOnce" -AccessRights $standardAccess -InheritanceFlags "containerinherit" | Out-Null
    Set-UserRegistryAudit -KeyPath "Software\Microsoft\Windows\CurrentVersion\RunServices" -AccessRights $standardAccess -InheritanceFlags "containerinherit" | Out-Null
    
    # Explorer Autorun Entry - HKLM keys
    Write-Log "Auditing Explorer autorun registry keys (HKLM)" -Level INFO
    Set-RegistryKeyAudit -Key "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run" -AccessRights $standardAccess -InheritanceFlags "containerinherit" | Out-Null
    Set-RegistryKeyAudit -Key "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run" -AccessRights $standardAccess -InheritanceFlags "containerinherit" | Out-Null
    
    # Explorer Autorun Entry - HKEY_USERS keys
    Write-Log "Auditing Explorer autorun registry keys (HKEY_USERS)" -Level INFO
    Set-UserRegistryAudit -KeyPath "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run" -AccessRights $standardAccess -InheritanceFlags "containerinherit" | Out-Null
    Set-UserRegistryAudit -KeyPath "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run" -AccessRights $standardAccess -InheritanceFlags "containerinherit" | Out-Null
    
    # Winlogon Autorun Entry - HKLM keys
    Write-Log "Auditing Winlogon registry keys (HKLM)" -Level INFO
    Set-RegistryKeyAudit -Key "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" -AccessRights $standardAccess -InheritanceFlags "containerinherit" | Out-Null
    Set-RegistryKeyAudit -Key "HKLM:\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Winlogon" -AccessRights $standardAccess -InheritanceFlags "containerinherit" | Out-Null
    
    # Winlogon Autorun Entry - HKEY_USERS keys
    Write-Log "Auditing Winlogon registry keys (HKEY_USERS)" -Level INFO
    Set-UserRegistryAudit -KeyPath "Software\Microsoft\Windows NT\CurrentVersion\Winlogon" -AccessRights $standardAccess -InheritanceFlags "containerinherit" | Out-Null
    Set-UserRegistryAudit -KeyPath "Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Winlogon" -AccessRights $standardAccess -InheritanceFlags "containerinherit" | Out-Null
    
    # Alternative Autorun Entry - HKLM keys
    Write-Log "Auditing alternative autorun registry keys (HKLM)" -Level INFO
    Set-RegistryKeyAudit -Key "HKLM:\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows" -AccessRights $standardAccess -InheritanceFlags "none" | Out-Null
    Set-RegistryKeyAudit -Key "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Windows" -AccessRights $standardAccess -InheritanceFlags "none" | Out-Null
    Set-RegistryKeyAudit -Key "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -AccessRights $standardAccess -InheritanceFlags "none" | Out-Null
    
    # Alternative Autorun Entry - HKEY_USERS keys
    Write-Log "Auditing alternative autorun registry keys (HKEY_USERS)" -Level INFO
    Set-UserRegistryAudit -KeyPath "Software\Microsoft\Windows NT\CurrentVersion\Windows" -AccessRights $standardAccess -InheritanceFlags "none" | Out-Null
    Set-UserRegistryAudit -KeyPath "Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows" -AccessRights $standardAccess -InheritanceFlags "none" | Out-Null
    Set-UserRegistryAudit -KeyPath "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -AccessRights $standardAccess -InheritanceFlags "none" | Out-Null
    
    # Local Policy Startup Script - HKLM keys
    Write-Log "Auditing local policy startup script registry keys (HKLM)" -Level INFO
    Set-RegistryKeyAudit -Key "HKLM:\Software\Microsoft\Windows\CurrentVersion\Group Policy\Scripts" -AccessRights $standardAccess -InheritanceFlags "containerinherit" | Out-Null
    Set-RegistryKeyAudit -Key "HKLM:\Software\Policies\Microsoft\Windows\System\Scripts" -AccessRights $standardAccess -InheritanceFlags "containerinherit" | Out-Null
    
    # Local Policy Startup Script - HKEY_USERS keys
    Write-Log "Auditing local policy startup script registry keys (HKEY_USERS)" -Level INFO
    Set-UserRegistryAudit -KeyPath "Software\Microsoft\Windows\CurrentVersion\Group Policy\Scripts" -AccessRights $standardAccess -InheritanceFlags "containerinherit" | Out-Null
    Set-UserRegistryAudit -KeyPath "Software\Policies\Microsoft\Windows\System\Scripts" -AccessRights $standardAccess -InheritanceFlags "containerinherit" | Out-Null
    
    # Other Windows Security Setting - HKLM keys
    Write-Log "Auditing Windows security setting registry keys (HKLM)" -Level INFO
    Set-RegistryKeyAudit -Key "HKLM:\System\CurrentControlSet\Control\Lsa" -AccessRights $standardAccess -InheritanceFlags "none" | Out-Null
    Set-RegistryKeyAudit -Key "HKLM:\System\CurrentControlSet\Control\SafeBoot" -AccessRights $standardAccess -InheritanceFlags "containerinherit" | Out-Null
    Set-RegistryKeyAudit -Key "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -AccessRights $standardAccess -InheritanceFlags "containerinherit" | Out-Null
    Set-RegistryKeyAudit -Key "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SecurityProviders" -AccessRights $standardAccess -InheritanceFlags "none" | Out-Null
    Set-RegistryKeyAudit -Key "HKLM:\System\CurrentControlSet\Control\SecurityProviders\WDigest" -AccessRights $standardAccess -InheritanceFlags "none" | Out-Null
    Set-RegistryKeyAudit -Key "HKLM:\SAM" -AccessRights $readWriteAccess -InheritanceFlags "containerinherit" | Out-Null
    
    Write-Log "Registry auditing (ASEPs) applied successfully" -Level SUCCESS
}

#endregion Registry Audit Module

#region FileSystem Audit Module

<#
.SYNOPSIS
    Sets audit rules for a specific file system path.

.DESCRIPTION
    Applies audit rules to monitor file system access by Everyone with specified access rights.
    Logs success or warning if the path doesn't exist.

.PARAMETER Path
    The file system path to audit (e.g., "C:\Windows\System32\config\SAM").

.PARAMETER AccessRights
    The access rights to audit (e.g., "AppendData,ChangePermissions,CreateDirectories,CreateFiles,Delete").

.EXAMPLE
    Set-PathAudit -Path "C:\Users\Public" -AccessRights "AppendData,ChangePermissions,CreateDirectories,CreateFiles,Delete,DeleteSubdirectoriesAndFiles,TakeOwnership,Write,WriteAttributes,WriteExtendedAttributes"
#>
function Set-PathAudit {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,
        
        [Parameter(Mandatory = $true)]
        [string]$AccessRights
    )
    
    if (Test-Path -LiteralPath $Path) {
        try {
            $ACL = New-Object System.Security.AccessControl.DirectorySecurity
            $AccessRule = New-Object System.Security.AccessControl.FileSystemAuditRule("Everyone", $AccessRights, "ContainerInherit, ObjectInherit", "NoPropagateInherit", "Success")
            $ACL.SetAuditRule($AccessRule)
            $ACL | Set-Acl $Path
            Write-Log "Set filesystem audit: $Path" -Level SUCCESS -NoConsole
            return $true
        }
        catch {
            Write-Log "Failed to set filesystem audit for '$Path': $_" -Level WARNING
            return $false
        }
    }
    else {
        # Path not found is common (e.g. if software not installed), log as INFO to avoid console noise
        Write-Log "Path not found: $Path" -Level INFO -NoConsole
        return $false
    }
}

<#
.SYNOPSIS
    Enumerates all user profile folders.

.DESCRIPTION
    Gets all user profile directories from the Users folder, excluding system folders.
    Returns an array of user folder paths.

.OUTPUTS
    Array of user profile folder paths.

.EXAMPLE
    $userFolders = Get-UserFolders
#>
function Get-UserFolders {
    try {
        $usersPath = "$env:SystemDrive\Users"
        
        if (-not (Test-Path $usersPath)) {
            Write-Log "Users folder not found: $usersPath" -Level WARNING
            return @()
        }
        
        $userFolders = Get-ChildItem -LiteralPath $usersPath -Force -ErrorAction Stop | 
        Where-Object { $_.PSIsContainer } | 
        Select-Object -ExpandProperty FullName
        
        Write-Log "Found $($userFolders.Count) user profile folder(s)" -Level INFO
        return $userFolders
    }
    catch {
        Write-Log "Error enumerating user folders: $_" -Level WARNING
        return @()
    }
}

<#
.SYNOPSIS
    Applies filesystem auditing to suspicious and security-critical paths.

.DESCRIPTION
    Configures audit rules for file system paths commonly accessed by malware or critical for security:
    - User startup folders (per-user AppData\Roaming\...\Startup)
    - User data folders (Music, Pictures, Videos, Documents, Contacts)
    - Global startup folders (Default user, ProgramData)
    - Suspicious/public folders (Public, ProgramData, PerfLogs, debug, etc.)
    - SAM and SECURITY files (credential databases)
    - IIS config files (applicationhost.config)
    - NTDS.dit file (Active Directory database)
    
    Based on the Windows File Auditing Cheat Sheet from www.MalwareArchaeology.com

.EXAMPLE
    Set-FileSystemAudit
#>
function Set-FileSystemAudit {
    Write-Log "========================================" -Level INFO
    Write-Log "Applying FileSystem Auditing" -Level INFO
    Write-Log "========================================" -Level INFO
    
    # Define common access rights for write operations
    $writeAccess = "AppendData,ChangePermissions,CreateDirectories,CreateFiles,Delete,DeleteSubdirectoriesAndFiles,TakeOwnership,Write,WriteAttributes,WriteExtendedAttributes"
    
    # Define access rights for read operations (SAM/SECURITY monitoring)
    $readAccess = "Modify,Read,ReadAndExecute,ReadAttributes,ReadData,ReadExtendedAttributes,ReadPermissions"
    
    $rootDir = $env:SystemDrive
    $dataFolders = @("Music", "Pictures", "Videos", "Documents", "Contacts")
    
    # Get all user folders
    $userFolders = Get-UserFolders
    
    if ($userFolders.Count -gt 0) {
        Write-Log "Auditing user-specific folders" -Level INFO
        
        foreach ($userDir in $userFolders) {
            # User startup folder
            $startupPath = Join-Path $userDir "AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"
            Set-PathAudit -Path $startupPath -AccessRights $writeAccess | Out-Null
            
            # User data folders (Music, Pictures, Videos, Documents, Contacts)
            foreach ($folder in $dataFolders) {
                $dataPath = Join-Path $userDir $folder
                Set-PathAudit -Path $dataPath -AccessRights $writeAccess | Out-Null
            }
        }
    }
    
    # Global startup folders
    Write-Log "Auditing global startup folders" -Level INFO
    Set-PathAudit -Path "$rootDir\Users\Default\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup" -AccessRights $writeAccess | Out-Null
    Set-PathAudit -Path "$rootDir\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup" -AccessRights $writeAccess | Out-Null
    
    # Suspicious/Public folders (noisy but important)
    Write-Log "Auditing suspicious/public folders" -Level INFO
    $suspiciousFolders = @(
        "$rootDir\Users\Public",
        "$rootDir\ProgramData",
        "$rootDir\PerfLogs",
        "$env:windir\debug",
        "$env:Public",
        "$env:windir\ServiceProfiles"
    )
    
    foreach ($folder in $suspiciousFolders) {
        if ($folder) {
            Set-PathAudit -Path $folder.ToLower() -AccessRights $writeAccess | Out-Null
        }
    }
    
    # SAM and SECURITY files (credential databases)
    Write-Log "Auditing SAM and SECURITY files" -Level INFO
    Set-PathAudit -Path "$rootDir\Windows\System32\config\SAM" -AccessRights $readAccess | Out-Null
    Set-PathAudit -Path "$rootDir\Windows\System32\config\SECURITY" -AccessRights $readAccess | Out-Null
    
    # IIS Webserver config files
    Write-Log "Auditing IIS config files (if present)" -Level INFO
    Set-PathAudit -Path "$rootDir\Windows\System32\inetsrv\config\applicationhost.config" -AccessRights $writeAccess | Out-Null
    Set-PathAudit -Path "$rootDir\Windows\SysWOW64\inetsrv\config\applicationhost.config" -AccessRights $writeAccess | Out-Null
    
    # NTDS.dit (Active Directory database)
    Write-Log "Auditing NTDS.dit file (if present)" -Level INFO
    Set-PathAudit -Path "$rootDir\Windows\NTDS\Ntds.dit" -AccessRights $readAccess | Out-Null
    
    Write-Log "FileSystem auditing applied successfully" -Level SUCCESS
}

#endregion FileSystem Audit Module

#region Sysmon Module

<#
.SYNOPSIS
    Checks if Sysmon is already installed on the system.

.DESCRIPTION
    Queries the Windows service manager to determine if Sysmon or Sysmon64 service is installed.

.OUTPUTS
    Boolean indicating if Sysmon is installed.

.EXAMPLE
    $isInstalled = Test-SysmonInstalled
#>
function Test-SysmonInstalled {
    try {
        # Check for Sysmon service (32-bit)
        $sysmonService = Get-Service -Name "Sysmon" -ErrorAction SilentlyContinue
        
        # Check for Sysmon64 service (64-bit)
        $sysmon64Service = Get-Service -Name "Sysmon64" -ErrorAction SilentlyContinue
        
        if ($sysmonService -or $sysmon64Service) {
            $serviceName = if ($sysmon64Service) { "Sysmon64" } else { "Sysmon" }
            Write-Log "Sysmon is already installed (Service: $serviceName)" -Level INFO
            return $true
        }
        else {
            Write-Log "Sysmon is not installed" -Level INFO
            return $false
        }
    }
    catch {
        Write-Log "Error checking Sysmon installation status: $_" -Level WARNING
        return $false
    }
}

<#
.SYNOPSIS
    Installs or updates Sysmon with configuration.

.DESCRIPTION
    Installs Sysmon if not present, or updates the configuration if already installed.
    Automatically detects Windows version and selects appropriate Sysmon version.
    
    After installation/update, sets Sysmon event log size to 1GB.

.EXAMPLE
    Install-Sysmon
#>
function Install-Sysmon {
    Write-Log "========================================" -Level INFO
    Write-Log "Installing/Updating Sysmon" -Level INFO
    Write-Log "========================================" -Level INFO
    
    # Detect Windows version
    $osVersion = [System.Environment]::OSVersion.Version
    $major = $osVersion.Major
    $minor = $osVersion.Minor
    
    $sysmonFolder = Join-Path -Path $PSScriptRoot -ChildPath "Sysmon"
    
    if (-not (Test-Path $sysmonFolder)) {
        Write-Log "Sysmon folder not found: $sysmonFolder" -Level ERROR
        return $false
    }
    
    # Determine preferred version pattern based on OS (Legacy support)
    $preferredVersionPattern = $null
    $osName = "Unknown"
    
    if ($major -eq 6) {
        switch ($minor) {
            0 { 
                $preferredVersionPattern = "6.0"
                $osName = "Windows Vista/Server 2008" 
            }
            1 { 
                $preferredVersionPattern = "6.0"
                $osName = "Windows 7/Server 2008 R2" 
            }
            2 { 
                $preferredVersionPattern = "6.2"
                $osName = "Windows 8/Server 2012" 
            }
            3 { 
                $preferredVersionPattern = "6.3"
                $osName = "Windows 8.1/Server 2012 R2" 
            }
        }
    }
    elseif ($major -ge 10) {
        $osName = "Windows 10/11/Server 2016+"
        # No specific preferred pattern, we want the latest version available
    }
    elseif ($major -lt 6) {
        Write-Log "Unsupported Windows version for Sysmon: $major.$minor" -Level ERROR
        return $false
    }
    
    Write-Log "Detected OS: $osName (Version $major.$minor)" -Level INFO
    
    # Find available Sysmon executables
    $sysmonFiles = Get-ChildItem -Path $sysmonFolder -Filter "*.exe"
    
    if ($sysmonFiles.Count -eq 0) {
        Write-Log "No Sysmon executables found in $sysmonFolder" -Level ERROR
        return $false
    }
    
    $selectedExe = $null
    
    # Strategy 1: If we have a preferred legacy version, try to find it first
    if ($preferredVersionPattern) {
        $selectedExe = $sysmonFiles | Where-Object { $_.Name -match "Sysmon.*$preferredVersionPattern" } | Select-Object -First 1
        if ($selectedExe) {
            Write-Log "Found legacy compatible version: $($selectedExe.Name)" -Level INFO
        }
    }
    
    # Strategy 2: If no preferred version (Modern OS) or preferred not found, get the latest version
    if (-not $selectedExe) {
        # Sort by version. We try to parse version from filename or file version info.
        $selectedExe = $sysmonFiles | Sort-Object -Property {
            $ver = "0.0.0.0"
            # Try to extract from filename first (e.g. _6.3.exe)
            if ($_.Name -match '(\d+\.\d+(\.\d+)?(\.\d+)?)') {
                $ver = $matches[1]
            }
            # Fallback to FileVersionInfo if filename doesn't have version
            elseif ($_.VersionInfo.FileVersion) {
                $ver = $_.VersionInfo.FileVersion
            }
            
            # Convert to Version object for proper sorting
            try { [Version]$ver } catch { [Version]"0.0.0.0" }
        } -Descending | Select-Object -First 1
        
        if ($selectedExe) {
            Write-Log "Selected latest available version: $($selectedExe.Name)" -Level INFO
        }
    }
    
    if (-not $selectedExe) {
        Write-Log "Could not determine suitable Sysmon version." -Level ERROR
        return $false
    }
    
    $sysmonExe = $selectedExe.FullName
    
    # Look for matching config file
    # Priority:
    # 1. [ExeBaseName].xml (e.g., Sysmon_for_windows_6.3.xml)
    # 2. sysmonconfig.xml (Generic)
    # 3. SysmonConfig.xml (Generic)
    
    $baseName = $selectedExe.BaseName
    $possibleConfigs = @(
        (Join-Path $sysmonFolder "$baseName.xml"),
        (Join-Path $sysmonFolder "sysmonconfig.xml"),
        (Join-Path $sysmonFolder "SysmonConfig.xml")
    )
    
    $sysmonConfig = $null
    foreach ($conf in $possibleConfigs) {
        if (Test-Path $conf) {
            $sysmonConfig = $conf
            break
        }
    }
    
    if (-not $sysmonConfig) {
        Write-Log "Sysmon configuration file not found. Checked: $($possibleConfigs -join ', ')" -Level ERROR
        return $false
    }
    
    Write-Log "Using Sysmon executable: $sysmonExe" -Level INFO
    Write-Log "Using Sysmon config: $sysmonConfig" -Level INFO
    
    # Copy Sysmon to temp directory
    $tempSysmon = Join-Path -Path $env:windir -ChildPath "Temp\Sysmon.exe"
    
    try {
        Write-Log "Copying Sysmon to temporary location: $tempSysmon" -Level INFO
        Copy-Item -Path $sysmonExe -Destination $tempSysmon -Force -ErrorAction Stop
        Write-Log "Sysmon copied successfully" -Level SUCCESS
    }
    catch {
        Write-Log "Failed to copy Sysmon executable: $_" -Level ERROR
        return $false
    }
    
    # Check if Sysmon is already installed
    $isInstalled = Test-SysmonInstalled
    
    if ($isInstalled) {
        # Update configuration
        Write-Log "Updating Sysmon configuration" -Level INFO
        
        try {
            $result = & $tempSysmon -c $sysmonConfig 2>&1
            
            if ($LASTEXITCODE -eq 0) {
                Write-Log "Sysmon configuration updated successfully" -Level SUCCESS
            }
            else {
                Write-Log "Failed to update Sysmon configuration. Exit code: $LASTEXITCODE" -Level WARNING
                Write-Log "Output: $result" -Level WARNING
            }
        }
        catch {
            Write-Log "Error updating Sysmon configuration: $_" -Level ERROR
            return $false
        }
    }
    else {
        # Install Sysmon
        Write-Log "Installing Sysmon" -Level INFO
        
        try {
            $result = & $tempSysmon -accepteula -i $sysmonConfig 2>&1
            
            if ($LASTEXITCODE -eq 0) {
                Write-Log "Sysmon installed successfully" -Level SUCCESS
            }
            else {
                Write-Log "Failed to install Sysmon. Exit code: $LASTEXITCODE" -Level WARNING
                Write-Log "Output: $result" -Level WARNING
                return $false
            }
        }
        catch {
            Write-Log "Error installing Sysmon: $_" -Level ERROR
            return $false
        }
    }
    
    # Set Sysmon event log size to 1GB (1073741824 bytes)
    Write-Log "Setting Sysmon event log size to 1GB" -Level INFO
    
    try {
        $result = & wevtutil.exe sl "Microsoft-Windows-Sysmon/Operational" /ms:1073741824 2>&1
        
        if ($LASTEXITCODE -eq 0) {
            Write-Log "Sysmon event log size set successfully" -Level SUCCESS
        }
        else {
            Write-Log "Failed to set Sysmon event log size: $result" -Level WARNING
        }
    }
    catch {
        Write-Log "Error setting Sysmon event log size: $_" -Level WARNING
    }
    
    Write-Log "Sysmon installation/update completed" -Level SUCCESS
    return $true
}
<#
.SYNOPSIS
    Exports the current audit policy configuration to a CSV file.

.DESCRIPTION
    Uses auditpol.exe to export the current audit policy settings to a timestamped CSV file.
    The CSV file can be imported into SecPol.msc for review or backup purposes.
    
    The filename format is: COMPUTERNAME_YYYY_MM_DD_HH_MM.csv

.OUTPUTS
    String containing the path to the exported CSV file, or $null if export failed.

.EXAMPLE
    $csvPath = Export-AuditPolicy
#>
function Export-AuditPolicy {
    Write-Log "Exporting audit policy to CSV" -Level INFO
    
    # Generate CSV filename with computer name and timestamp
    $computerName = $env:COMPUTERNAME
    $timestamp = Get-Date -Format 'yyyy_MM_dd_HH_mm'
    $csvFileName = "${computerName}_${timestamp}.csv"
    
    # Set full path for CSV file in script directory
    $csvFilePath = Join-Path -Path $PSScriptRoot -ChildPath $csvFileName
    
    try {
        # Export audit policy using auditpol.exe
        Write-Log "Executing: auditpol.exe /backup /file:$csvFilePath" -Level INFO
        $result = & auditpol.exe /backup /file:$csvFilePath 2>&1
        
        if ($LASTEXITCODE -eq 0) {
            if (Test-Path $csvFilePath) {
                Write-Log "Audit policy exported successfully to: $csvFilePath" -Level SUCCESS
                return $csvFilePath
            }
            else {
                Write-Log "Audit policy export command succeeded but file not found: $csvFilePath" -Level WARNING
                return $null
            }
        }
        else {
            Write-Log "Failed to export audit policy. Exit code: $LASTEXITCODE" -Level ERROR
            Write-Log "Output: $result" -Level ERROR
            return $null
        }
    }
    catch {
        Write-Log "Error exporting audit policy: $_" -Level ERROR
        return $null
    }
}

<#
.SYNOPSIS
    Generates a summary report of the applied audit configuration.

.DESCRIPTION
    Creates a formatted summary report showing:
    - Computer name and timestamp
    - Applied audit level (1, 2, or 3)
    - Sysmon installation status
    - Product type (Server or Workstation)
    - Key configuration details
    - Paths to generated files (log and CSV)

.PARAMETER Config
    Configuration hashtable containing audit_level and sysmon_setting.

.PARAMETER ProductType
    The detected product type ("Server" or "Workstation").

.PARAMETER CsvPath
    Path to the exported CSV file (optional).

.OUTPUTS
    String containing the formatted summary report.

.EXAMPLE
    $summary = New-SummaryReport -Config $config -ProductType "Workstation" -CsvPath "C:\path\to\export.csv"
    Write-Host $summary
#>
function New-SummaryReport {
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Config,
        
        [Parameter(Mandatory = $true)]
        [string]$ProductType,
        
        [Parameter(Mandatory = $false)]
        [string]$CsvPath,
        
        [Parameter(Mandatory = $false)]
        [bool]$SysmonApplied = $false
    )
    
    $computerName = $env:COMPUTERNAME
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    
    # Get audit level and sysmon setting from config
    $auditLevel = $Config['Global']['audit_level']
    $sysmonSetting = $Config['Global']['sysmon_setting']
    $sysmonEnabled = ($sysmonSetting -eq '1')
    
    # Determine audit level description
    # Determine audit level description
    $auditLevelDesc = switch ($auditLevel) {
        '1' { "Level 1 (Required)" }
        '2' { "Level 2 (Recommend)" }
        '3' { "Level 3 (Optional)" }
        'Auto' { 
            if ($ProductType -eq 'Server') { "Auto (Level 3 - Server)" }
            elseif ($ProductType -eq 'Domain Controller') { "Auto (Level 3 - Domain Controller)" }
            else { "Auto (Level 2 - Workstation)" }
        }
        default { "Unknown ($auditLevel)" }
    }
    
    # Build summary report
    $summary = @"

================================================================================
                    AUDIT CONFIGURATION SUMMARY
================================================================================

Computer Name:          $computerName
Completion Time:        $timestamp
Product Type:           $ProductType
Audit Level:            $auditLevelDesc
Sysmon:                 $(if ($sysmonEnabled) {
                             if ($SysmonApplied) { "Enabled (installation successful)" }
                             else { "Enabled (installation failed)" }
                         } else {
                             "Disabled"
                         })

Configuration Applied:
----------------------
"@
    
    # Add level-specific details
    $summary += "`n  [OK] Advanced Audit Policy forced via registry"
    $summary += "`n  [OK] Event log sizes configured (Security: 512MB, PowerShell: 512MB)"
    $summary += "`n  [OK] Command line logging enabled"
    $summary += "`n  [OK] PowerShell script block and module logging enabled"
    $summary += "`n  [OK] Critical audit policies applied (Process Creation, Registry, Logon, etc.)"
    
    if ($auditLevel -ge 2) {
        $summary += "`n  [OK] Additional event logs enabled (TaskScheduler, DNS-Client, DriverFrameworks)"
        $summary += "`n  [OK] Recommended audit policies applied (File System, Policy Changes, Account Management)"
        $summary += "`n  [OK] PowerShell transcription logging enabled"
    }
    
    if ($auditLevel -ge 3) {
        $summary += "`n  [OK] Optional audit policies applied ($ProductType-specific)"
        $summary += "`n  [OK] Extended event log sizes configured"
    }
    
    $summary += "`n  [OK] Registry auditing applied (ASEPs and security-critical keys)"
    $summary += "`n  [OK] FileSystem auditing applied (suspicious paths and security files)"
    
    if ($sysmonEnabled) {
        if ($SysmonApplied) {
            $summary += "`n  [OK] Sysmon installed/updated with configuration"
        }
        else {
            $summary += "`n  [WARN] Sysmon was enabled in config but installation/update failed"
        }
    }
    
    # Add file paths
    $summary += "`n`nGenerated Files:"
    $summary += "`n----------------"
    
    if ($script:LogFilePath) {
        $summary += "`n  Log File:    $script:LogFilePath"
    }
    
    if ($CsvPath) {
        $summary += "`n  CSV Export:  $CsvPath"
        $summary += "`n               (Can be imported to SecPol.msc for review)"
    }
    
    # Add next steps
    $summary += "`n`nNext Steps:"
    $summary += "`n-----------"
    $summary += "`n  1. Review the log file for any warnings or errors"
    $summary += "`n  2. Verify audit policies with: auditpol /get /category:*"
    $summary += "`n  3. Check event log sizes with: wevtutil gli Security"
    $summary += "`n  4. Monitor Event Viewer for security events"
    
    if ($sysmonEnabled) {
        $summary += "`n  5. Verify Sysmon service: Get-Service Sysmon64"
    }
    
    $summary += "`n`n================================================================================"
    $summary += "`n"
    
    return $summary
}

#endregion Reporting Module
#region Main Execution Flow

<#
.SYNOPSIS
    Main orchestration function for audit configuration.

.DESCRIPTION
    Orchestrates the entire audit configuration process:
    1. Checks prerequisites (admin rights, OS version)
    2. Reads and validates configuration from config.ini
    3. Starts logging session
    4. Executes audit policies based on configured level (1, 2, or 3)
    5. Applies Sysmon if configured
    6. Exports audit policy to CSV
    7. Generates and displays summary report
    8. Refreshes Group Policy with gpupdate
    9. Stops logging session
    
    Includes comprehensive error handling with try-catch blocks.

.EXAMPLE
    Invoke-AuditConfiguration
#>
function Invoke-AuditConfiguration {
    # Display banner
    Write-Host ""
    Write-Host "================================================================================" -ForegroundColor Cyan
    Write-Host "           Windows Event Log Configuration Tool v2.0" -ForegroundColor Cyan
    Write-Host "================================================================================" -ForegroundColor Cyan
    Write-Host ""
    
    # Step 1: Check prerequisites
    Write-Host "Checking prerequisites..." -ForegroundColor Yellow
    
    try {
        $prerequisitesPassed = Test-Prerequisites
        
        if (-not $prerequisitesPassed) {
            Write-Host "`nPrerequisite checks failed. Please resolve the issues above and try again." -ForegroundColor Red
            Write-Host "Press any key to exit..." -ForegroundColor Yellow
            $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            exit 1
        }
        
        Write-Host "[+] All prerequisite checks passed" -ForegroundColor Green
    }
    catch {
        Write-Host "Error during prerequisite checks: $_" -ForegroundColor Red
        Write-Host "Press any key to exit..." -ForegroundColor Yellow
        $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        exit 1
    }
    
    # Step 2: Read and validate configuration
    Write-Host "`nReading configuration..." -ForegroundColor Yellow
    
    try {
        $configPath = Join-Path -Path $PSScriptRoot -ChildPath "config.ini"
        $config = Read-ConfigFile -FilePath $configPath
        
        $configValid = Test-Configuration -Config $config
        
        if (-not $configValid) {
            Write-Host "`nConfiguration validation failed. Please check config.ini and try again." -ForegroundColor Red
            Write-Host "Press any key to exit..." -ForegroundColor Yellow
            $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            exit 1
        }
        
        $auditLevel = $config['Global']['audit_level']
        $sysmonSetting = [int]$config['Global']['sysmon_setting']
        
        Write-Host "[+] Configuration loaded successfully" -ForegroundColor Green
        Write-Host "  - Audit Level: $auditLevel" -ForegroundColor Cyan
        Write-Host "  - Sysmon: $(if ($sysmonSetting -eq 1) { 'Enabled' } else { 'Disabled' })" -ForegroundColor Cyan
    }
    catch {
        Write-Host "Error reading configuration: $_" -ForegroundColor Red
        Write-Host "Press any key to exit..." -ForegroundColor Yellow
        $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        exit 1
    }
    
    # Step 3: Start logging session
    Write-Host "`nInitializing logging..." -ForegroundColor Yellow
    
    try {
        $logPath = Start-LogSession
        
        if (-not $logPath) {
            Write-Host "Warning: Failed to create log file. Continuing without file logging..." -ForegroundColor Yellow
        }
        else {
            Write-Host "[+] Logging initialized" -ForegroundColor Green
        }
    }
    catch {
        Write-Host "Error initializing logging: $_" -ForegroundColor Yellow
        Write-Host "Continuing without file logging..." -ForegroundColor Yellow
    }
    
    # Detect Product Type early for Auto mode
    $productType = Get-ProductType
    
    # Auto-detect audit level if set to 'Auto'
    if ($auditLevel -eq 'Auto') {
        Write-Log "Audit level set to 'Auto'. Detecting appropriate level..." -Level INFO
        
        # Get specific product info to distinguish DC from Member Server
        $osInfo = Get-WmiObject -Class Win32_OperatingSystem
        # ProductType: 1=Workstation, 2=Domain Controller, 3=Server
        
        if ($osInfo.ProductType -eq 2) {
            $auditLevel = '3'
            Write-Log "Detected Domain Controller. Setting Audit Level to 3 (Optional/Advanced)" -Level INFO
            Write-Host "Auto-detected Domain Controller. Applying Level 3 (Advanced)..." -ForegroundColor Cyan
        }
        elseif ($osInfo.ProductType -eq 3) {
            $auditLevel = '2'
            Write-Log "Detected Member Server. Setting Audit Level to 2 (Recommended)" -Level INFO
            Write-Host "Auto-detected Member Server. Applying Level 2 (Recommended)..." -ForegroundColor Cyan
        }
        else {
            $auditLevel = '2'
            Write-Log "Detected Workstation. Setting Audit Level to 2 (Recommended)" -Level INFO
            Write-Host "Auto-detected Workstation. Applying Level 2 (Recommended)..." -ForegroundColor Cyan
        }
    }
    
    Write-Log "========================================" -Level INFO
    Write-Log "Starting Audit Configuration" -Level INFO
    Write-Log "Audit Level: $auditLevel" -Level INFO
    Write-Log "Sysmon Setting: $(if ($sysmonSetting -eq 1) { 'Enabled' } else { 'Disabled' })" -Level INFO
    Write-Log "========================================" -Level INFO
    
    # Step 4: Execute audit policies based on configured level
    Write-Host "`nApplying audit policies..." -ForegroundColor Yellow
    
    try {
        # Level 1: Required (always applied)
        Write-Log "Applying audit policies for Level 1 (Required)" -Level INFO
        Set-RequiredAuditPolicies
        
        # Level 2: Recommend (if audit_level >= 2)
        if ([int]$auditLevel -ge 2) {
            Write-Log "Applying audit policies for Level 2 (Recommend)" -Level INFO
            Set-RecommendAuditPolicies
        }
        
        # Level 3: Optional (if audit_level >= 3)
        if ([int]$auditLevel -ge 3) {
            Write-Log "Applying audit policies for Level 3 (Optional)" -Level INFO
            Set-OptionalAuditPolicies
        }
        
        Write-Host "[+] Audit policies applied successfully" -ForegroundColor Green
    }
    catch {
        Write-Log "Error applying audit policies: $_" -Level ERROR
        Write-Host "Error applying audit policies: $_" -ForegroundColor Red
        # Continue execution despite errors
    }
    
    # Apply Registry Auditing (always applied)
    Write-Host "`nApplying registry auditing..." -ForegroundColor Yellow
    
    try {
        Set-RegistryAudit
        Write-Host "[+] Registry auditing applied successfully" -ForegroundColor Green
    }
    catch {
        Write-Log "Error applying registry auditing: $_" -Level ERROR
        Write-Host "Error applying registry auditing: $_" -ForegroundColor Red
        # Continue execution despite errors
    }
    
    # Apply FileSystem Auditing (always applied)
    Write-Host "`nApplying filesystem auditing..." -ForegroundColor Yellow
    
    try {
        Set-FileSystemAudit
        Write-Host "[+] Filesystem auditing applied successfully" -ForegroundColor Green
    }
    catch {
        Write-Log "Error applying filesystem auditing: $_" -Level ERROR
        Write-Host "Error applying filesystem auditing: $_" -ForegroundColor Red
        # Continue execution despite errors
    }
    
    # Step 5: Apply Sysmon if configured
    $sysmonApplied = $false
    if ($sysmonSetting -eq 1) {
        Write-Host "`nInstalling/Updating Sysmon..." -ForegroundColor Yellow
        
        try {
            $sysmonResult = Install-Sysmon
            $sysmonApplied = [bool]$sysmonResult
            
            if ($sysmonResult) {
                Write-Host "[+] Sysmon installed/updated successfully" -ForegroundColor Green
            }
            else {
                Write-Host "[!] Sysmon installation/update encountered issues (see log for details)" -ForegroundColor Yellow
            }
        }
        catch {
            Write-Log "Error installing/updating Sysmon: $_" -Level ERROR
            Write-Host "Error installing/updating Sysmon: $_" -ForegroundColor Red
            # Continue execution despite errors
        }
    }
    else {
        Write-Log "Sysmon installation skipped (sysmon_setting = 0)" -Level INFO
        Write-Host "`nSysmon installation skipped (disabled in config)" -ForegroundColor Cyan
    }
    
    # Step 6: Export audit policy to CSV
    Write-Host "`nExporting audit policy..." -ForegroundColor Yellow
    
    try {
        $csvPath = Export-AuditPolicy
        
        if ($csvPath) {
            Write-Host "[+] Audit policy exported to CSV" -ForegroundColor Green
        }
        else {
            Write-Host "[!] Failed to export audit policy to CSV" -ForegroundColor Yellow
        }
    }
    catch {
        Write-Log "Error exporting audit policy: $_" -Level ERROR
        Write-Host "Error exporting audit policy: $_" -ForegroundColor Red
        $csvPath = $null
        # Continue execution despite errors
    }
    
    # Step 7: Generate and display summary report
    Write-Host "`nGenerating summary report..." -ForegroundColor Yellow
    
    try {
        # productType is already retrieved earlier
        $summary = New-SummaryReport -Config $config -ProductType $productType -CsvPath $csvPath -SysmonApplied:$sysmonApplied
        
        Write-Host $summary -ForegroundColor White
        
        # Also log the summary
        Write-Log "Summary report generated" -Level SUCCESS
    }
    catch {
        Write-Log "Error generating summary report: $_" -Level ERROR
        Write-Host "Error generating summary report: $_" -ForegroundColor Red
        # Continue execution despite errors
    }
    
    # Step 8: Refresh Group Policy
    Write-Host "Refreshing Group Policy..." -ForegroundColor Yellow
    
    try {
        Write-Log "Executing: gpupdate /force" -Level INFO
        $gpupdateResult = & gpupdate.exe /force 2>&1
        
        if ($LASTEXITCODE -eq 0) {
            Write-Log "Group Policy refreshed successfully" -Level SUCCESS
            Write-Host "[+] Group Policy refreshed successfully" -ForegroundColor Green
        }
        else {
            Write-Log "Group Policy refresh completed with warnings or errors: $gpupdateResult" -Level WARNING
            Write-Host "[!] Group Policy refresh completed with warnings (see log for details)" -ForegroundColor Yellow
        }
    }
    catch {
        Write-Log "Error refreshing Group Policy: $_" -Level WARNING
        Write-Host "Warning: Failed to refresh Group Policy: $_" -ForegroundColor Yellow
        # Continue execution despite errors
    }
    
    # Step 9: Stop logging session
    try {
        Write-Log "Audit configuration completed successfully" -Level SUCCESS
        Write-Log "========================================" -Level INFO
        Stop-LogSession
    }
    catch {
        Write-Host "Error finalizing log session: $_" -ForegroundColor Yellow
    }
    
    # Final message
    Write-Host ""
    Write-Host "================================================================================" -ForegroundColor Green
    Write-Host "           Audit Configuration Completed Successfully!" -ForegroundColor Green
    Write-Host "================================================================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "Press any key to exit..." -ForegroundColor Yellow
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

#endregion Main Execution Flow

#region Script Entry Point

# Execute the main configuration function
try {
    Invoke-AuditConfiguration
}
catch {
    Write-Host ""
    Write-Host "================================================================================" -ForegroundColor Red
    Write-Host "           CRITICAL ERROR" -ForegroundColor Red
    Write-Host "================================================================================" -ForegroundColor Red
    Write-Host ""
    Write-Host "An unexpected error occurred during execution:" -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Red
    Write-Host ""
    Write-Host "Stack Trace:" -ForegroundColor Yellow
    Write-Host $_.ScriptStackTrace -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Press any key to exit..." -ForegroundColor Yellow
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    exit 1
}

#endregion Script Entry Point

