<#
.SCRIPT
    Server_hardening.ps1
    Skript för att härda Windows-server enligt CIS/NIST-standarder.
    Version: 1.1.0
    Författare: Henriette Heikki 
    Datum: 2025-05-12
    Beskrivning: Automatiserar säkerhetshärdning av Windows-server.
.SYNOPSIS
    Omfattande säkerhetskontroll och härdning av Windows-server enligt CIS/NIST.
.DESCRIPTION
    Detta skript automatiserar härdning:
      • Windows Firewall
      • Windows Defender
      • Administratörsgrupp
      • Osäkra protokoll (SMBv1)
      • Onödiga tjänster
      • Diskutrymme & temporära filer
      • BitLocker
      • Tidsstämplad loggning
.PARAMETER ConfigPath
    Sökväg till JSON-konfiguration. Om inte angiven används interna standardvärden.
.VERSION
    1.1.0
.CHANGELOG
    2025-05-12:
      - Utökad felhantering per funktion
      - Avancerad parameterhantering (ConfigPath)
      - Validering av konfigurationsvärden
      - Versionsnummer och changelog tillagt
.NOTES
    Kör med administratörsrättigheter (Run as Administrator).
#>

[CmdletBinding()]
param(
    [string]$ConfigPath = ""
)

# --- LÄS OCH VALIDERA KONFIGURATION ---
try {
    if ($ConfigPath) {
        Write-Host "Läser konfiguration från $ConfigPath" 
        $config = Get-Content $ConfigPath -ErrorAction Stop | ConvertFrom-Json 
    }
    else {
        # Standardkonfiguration
        $today = Get-Date -Format 'yyyyMMdd'
        $config = @{ 
            LogPath          = "C:\SecLogs\security_hardening_$today.log" # Loggfil med datumstämpel
            ApprovedAdmins   = "C:\SecConfig\approved_users.txt"       # Fil med godkända admins
            TempArchive      = "C:\TempArchive"                         # Mapp för arkivering av tillfälliga filer
            MinFreePercent   = 15                                   # Minsta % ledigt diskutrymme
            FirewallProfiles = @('Domain','Private','Public')      # Brandväggsprofiler
            AllowedPorts     = @(3389,443)   
            UnsafeProtocols  = @('SMB1')                       # Protokoll att inaktivera
            DisabledServices = @('Telnet','FTP','SNMP') # Tjänster att stoppa och inaktivera
            SystemDrive      = "$($env:SystemDrive)\" # Systemdriven (t.ex. C:\) 
        }
    }

    # Validera MinFreePercent som heltal mellan 1 och 100.
    if (-not ($config.MinFreePercent -is [int])) {  
        throw "MinFreePercent ($($config.MinFreePercent)) är inte ett heltal."
    } 
    if (($config.MinFreePercent -lt 1) -or ($config.MinFreePercent -gt 100)) {
        throw "MinFreePercent ($($config.MinFreePercent)) måste vara mellan 1 och 100."
    } 
    # Skapa loggkatalog om den saknas.
    $logDir = Split-Path $config.LogPath -Parent
    if (-not (Test-Path $logDir)) {
        New-Item -Path $logDir -ItemType Directory -Force | Out-Null
    }
}
catch {
    Write-Error "KONFIG-FEL: $_"
    exit 1
}

# Starta sessionstranskribering
Start-Transcript -Path $config.LogPath -Append | Out-Null

# Skriver tidsstämplad rad till konsol och loggfil
function Write-Log {
    param([string]$Message)
    $ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $entry = "[$ts] $Message"
    Write-Host  $entry
    Add-Content -Path $config.LogPath -Value $entry
}

# --- FUNKTIONSDEFINITIONER MED FELHANTERING ---
function Test-InitialConditions {
    [CmdletBinding()] param()
    try {
        Write-Log 'Kontrollerar TPM för BitLocker.'
        if (-not (Get-Tpm).TpmPresent) { throw 'TPM saknas.' }
        Write-Log 'TPM närvaro bekräftad.'

        Write-Log "Kontrollerar att '$($config.ApprovedAdmins)' finns."
        if (-not (Test-Path $config.ApprovedAdmins)) { throw 'approved_users.txt saknas.' }
        Write-Log 'Godkänd admin-lista hittad.'

        return $true
    }
    catch {
        Write-Log "FEL i Test-InitialConditions: $_"
        Stop-Transcript | Out-Null
        exit 1
    }
}

# --- FUNKTIONER FÖR HÄRDNING ---
function Set-SecureFirewall {
    [CmdletBinding()] param()
    try {
        foreach ($profile in $config.FirewallProfiles) {
            Write-Log "Konfigurerar brandväggsprofil: $profile"
            Set-NetFirewallProfile -Profile $profile `
                -Enabled True `
                -DefaultInboundAction Block `
                -DefaultOutboundAction Allow

            foreach ($port in $config.AllowedPorts) {
                if (-not (Get-NetFirewallRule -DisplayName "Allow_TCP_$port" -ErrorAction SilentlyContinue)) {
                    New-NetFirewallRule -DisplayName "Allow_TCP_$port" `
                        -Direction Inbound -Protocol TCP -LocalPort $port -Action Allow
                    Write-Log "Regel skapad: Allow_TCP_$port"
                }
            }
        }
        Write-Log 'Brandväggskonfiguration slutförd.'
    }
    catch {
        Write-Log "FEL i Set-SecureFirewall: $_"
    }
}

function Update-Defender {
    [CmdletBinding()] param()
    try {
        Write-Log 'Uppdaterar Defender-signaturer.'
        Update-MpSignature | Out-Null

        Write-Log 'Startar full Defender-skanning i bakgrunden.'
        Start-MpScan -ScanType FullScan -AsJob | Out-Null

        $status = Get-MpComputerStatus
        if (-not $status.AntivirusEnabled) {
            Set-MpPreference -DisableRealtimeMonitoring $false
            Write-Log 'Realtidsskydd aktiverat.'
        }
        Write-Log 'Defender-åtgärder slutförda.'
    }
    catch {
        Write-Log "FEL i Update-Defender: $_"
    }
}

function Manage-LocalAdmins {
    [CmdletBinding()] param()
    try {
        Write-Log 'Hanterar Administratörsgruppen.'
        $approved = Get-Content $config.ApprovedAdmins |
                    Where-Object { $_ -and -not $_.StartsWith('#') }

        $current = Get-LocalGroupMember -Group Administrators |
                   Select-Object -ExpandProperty Name

        foreach ($user in $current) {
            if ($user -notin $approved) {
                Remove-LocalGroupMember -Group Administrators -Member $user -Confirm:$false
                Write-Log "Obehörig admin borttagen: $user"
            }
        }

        Get-LocalUser |
            Where-Object { $_.Enabled -and $_.LastLogon -lt (Get-Date).AddDays(-90) } |
            ForEach-Object {
                Disable-LocalUser -Name $_.Name
                Write-Log "Inaktiverat konto (>90 dagar): $($_.Name)"
            }
        Write-Log 'Admin-hantering klar.'
    }
    catch {
        Write-Log "FEL i Manage-LocalAdmins: $_"
    }
}

function Disable-UnsecureProtocols {
    [CmdletBinding()] param()
    try {
        Write-Log 'Inaktiverar osäkra protokoll (SMBv1).'
        Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' `
            -Name SMB1 -Value 0 -Force
        Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10' `
            -Name Start -Value 4 -Force
        Write-Log 'SMBv1 inaktiverat.'
    }
    catch {
        Write-Log "FEL i Disable-UnsecureProtocols: $_"
    }
}

function Manage-Services {
    [CmdletBinding()] param()
    try {
        foreach ($svc in $config.DisabledServices) {
            if (Get-Service -Name $svc -ErrorAction SilentlyContinue) {
                Write-Log "Stoppar tjänst: $svc"
                Stop-Service -Name $svc -Force
                Set-Service  -Name $svc -StartupType Disabled
                Write-Log "Tjänst inaktiverad: $svc"
            }
        }
        Write-Log 'Tjänstehantering klar.'
    }
    catch {
        Write-Log "FEL i Manage-Services: $_"
    }
}

function Check-DiskSpace {
    [CmdletBinding()] param()
    try {
        $drive   = Get-PSDrive -Name $config.SystemDrive.TrimEnd(':')
        $freePct = [math]::Round(($drive.Free / ($drive.Used + $drive.Free)) * 100,1)
        Write-Log "Systemdisk ledigt: $freePct%"

        if ($freePct -lt $config.MinFreePercent) {
            Write-Log "Utrymme < $($config.MinFreePercent)% – arkiverar TEMP."
            if (-not (Test-Path $config.TempArchive)) {
                New-Item -Path $config.TempArchive -ItemType Directory -Force | Out-Null
            }
            Get-ChildItem -Path $env:TEMP -Recurse -ErrorAction SilentlyContinue |
                ForEach-Object {
                    $timestamp = Get-Date -Format 'yyyyMMddHHmmss'
                    $dest = Join-Path $config.TempArchive "$($_.BaseName)_$timestamp$($_.Extension)"
                    Move-Item -Path $_.FullName -Destination $dest -Force -ErrorAction SilentlyContinue
                }
            Write-Log 'Arkivering klar.'
        }
    }
    catch {
        Write-Log "FEL i Check-DiskSpace: $_"
    }
}

function Configure-BitLocker {
    [CmdletBinding()] param()
    try {
        Write-Log 'Kontrollerar BitLocker-status.'
        $bl = Get-BitLockerVolume -MountPoint $config.SystemDrive
        if ($bl.VolumeStatus -ne 'FullyEncrypted') {
            Write-Log 'Initierar BitLocker-kryptering.'
            Add-BitLockerKeyProtector -MountPoint $config.SystemDrive -TpmProtector | Out-Null
            Enable-BitLocker     -MountPoint $config.SystemDrive `
                                  -TpmProtector -UsedSpaceOnly | Out-Null
            Write-Log 'BitLocker initierad.'
        }
        else {
            Write-Log 'BitLocker redan aktiverat.'
        }
    }
    catch {
        Write-Log "FEL i Configure-BitLocker: $_"
    }
}

# --- HUVUDLOGIK ---
if (Test-InitialConditions) {
    Set-SecureFirewall
    Update-Defender
    Manage-LocalAdmins
    Disable-UnsecureProtocols
    Manage-Services
    Check-DiskSpace
    Configure-BitLocker
    Write-Log 'Härdning komplett. Kontrollera loggfil för detaljer.'
}

Stop-Transcript | Out-Null