#Requires -Version 7.0
# Read-only host assessment. No feature activation, VM, ACL or execution fallback.
[CmdletBinding()]
param([string]$FactsJson)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$keys = @('platform', 'edition', 'build', 'hyperv_feature', 'hyperv_module', 'vmms_running', 'hypervisor_present')
$source = 'local_read_only_probe'
$facts = [ordered]@{
    platform = 'non_windows'; edition = $null; build = $null
    hyperv_feature = 'unknown'; hyperv_module = $null
    vmms_running = $null; hypervisor_present = $null
}
$invalid = $false
if ($PSBoundParameters.ContainsKey('FactsJson')) {
    $source = 'supplied_facts'
    try {
        if ($FactsJson.Length -gt 8192) { throw 'size' }
        $document = [System.Text.Json.JsonDocument]::Parse($FactsJson)
        try {
            if ($document.RootElement.ValueKind -ne 'Object') { throw 'object' }
            $seen = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
            foreach ($property in $document.RootElement.EnumerateObject()) {
                if (-not $seen.Add($property.Name)) { throw 'duplicate' }
            }
        } finally { $document.Dispose() }
        $inputFacts = ConvertFrom-Json -InputObject $FactsJson -AsHashtable
        if ($inputFacts.Count -ne $keys.Count) { throw 'schema' }
        foreach ($key in $inputFacts.Keys) { if ($key -cnotin $keys) { throw 'schema' } }
        if ($inputFacts.platform -cnotin @('windows', 'non_windows') -or
            ($null -ne $inputFacts.edition -and ($inputFacts.edition -isnot [string] -or $inputFacts.edition.Length -gt 64)) -or
            ($null -ne $inputFacts.build -and ($inputFacts.build -isnot [long] -and $inputFacts.build -isnot [int])) -or
            $inputFacts.hyperv_feature -cnotin @('unknown', 'enabled', 'disabled')) { throw 'types' }
        foreach ($key in @('hyperv_module', 'vmms_running', 'hypervisor_present')) {
            if ($null -ne $inputFacts[$key] -and $inputFacts[$key] -isnot [bool]) { throw 'types' }
        }
        $facts = $inputFacts
    } catch { $invalid = $true; $facts = $null }
} elseif ($IsWindows) {
    $facts.platform = 'windows'
    try {
        $os = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
        $facts.edition = [string]$os.EditionID
        $facts.build = [int]$os.CurrentBuildNumber
    } catch { } # Missing/denied facts remain unknown, never Enabled.
    try { $facts.hyperv_module = $null -ne (Get-Module -ListAvailable -Name Hyper-V | Select-Object -First 1) } catch { }
    try { $facts.vmms_running = (Get-Service -Name vmms).Status -eq 'Running' } catch { }
    # Home cannot support this role. Avoid unnecessary privileged DISM/CIM calls.
    if ($facts.edition -in @('Professional', 'Enterprise', 'Education', 'ServerStandard', 'ServerDatacenter')) {
        try {
            $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
            $principal = [Security.Principal.WindowsPrincipal]::new($identity)
            if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
                $feature = Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All
                if ($feature.State -eq 'Enabled') { $facts.hyperv_feature = 'enabled' }
                elseif ($feature.State -eq 'Disabled') { $facts.hyperv_feature = 'disabled' }
            }
        } catch { }
        try {
            $system = Get-CimInstance -ClassName Win32_ComputerSystem -Property HypervisorPresent -OperationTimeoutSec 3
            $facts.hypervisor_present = [bool]$system.HypervisorPresent
        } catch { }
    }
}

$blocked = [System.Collections.Generic.List[string]]::new()
$unknown = [System.Collections.Generic.List[string]]::new()
if ($invalid) { $status = 'INVALID_FACTS' }
else {
    if ($facts.platform -ne 'windows') { $blocked.Add('WINDOWS_HOST_REQUIRED') }
    if ($null -eq $facts.edition) { $unknown.Add('WINDOWS_EDITION_UNKNOWN') }
    elseif ($facts.edition -notin @('Professional', 'Enterprise', 'Education', 'ServerStandard', 'ServerDatacenter')) {
        $blocked.Add('UNSUPPORTED_WINDOWS_EDITION')
    }
    if ($null -eq $facts.build) { $unknown.Add('WINDOWS_BUILD_UNKNOWN') }
    elseif (($facts.edition -like 'Server*' -and $facts.build -lt 20348) -or
            ($facts.edition -notlike 'Server*' -and $facts.build -lt 22000)) { $blocked.Add('UNSUPPORTED_WINDOWS_BUILD') }
    if ($facts.hyperv_feature -eq 'unknown') { $unknown.Add('HYPERV_FEATURE_UNKNOWN') }
    elseif ($facts.hyperv_feature -ne 'enabled') { $blocked.Add('HYPERV_FEATURE_DISABLED') }
    foreach ($pair in @(@('hyperv_module', 'HYPERV_MODULE'), @('vmms_running', 'VMMS_STATE'), @('hypervisor_present', 'HYPERVISOR_STATE'))) {
        if ($null -eq $facts[$pair[0]]) { $unknown.Add($pair[1] + '_UNKNOWN') }
        elseif (-not $facts[$pair[0]]) { $blocked.Add($pair[1] + '_UNAVAILABLE') }
    }
    $status = if ($blocked.Count -gt 0) { 'BLOCKED' } elseif ($unknown.Count -gt 0) { 'UNKNOWN' } else { 'HOST_READY' }
}
[ordered]@{
    schema_version = 1; profile = 'windows-hyperv-guest-v1'; status = $status
    read_only = $true; execution_admitted = $false; evidence_source = $source
    facts = $facts; reasons = @($blocked.ToArray()) + @($unknown.ToArray())
    remaining_conditions = @('REVIEWED_GUEST_AND_REAL_GATES_REQUIRED')
} | ConvertTo-Json -Depth 6 -Compress
