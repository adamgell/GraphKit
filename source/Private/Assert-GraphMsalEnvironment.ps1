<#
    Private: import-time MSAL environment guard.

    GraphKit late-binds to MSAL.NET, delivered transitively by the
    Microsoft.Graph.Authentication module (Connect-MgGraph is never called). That
    assembly is a private implementation detail of the SDK: several modules bundle
    competing copies (Az.Accounts ships newer, Microsoft.PowerShell.PSResourceGet
    ships older), and in the default .NET load context the FIRST copy loaded into
    the process wins for every consumer. This guard runs when GraphKit is imported:
    it detects the version that actually won and refuses to continue when that
    version is absent or below GraphKit's tested minimum, so a silent version
    regression cannot surface for the first time at token acquisition inside a
    customer engagement.
#>

# GraphKit's tested-minimum MSAL version (as shipped by Microsoft.Graph.Authentication).
$script:GraphMsalTestedMinimum = [version] '4.82.1'

function Get-GraphMsalSdkAssemblyPath {
    <#
        Private: resolve the filesystem path of the Microsoft.Identity.Client.dll
        delivered by the Microsoft.Graph.Authentication module. PowerShell 7 loads
        the Core (netstandard) copy; the Desktop copy is Windows PowerShell 5.1-only.
    #>

    $module = Get-Module 'Microsoft.Graph.Authentication' -ErrorAction SilentlyContinue |
        Sort-Object Version -Descending | Select-Object -First 1
    if ($null -eq $module) {
        $module = Get-Module 'Microsoft.Graph.Authentication' -ListAvailable -ErrorAction SilentlyContinue |
            Sort-Object Version -Descending | Select-Object -First 1
    }
    if ($null -eq $module) {
        return $null
    }

    $core = Join-Path $module.ModuleBase 'Dependencies/Core/Microsoft.Identity.Client.dll'
    if (Test-Path $core) {
        return $core
    }

    $bundled = Get-ChildItem -Path $module.ModuleBase -Recurse -Filter 'Microsoft.Identity.Client.dll' -ErrorAction SilentlyContinue |
        Select-Object -First 1
    if ($bundled) {
        return $bundled.FullName
    }

    return $null
}

function Get-GraphLoadedMsalVersion {
    [CmdletBinding()]
    [OutputType([version])]
    param()

    # First-load-wins: if a Microsoft.Identity.Client assembly is already loaded, its
    # version is the one every late-bound consumer in this process will use, whatever
    # module delivered it.
    $loaded = [AppDomain]::CurrentDomain.GetAssemblies() |
        Where-Object { $_.GetName().Name -eq 'Microsoft.Identity.Client' } |
        Select-Object -First 1
    if ($loaded) {
        return $loaded.GetName().Version
    }

    # Nothing loaded yet: load the SDK's bundled copy so the guard can detect the
    # version that will win for this process, and make the MSAL surface available.
    $sdkPath = Get-GraphMsalSdkAssemblyPath
    if ($null -eq $sdkPath) {
        throw "GraphKit could not locate Microsoft.Identity.Client.dll because the 'Microsoft.Graph.Authentication' module (or its bundled MSAL dependency) was not found on this system."
    }

    return ([System.Reflection.Assembly]::LoadFrom($sdkPath)).GetName().Version
}

function Test-GraphMsalVersion {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        [object] $Loaded
    )

    if ($null -eq $Loaded) {
        return $false
    }

    try {
        $parsed = if ($Loaded -is [version]) { $Loaded } else { [version] $Loaded }
    } catch {
        return $false
    }

    return ($parsed -ge $script:GraphMsalTestedMinimum)
}

# ---------------------------------------------------------------------------
# Import-time guard. This top-level code runs when ModuleBuilder concatenates
# this file into GraphKit.psm1, i.e. on every Import-Module GraphKit.
# ---------------------------------------------------------------------------
$foundMsalVersion = $null
$guardFailure = $null

try {
    $foundMsalVersion = Get-GraphLoadedMsalVersion
    if (-not (Test-GraphMsalVersion -Loaded $foundMsalVersion)) {
        $guardFailure = "the loaded Microsoft.Identity.Client assembly reports version $foundMsalVersion, which is below GraphKit's tested minimum of $script:GraphMsalTestedMinimum"
    }
} catch {
    $guardFailure = $_.Exception.Message
}

if ($guardFailure) {
    $foundText = if ($foundMsalVersion) { $foundMsalVersion.ToString() } else { '<none>' }

    throw @"
GraphKit import aborted: the MSAL environment check failed.

Found    : Microsoft.Identity.Client $foundText
Required : Microsoft.Identity.Client $($script:GraphMsalTestedMinimum) or later
Cause    : $guardFailure
Dependency: Microsoft.Graph.Authentication is GraphKit's pinned MSAL delivery vehicle (Connect-MgGraph is never called); a copy at or above its pinned minimum must be present.
Hazard   : Microsoft.Identity.Client is a private implementation detail of Microsoft.Graph.Authentication. In the default .NET load context the FIRST copy loaded into the process wins for everyone. Az.Accounts bundles a newer copy and Microsoft.PowerShell.PSResourceGet an older one; if either loaded before GraphKit, its copy wins and may sit below the tested minimum. Reorder imports so Microsoft.Graph.Authentication loads its MSAL first (or fix the conflicting module's version), then re-import GraphKit.
"@
}
