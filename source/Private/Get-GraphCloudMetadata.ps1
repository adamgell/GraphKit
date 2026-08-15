<#
    Private: resolve a Graph cloud name to its metadata.

    The cloud table is the single source of truth for a cloud's Graph base URI,
    OAuth authority and audience resource. The audience resource identifier
    (https://graph.microsoft.com) is the well-known Graph application-id URI and
    is identical across clouds; only the base URI and the login authority change.
#>

function Get-GraphCloudMetadata {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory, Position = 0)]
        [string] $Name
    )

    $clouds = @{
        'Global'   = @{ GraphBaseUri = 'https://graph.microsoft.com';             Authority = 'https://login.microsoftonline.com'; Resource = 'https://graph.microsoft.com' }
        'China'    = @{ GraphBaseUri = 'https://microsoftgraph.chinacloudapi.cn'; Authority = 'https://login.chinacloudapi.cn';     Resource = 'https://graph.microsoft.com' }
        'Germany'  = @{ GraphBaseUri = 'https://graph.microsoft.de';              Authority = 'https://login.microsoftonline.de'; Resource = 'https://graph.microsoft.com' }
        'USGov'    = @{ GraphBaseUri = 'https://graph.microsoft.us';              Authority = 'https://login.microsoftonline.us'; Resource = 'https://graph.microsoft.com' }
        'USGovDoD' = @{ GraphBaseUri = 'https://dod-graph.microsoft.us';          Authority = 'https://login.microsoftonline.us'; Resource = 'https://graph.microsoft.com' }
    }

    if (-not $clouds.ContainsKey($Name)) {
        $valid = ($clouds.Keys | Sort-Object) -join ', '
        throw "Unknown Graph cloud '$Name'. Valid clouds are: $valid."
    }

    return @{
        Name         = $Name
        GraphBaseUri = [uri] $clouds[$Name].GraphBaseUri
        Authority    = $clouds[$Name].Authority
        Resource     = $clouds[$Name].Resource
    }
}
