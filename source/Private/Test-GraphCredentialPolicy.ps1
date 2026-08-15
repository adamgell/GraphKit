<#
    .SYNOPSIS
        Enforces the non-bypassable credential policy for a request URI before any send.

    .DESCRIPTION
        GraphBearer demands HTTPS plus an exact match against the cloud-specific Graph authority
        for the supplied context. None demands HTTPS plus a host on the descriptor's allowlist and
        sends no credential at all. A violation is a hard error naming the offending authority,
        never a silent downgrade to an unauthenticated request and never a silent send. This check
        runs even for -Raw requests, because descriptor bypass does not bypass credential policy.

    .NOTES
        Returns $true when the URI is compliant and throws otherwise.
#>
function Test-GraphCredentialPolicy {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory, Position = 0)]
        [uri] $Uri,

        [Parameter(Mandatory)]
        [hashtable] $Descriptor,

        [Parameter()]
        [PSCustomObject] $Context
    )

    switch ($Descriptor.CredentialPolicy) {
        'GraphBearer' {
            if ($null -eq $Context) {
                throw "Credential policy 'GraphBearer' requires a context to validate the Graph authority."
            }

            # HTTPS + exact authority match (port 443 only). Reuses the nextLink guard so both
            # direct requests and paging hops share one authority definition.
            $null = Test-GraphNextLinkAuthority -NextLink $Uri -Context $Context
            return $true
        }

        'None' {
            if ($null -eq $Uri -or -not $Uri.IsAbsoluteUri -or $Uri.Scheme -ne 'https') {
                throw "Credential policy 'None' requires an HTTPS URI; refusing to send credentials-free to '{0}'." -f $Uri.AbsoluteUri
            }

            # The loader enforces a non-empty allowlist; re-check here so -Raw synthesized
            # descriptors and future callers can never slip an empty allowlist through.
            $allowedHosts = @($Descriptor.AllowedHosts | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
            if ($allowedHosts.Count -eq 0) {
                throw "Credential policy 'None' requires a non-empty AllowedHosts allowlist; refusing to send."
            }

            $hostName = $Uri.Host.ToLowerInvariant()
            $normalized = @($allowedHosts | ForEach-Object { $_.ToLowerInvariant() })
            if ($normalized -notcontains $hostName) {
                throw (
                    "Credential policy 'None' does not allow host '{0}' - allowed hosts: {1}." +
                    ' Refusing to send.'
                ) -f $Uri.Host, ($allowedHosts -join ', ')
            }

            return $true
        }

        default {
            throw "Unknown CredentialPolicy '{0}' - refusing to send." -f $Descriptor.CredentialPolicy
        }
    }
}
