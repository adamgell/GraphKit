function Assert-GraphOperationAuthMode {
    <#
        .SYNOPSIS
            Refuses a descriptor-driven operation when its persisted auth-mode
            declaration excludes the context's token source.

        .DESCRIPTION
            Provider is an injected, non-persistable context source and is deliberately
            outside descriptor SupportedAuthModes. Descriptor policy applies only to the
            four profile AuthMethod values validated by Import-GraphOperationDescriptor.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject] $Context,

        [Parameter(Mandatory)]
        [hashtable] $Descriptor
    )

    if ($null -eq $Context.TokenSource) {
        throw 'Descriptor-driven operations require a context token source to enforce SupportedAuthModes.'
    }

    $authMode = [string] $Context.TokenSource.AuthMode
    if ([string]::IsNullOrWhiteSpace($authMode)) {
        throw 'Descriptor-driven operations require a context token source with an AuthMode.'
    }

    if ($authMode -eq 'Provider') {
        return $true
    }

    $supportedAuthModes = @($Descriptor.SupportedAuthModes)
    if ($supportedAuthModes -notcontains $authMode) {
        throw "Operation '$($Descriptor.Type)/$($Descriptor.Operation)' does not support auth mode '$authMode'."
    }

    return $true
}
