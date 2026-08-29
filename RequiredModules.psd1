@{
    <#
        This is only required if you need to use the method PowerShellGet & PSDepend
        It is not required for PSResourceGet or ModuleFast (and will be ignored).
        See Resolve-Dependency.psd1 on how to enable methods.
    #>
    #PSDependOptions             = @{
    #    AddToPath  = $true
    #    Target     = 'output\RequiredModules'
    #    Parameters = @{
    #        Repository = 'PSGallery'
    #    }
    #}

    InvokeBuild                 = '5.14.23'
    PSScriptAnalyzer            = '1.25.0'
    Pester                      = '6.1.0'
    ModuleBuilder               = '3.1.8'
    ChangelogManagement         = '3.1.0'
    Sampler                     = '0.120.1'




    # Dependencies resolved for build and test. Graph Authentication is also the hard runtime
    # dependency; SecretManagement remains here so CI exercises vault paths while the module
    # loads and validates it only when a vault-backed credential is used.
    'Microsoft.Graph.Authentication'        = '2.38.1'
    'Microsoft.PowerShell.SecretManagement' = '1.1.2'
}
