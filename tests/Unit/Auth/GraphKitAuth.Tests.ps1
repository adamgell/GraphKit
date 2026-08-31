BeforeAll {
    $script:repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../../..')).ProviderPath
    $script:contractsPath = Join-Path $script:repoRoot 'src/GraphKit.Auth/GraphKit.Auth.Contracts/bin/Release/net8.0/GraphKit.Auth.Contracts.dll'
    $script:contractsAssembly = $null

    if (Test-Path -LiteralPath $script:contractsPath -PathType Leaf) {
        $resolvedContractsPath = (Resolve-Path -LiteralPath $script:contractsPath).ProviderPath
        $loadedContracts = @(
            [System.Runtime.Loader.AssemblyLoadContext]::Default.Assemblies |
                Where-Object { $_.GetName().Name -ceq 'GraphKit.Auth.Contracts' }
        )

        if ($loadedContracts.Count -eq 1) {
            $script:contractsAssembly = $loadedContracts[0]
        }
        elseif ($loadedContracts.Count -eq 0) {
            $script:contractsAssembly = [System.Runtime.Loader.AssemblyLoadContext]::Default.LoadFromAssemblyPath(
                $resolvedContractsPath
            )
        }
    }

    function Get-GraphKitAuthPublicSignatureTypes {
        param(
            [Parameter(Mandatory)]
            [System.Reflection.Assembly] $Assembly
        )

        $seen = [System.Collections.Generic.HashSet[System.Type]]::new()

        function Add-SignatureType {
            param([System.Type] $Type)

            if ($null -eq $Type -or -not $seen.Add($Type)) {
                return
            }

            if ($Type.HasElementType) {
                Add-SignatureType -Type $Type.GetElementType()
            }

            foreach ($argument in $Type.GetGenericArguments()) {
                Add-SignatureType -Type $argument
            }

            if ($Type.IsGenericParameter) {
                foreach ($constraint in $Type.GetGenericParameterConstraints()) {
                    Add-SignatureType -Type $constraint
                }
            }
        }

        $bindingFlags = [System.Reflection.BindingFlags]'Public,Instance,Static'
        foreach ($type in $Assembly.GetExportedTypes()) {
            Add-SignatureType -Type $type
            Add-SignatureType -Type $type.BaseType

            foreach ($interface in $type.GetInterfaces()) {
                Add-SignatureType -Type $interface
            }

            foreach ($member in $type.GetMembers($bindingFlags)) {
                Add-SignatureType -Type $member.DeclaringType

                if ($member -is [System.Reflection.MethodInfo]) {
                    Add-SignatureType -Type $member.ReturnType
                    foreach ($argument in $member.GetGenericArguments()) {
                        Add-SignatureType -Type $argument
                    }
                    foreach ($parameter in $member.GetParameters()) {
                        Add-SignatureType -Type $parameter.ParameterType
                    }
                }
                elseif ($member -is [System.Reflection.ConstructorInfo]) {
                    foreach ($parameter in $member.GetParameters()) {
                        Add-SignatureType -Type $parameter.ParameterType
                    }
                }
                elseif ($member -is [System.Reflection.PropertyInfo]) {
                    Add-SignatureType -Type $member.PropertyType
                    foreach ($parameter in $member.GetIndexParameters()) {
                        Add-SignatureType -Type $parameter.ParameterType
                    }
                }
                elseif ($member -is [System.Reflection.FieldInfo]) {
                    Add-SignatureType -Type $member.FieldType
                }
                elseif ($member -is [System.Reflection.EventInfo]) {
                    Add-SignatureType -Type $member.EventHandlerType
                }
            }
        }

        return @($seen)
    }
}

Describe 'GraphKit.Auth ABI v1 contract' -Tag 'Unit' {
    It 'loads the contract assembly with the exact ABI marker and Acquire result' {
        $script:contractsPath | Should -Exist -Because 'Task 3 must build the dependency-free GraphKit.Auth contract assembly'
        $script:contractsAssembly | Should -Not -BeNullOrEmpty -Because 'exactly one contracts assembly must load in the default AssemblyLoadContext'

        [GraphKit.Auth.GraphAuthHost]::ContractMarker | Should -Be 'GraphKit.Auth.Abi/1'
        [GraphKit.Auth.IGraphTokenSource].GetMethod('Acquire').ReturnType.FullName |
            Should -Be 'GraphKit.Auth.GraphTokenResult'
    }

    It 'keeps Microsoft.Identity.Client out of every public contract signature' {
        $script:contractsPath | Should -Exist -Because 'the public GraphKit.Auth surface can only be inspected after Task 3 builds it'
        $script:contractsAssembly | Should -Not -BeNullOrEmpty -Because 'the complete public ABI must be available for reflection'

        $signatureTypes = @(Get-GraphKitAuthPublicSignatureTypes -Assembly $script:contractsAssembly)
        $leaks = @(
            $signatureTypes | Where-Object {
                [string] $_.FullName -like '*Microsoft.Identity.Client*' -or
                [string] $_.Assembly.FullName -like '*Microsoft.Identity.Client*'
            }
        )

        $leaks.FullName | Should -BeNullOrEmpty -Because 'no MSAL type may cross the GraphKit-owned ABI boundary'
    }
}
