<#
    Verification-only GraphKit.Auth protected parity runner.

    This script never provisions credentials, profiles, permissions, app registrations, modules,
    repositories, Azure resources, or live infrastructure. Its only live behavior, when explicitly
    invoked in the Live parameter set, is one existing-profile context resolution and one
    ManagedDevice.List read through the exact supplied package.
#>
[CmdletBinding(DefaultParameterSetName = 'Live')]
param(
    [Parameter(Mandatory)] [string] $PackagePath,
    [Parameter(Mandatory)] [string] $PackageSha256,
    [Parameter(Mandatory)] [string] $AuthMode,
    [Parameter(Mandatory, ParameterSetName = 'Live')] [string] $ProfileId,
    [Parameter(ParameterSetName = 'Live')] [string] $StorePath,
    [Parameter(Mandatory, ParameterSetName = 'DryRun')] [switch] $DryRun
)

Set-StrictMode -Version Latest

$script:GraphKitAuthParityModes = @('Certificate','ClientSecret','ManagedIdentity','BearerToken')
$script:GraphKitAuthParityFailureStages = @(
    'None','Artifact','Import','Context','Acquisition','Read','Diagnostics','Cleanup','Evidence')
$script:GraphKitAuthParityFailureCodes = @(
    'None','ArtifactRejected','ImportRejected','ContextRejected','AcquisitionFailed','ReadFailed',
    'DiagnosticsRejected','CleanupFailed','EvidenceRejected')
$script:GraphKitAuthParityChecks = @(
    'packageDigestMatched','snapshotBound','archiveValidated','extractionSealed','exactImport',
    'routeMatched','contextMatched','sourceMatched','tenantProofVerified','cleanupVerified')
$script:GraphKitAuthParityAdapterChecks = @(
    'abiMarkerExact','contractsDefault','providerCollectibleNonDefault','msalVersionExact',
    'providerMsalSameContext','publicAbiExact')
$script:GraphKitAuthParityExpectedPublicAbiSha256 =
    '5b808693dfcd58c1b8b8a093caa789d8b5f9ce87f1bc57c6a1d8628077efc1f1'
$script:GraphKitAuthParityExpectedNativeSourceSha256 =
    'c4132fbc857e8c96e741c6f0eda371f62ec59bd61c669573faaab18d998a3808'
$script:GraphKitAuthParityNativeType = $null
$script:GraphKitAuthParityMaxEntries = 4096
$script:GraphKitAuthParityMaxPackageBytes = 512MB
$script:GraphKitAuthParityMaxEntryBytes = 64MB
$script:GraphKitAuthParityMaxTotalBytes = 256MB
$script:GraphKitAuthParityRatioThresholdBytes = 1MB
$script:GraphKitAuthParityMaxCompressionRatio = 200
$script:GraphKitAuthParityMarkerName = '.graphkit-auth-parity-runner'
$script:GraphKitAuthParitySnapshotName = 'candidate.nupkg'
$script:GraphKitAuthParityModuleName = 'module'

function Get-GraphKitAuthParityAbiTypeDisplayName {
    param([Parameter(Mandatory)][Type] $Type)
    if ($Type.IsArray) {
        return "$(Get-GraphKitAuthParityAbiTypeDisplayName -Type $Type.GetElementType())[]"
    }
    if ($Type.IsGenericType) {
        $definition = $Type.GetGenericTypeDefinition().FullName
        $definition = $definition.Substring(0, $definition.IndexOf('`'))
        $arguments = @($Type.GetGenericArguments() | ForEach-Object {
            Get-GraphKitAuthParityAbiTypeDisplayName -Type $_
        }) -join ','
        return "$definition<$arguments>"
    }
    return $Type.FullName
}

function Get-GraphKitAuthParityAbiParameterDisplay {
    param([Parameter(Mandatory)][Reflection.ParameterInfo] $Parameter)
    "$(Get-GraphKitAuthParityAbiTypeDisplayName -Type $Parameter.ParameterType) $($Parameter.Name)"
}

function Get-GraphKitAuthParityAbiNullabilityDisplay {
    param([Reflection.NullabilityInfo] $Info)
    if ($null -eq $Info) { return '<none>' }

    $display = "$($Info.ReadState)/$($Info.WriteState)"
    if ($null -ne $Info.ElementType) {
        $display += ";element=$(Get-GraphKitAuthParityAbiNullabilityDisplay -Info $Info.ElementType)"
    }
    if ($Info.GenericTypeArguments.Count -ne 0) {
        $arguments = @($Info.GenericTypeArguments | ForEach-Object {
            Get-GraphKitAuthParityAbiNullabilityDisplay -Info $_
        }) -join ','
        $display += ";arguments=[$arguments]"
    }
    return $display
}

function Get-GraphKitAuthParityAbiModifierDisplay {
    param([AllowEmptyCollection()][Type[]] $Modifiers)
    $names = [string[]]@($Modifiers | ForEach-Object FullName)
    [Array]::Sort($names, [StringComparer]::Ordinal)
    return '[' + ($names -join ',') + ']'
}

function Get-GraphKitAuthParityAbiCallableId {
    param([Parameter(Mandatory)][Reflection.MethodBase] $Callable)
    $parameters = @($Callable.GetParameters() | ForEach-Object {
        Get-GraphKitAuthParityAbiTypeDisplayName -Type $_.ParameterType
    }) -join ','
    $name = if ($Callable -is [Reflection.ConstructorInfo]) { '.ctor' } else { $Callable.Name }
    return "$($Callable.DeclaringType.FullName)::$name($parameters)"
}

function Get-GraphKitAuthParityAbiDefaultDisplay {
    param([Parameter(Mandatory)][Reflection.ParameterInfo] $Parameter)
    if (-not $Parameter.HasDefaultValue) { return '<none>' }
    if ($null -eq $Parameter.DefaultValue) { return '<null>' }
    if ($Parameter.DefaultValue -is [string]) {
        return '"' + ([string]$Parameter.DefaultValue).Replace('"', '\"') + '"'
    }
    if ($Parameter.DefaultValue -is [char]) {
        return "'$($Parameter.DefaultValue)'"
    }
    if ($Parameter.DefaultValue -is [bool]) {
        return ([string]$Parameter.DefaultValue).ToLowerInvariant()
    }
    return [Convert]::ToString(
        $Parameter.DefaultValue,
        [Globalization.CultureInfo]::InvariantCulture)
}

function Add-GraphKitAuthParityAbiParameterMetadata {
    param(
        [Parameter(Mandatory)][Collections.Generic.List[string]] $Lines,
        [Parameter(Mandatory)][Reflection.NullabilityInfoContext] $NullabilityContext,
        [Parameter(Mandatory)][string] $OwnerKind,
        [Parameter(Mandatory)][string] $OwnerId,
        [Parameter(Mandatory)][Reflection.ParameterInfo] $Parameter
    )

    $direction = if ($Parameter.IsOut) {
        'out'
    }
    elseif ($Parameter.ParameterType.IsByRef -and $Parameter.IsIn) {
        'in'
    }
    elseif ($Parameter.ParameterType.IsByRef) {
        'ref'
    }
    else {
        'value'
    }
    $isParams = $Parameter.IsDefined([ParamArrayAttribute], $false).ToString().ToLowerInvariant()
    $isOptional = $Parameter.IsOptional.ToString().ToLowerInvariant()
    $hasDefault = $Parameter.HasDefaultValue.ToString().ToLowerInvariant()
    $requiredModifiers = Get-GraphKitAuthParityAbiModifierDisplay `
        -Modifiers $Parameter.GetRequiredCustomModifiers()
    $optionalModifiers = Get-GraphKitAuthParityAbiModifierDisplay `
        -Modifiers $Parameter.GetOptionalCustomModifiers()
    $nullability = Get-GraphKitAuthParityAbiNullabilityDisplay `
        -Info $NullabilityContext.Create($Parameter)
    $Lines.Add(
        "PARAMETER-META|$OwnerKind|$OwnerId|$($Parameter.Position)|$($Parameter.Name)|" +
        "$(Get-GraphKitAuthParityAbiTypeDisplayName -Type $Parameter.ParameterType)|direction=$direction|params=$isParams|" +
        "optional=$isOptional|hasDefault=$hasDefault|default=$(Get-GraphKitAuthParityAbiDefaultDisplay -Parameter $Parameter)|" +
        "requiredMods=$requiredModifiers|optionalMods=$optionalModifiers|nullable=$nullability")
}

function Add-GraphKitAuthParityAbiGenericParameterMetadata {
    param(
        [Parameter(Mandatory)][Collections.Generic.List[string]] $Lines,
        [Parameter(Mandatory)][string] $OwnerKind,
        [Parameter(Mandatory)][string] $OwnerId,
        [AllowEmptyCollection()][Type[]] $GenericParameters
    )

    foreach ($parameter in @($GenericParameters | Where-Object IsGenericParameter |
            Sort-Object GenericParameterPosition)) {
        $constraints = [string[]]@($parameter.GetGenericParameterConstraints() |
            ForEach-Object { Get-GraphKitAuthParityAbiTypeDisplayName -Type $_ })
        [Array]::Sort($constraints, [StringComparer]::Ordinal)
        $Lines.Add(
            "GENERIC-PARAMETER|$OwnerKind|$OwnerId|$($parameter.GenericParameterPosition)|" +
            "$($parameter.Name)|attributes=$($parameter.GenericParameterAttributes)|constraints=[$($constraints -join ',')]")
    }
}

function Get-GraphKitAuthParityPublicAbiRecords {
    param([Parameter(Mandatory)][Reflection.Assembly] $Assembly)

    $lines = [Collections.Generic.List[string]]::new()
    $flags = [Reflection.BindingFlags]'Public,Instance,Static,DeclaredOnly'
    $nullabilityContext = [Reflection.NullabilityInfoContext]::new()
    $exportedTypes = if ($Assembly.IsDynamic) {
        @($Assembly.GetTypes() | Where-Object IsVisible)
    }
    else {
        @($Assembly.GetExportedTypes())
    }
    foreach ($type in @($exportedTypes | Sort-Object FullName)) {
        $kind = if ($type.IsEnum) {
            'enum'
        }
        elseif ($type.IsInterface) {
            'interface'
        }
        elseif ($type.IsAbstract) {
            'abstract-class'
        }
        elseif ($type.IsSealed) {
            'sealed-class'
        }
        else {
            'class'
        }
        $baseType = if ($null -eq $type.BaseType) {
            ''
        }
        else {
            Get-GraphKitAuthParityAbiTypeDisplayName -Type $type.BaseType
        }
        $interfaces = [string[]]@($type.GetInterfaces() | ForEach-Object {
            Get-GraphKitAuthParityAbiTypeDisplayName -Type $_
        })
        [Array]::Sort($interfaces, [StringComparer]::Ordinal)
        $lines.Add("TYPE|$($type.FullName)|$kind|$baseType|$($interfaces -join ',')")
        $isStaticType = ($type.IsAbstract -and $type.IsSealed -and
            -not $type.IsEnum).ToString().ToLowerInvariant()
        $enumUnderlying = if ($type.IsEnum) {
            Get-GraphKitAuthParityAbiTypeDisplayName -Type ([Enum]::GetUnderlyingType($type))
        }
        else {
            '<none>'
        }
        $genericParameters = @($type.GetGenericArguments() | Where-Object IsGenericParameter)
        $lines.Add(
            "TYPE-META|$($type.FullName)|staticType=$isStaticType|" +
            "enumUnderlying=$enumUnderlying|genericArity=$($genericParameters.Count)")
        Add-GraphKitAuthParityAbiGenericParameterMetadata -Lines $lines -OwnerKind TYPE `
            -OwnerId $type.FullName -GenericParameters $genericParameters

        if ($type.IsEnum) {
            foreach ($name in [Enum]::GetNames($type)) {
                $value = [Convert]::ToInt64([Enum]::Parse($type, $name))
                $lines.Add("ENUM|$($type.FullName)|$name=$value")
            }
        }

        foreach ($constructor in @($type.GetConstructors($flags) |
                Sort-Object { $_.ToString() })) {
            $parameters = @($constructor.GetParameters() | ForEach-Object {
                Get-GraphKitAuthParityAbiParameterDisplay -Parameter $_
            }) -join ','
            $lines.Add("CTOR|$($type.FullName)|($parameters)")
            $ownerId = Get-GraphKitAuthParityAbiCallableId -Callable $constructor
            $lines.Add("MEMBER-META|CTOR|$ownerId|static=false|genericArity=0")
            foreach ($parameter in $constructor.GetParameters()) {
                Add-GraphKitAuthParityAbiParameterMetadata -Lines $lines `
                    -NullabilityContext $nullabilityContext -OwnerKind CTOR `
                    -OwnerId $ownerId -Parameter $parameter
            }
        }

        foreach ($property in @($type.GetProperties($flags) | Sort-Object Name)) {
            $accessors = [Collections.Generic.List[string]]::new()
            if ($null -ne $property.GetMethod -and $property.GetMethod.IsPublic) {
                $accessors.Add('get')
            }
            if ($null -ne $property.SetMethod -and $property.SetMethod.IsPublic) {
                $isInit = @($property.SetMethod.ReturnParameter.GetRequiredCustomModifiers() |
                    Where-Object FullName -eq 'System.Runtime.CompilerServices.IsExternalInit').Count -ne 0
                $accessors.Add($(if ($isInit) { 'init' } else { 'set' }))
            }
            $isRequired = @($property.GetCustomAttributesData() |
                Where-Object AttributeType -EQ (
                    [Runtime.CompilerServices.RequiredMemberAttribute])).Count -ne 0
            if ($isRequired) { $accessors.Add('required') }
            $lines.Add(
                "PROPERTY|$($type.FullName)|$($property.Name)|" +
                "$(Get-GraphKitAuthParityAbiTypeDisplayName -Type $property.PropertyType)|" +
                "$($accessors -join ',')")
            $propertyAccessor = if ($null -ne $property.GetGetMethod($true)) {
                $property.GetGetMethod($true)
            }
            else {
                $property.GetSetMethod($true)
            }
            $propertyIsStatic = $propertyAccessor.IsStatic.ToString().ToLowerInvariant()
            $propertyNullability = Get-GraphKitAuthParityAbiNullabilityDisplay `
                -Info $nullabilityContext.Create($property)
            $indexParameters = @($property.GetIndexParameters())
            $setter = $property.GetSetMethod($true)
            $setterRequiredModifiers = if ($null -eq $setter) {
                '<none>'
            }
            else {
                Get-GraphKitAuthParityAbiModifierDisplay `
                    -Modifiers $setter.ReturnParameter.GetRequiredCustomModifiers()
            }
            $setterOptionalModifiers = if ($null -eq $setter) {
                '<none>'
            }
            else {
                Get-GraphKitAuthParityAbiModifierDisplay `
                    -Modifiers $setter.ReturnParameter.GetOptionalCustomModifiers()
            }
            $propertyOwnerId = "$($type.FullName)::$($property.Name)"
            $lines.Add(
                "PROPERTY-META|$propertyOwnerId|static=$propertyIsStatic|" +
                "nullable=$propertyNullability|indexCount=$($indexParameters.Count)|" +
                "setterRequiredMods=$setterRequiredModifiers|" +
                "setterOptionalMods=$setterOptionalModifiers")
            foreach ($parameter in $indexParameters) {
                Add-GraphKitAuthParityAbiParameterMetadata -Lines $lines `
                    -NullabilityContext $nullabilityContext -OwnerKind INDEX `
                    -OwnerId $propertyOwnerId -Parameter $parameter
            }
        }

        foreach ($method in @($type.GetMethods($flags) |
                Where-Object { -not $_.IsSpecialName -or $_.Name.StartsWith('op_') } |
                Sort-Object Name, { $_.ToString() })) {
            $parameters = @($method.GetParameters() | ForEach-Object {
                Get-GraphKitAuthParityAbiParameterDisplay -Parameter $_
            }) -join ','
            $lines.Add(
                "METHOD|$($type.FullName)|$($method.Name)|($parameters)->" +
                "$(Get-GraphKitAuthParityAbiTypeDisplayName -Type $method.ReturnType)")
            $ownerId = Get-GraphKitAuthParityAbiCallableId -Callable $method
            $methodGenericParameters = @($method.GetGenericArguments() |
                Where-Object IsGenericParameter)
            $lines.Add(
                "MEMBER-META|METHOD|$ownerId|static=$($method.IsStatic.ToString().ToLowerInvariant())|" +
                "genericArity=$($methodGenericParameters.Count)")
            Add-GraphKitAuthParityAbiGenericParameterMetadata -Lines $lines `
                -OwnerKind METHOD -OwnerId $ownerId `
                -GenericParameters $methodGenericParameters
            foreach ($parameter in $method.GetParameters()) {
                Add-GraphKitAuthParityAbiParameterMetadata -Lines $lines `
                    -NullabilityContext $nullabilityContext -OwnerKind METHOD `
                    -OwnerId $ownerId -Parameter $parameter
            }
            $returnParameter = $method.ReturnParameter
            $lines.Add(
                "RETURN-META|METHOD|$ownerId|" +
                "$(Get-GraphKitAuthParityAbiTypeDisplayName -Type $method.ReturnType)|" +
                "requiredMods=$(Get-GraphKitAuthParityAbiModifierDisplay -Modifiers $returnParameter.GetRequiredCustomModifiers())|" +
                "optionalMods=$(Get-GraphKitAuthParityAbiModifierDisplay -Modifiers $returnParameter.GetOptionalCustomModifiers())|" +
                "nullable=$(Get-GraphKitAuthParityAbiNullabilityDisplay -Info $nullabilityContext.Create($returnParameter))")
        }

        foreach ($eventInfo in @($type.GetEvents($flags) | Sort-Object Name)) {
            $accessors = [Collections.Generic.List[string]]::new()
            if ($null -ne $eventInfo.AddMethod -and $eventInfo.AddMethod.IsPublic) {
                $accessors.Add('add')
            }
            if ($null -ne $eventInfo.RemoveMethod -and $eventInfo.RemoveMethod.IsPublic) {
                $accessors.Add('remove')
            }
            $lines.Add(
                "EVENT|$($type.FullName)|$($eventInfo.Name)|" +
                "$(Get-GraphKitAuthParityAbiTypeDisplayName -Type $eventInfo.EventHandlerType)|" +
                "$($accessors -join ',')")
            $eventAccessor = if ($null -ne $eventInfo.AddMethod) {
                $eventInfo.AddMethod
            }
            else {
                $eventInfo.RemoveMethod
            }
            $lines.Add(
                "EVENT-META|$($type.FullName)::$($eventInfo.Name)|" +
                "static=$($eventAccessor.IsStatic.ToString().ToLowerInvariant())|" +
                "nullable=$(Get-GraphKitAuthParityAbiNullabilityDisplay -Info $nullabilityContext.Create($eventInfo))")
        }

        foreach ($field in @($type.GetFields($flags) |
                Where-Object { -not $type.IsEnum } | Sort-Object Name)) {
            $literal = if ($field.IsLiteral) {
                [string]$field.GetRawConstantValue()
            }
            else {
                ''
            }
            $lines.Add(
                "FIELD|$($type.FullName)|$($field.Name)|" +
                "$(Get-GraphKitAuthParityAbiTypeDisplayName -Type $field.FieldType)|$literal")
            $lines.Add(
                "FIELD-META|$($type.FullName)::$($field.Name)|" +
                "static=$($field.IsStatic.ToString().ToLowerInvariant())|" +
                "nullable=$(Get-GraphKitAuthParityAbiNullabilityDisplay -Info $nullabilityContext.Create($field))")
        }
    }

    $records = [string[]]$lines.ToArray()
    [Array]::Sort($records, [StringComparer]::Ordinal)
    return $records
}

function Get-GraphKitAuthParityPublicAbiSha256 {
    param([Parameter(Mandatory)][Reflection.Assembly] $Assembly)

    $records = [string[]]@(Get-GraphKitAuthParityPublicAbiRecords -Assembly $Assembly)
    $canonical = $records -join "`n"
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes($canonical)
    $hash = [Security.Cryptography.SHA256]::HashData($bytes)
    return ([Convert]::ToHexString($hash)).ToLowerInvariant()
}

function Test-GraphKitAuthParityContractsIdentity {
    param([Parameter(Mandatory)][Reflection.AssemblyName] $Name)

    if ($Name.Name -cne 'GraphKit.Auth.Contracts' -or
        -not $Name.Version.Equals([version]'1.0.0.0') -or
        -not [string]::IsNullOrEmpty($Name.CultureName)) {
        return $false
    }
    [byte[]]$publicKeyToken = $Name.GetPublicKeyToken()
    return $null -eq $publicKeyToken -or $publicKeyToken.Count -eq 0
}

function Get-GraphKitAuthParityUtcText {
    return [DateTime]::UtcNow.ToString(
        "yyyy-MM-dd'T'HH:mm:ss.fffffff'Z'",
        [Globalization.CultureInfo]::InvariantCulture)
}

function Test-GraphKitAuthParityExactProperties {
    param(
        [Parameter(Mandatory)] $Value,
        [Parameter(Mandatory)][string[]] $Names
    )
    if ($null -eq $Value) { return $false }
    return (($Value.PSObject.Properties.Name -join '|') -ceq ($Names -join '|'))
}

function Test-GraphKitAuthParityUtcText {
    param([Parameter(Mandatory)][string] $Value)
    $parsed = [DateTime]::MinValue
    return [DateTime]::TryParseExact(
        $Value,
        "yyyy-MM-dd'T'HH:mm:ss.fffffff'Z'",
        [Globalization.CultureInfo]::InvariantCulture,
        [Globalization.DateTimeStyles]::AssumeUniversal -bor
            [Globalization.DateTimeStyles]::AdjustToUniversal,
        [ref] $parsed)
}

function Test-GraphKitAuthParityForbiddenString {
    param([AllowNull()][string] $Value)
    if ($null -eq $Value) { return $false }
    return $Value -match '(?i)(?:\bBearer\s+|\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]+\.|' +
        '\btokenFingerprint\b|\bcorrelationId\b|\bresponseBody\b|\bSystem\.[A-Za-z]+Exception\b|' +
        '(?:^|\s)/Users/|(?:^|\s)/home/|[A-Za-z]:\\|task8-secret-sentinel|' +
        '\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b)'
}

function New-GraphKitAuthParityRoute {
    param([Parameter(Mandatory)][string] $Mode)
    if ($Mode -cnotin $script:GraphKitAuthParityModes) {
        throw [InvalidOperationException]::new('The protected parity route is not allowlisted.')
    }
    return [pscustomobject][ordered]@{
        AuthMode = $Mode
        CanRefresh = $Mode -cne 'BearerToken'
        UsesVault = $Mode -cin @('Certificate','ClientSecret','BearerToken')
        OperationType = 'ManagedDevice'
        Operation = 'List'
        OperationId = 'ManagedDevice.List'
        UsesImds = $Mode -ceq 'ManagedIdentity'
    }
}

function Assert-GraphKitAuthParitySourceBound {
    param([Parameter(Mandatory)] $Evidence)
    if ($null -eq $Evidence.PSObject.Properties['Length'] -or
        [long]$Evidence.Length -lt 0 -or
        [long]$Evidence.Length -gt $script:GraphKitAuthParityMaxPackageBytes) {
        throw [InvalidOperationException]::new('The package source exceeds the protected bound.')
    }
    return $true
}

function Assert-GraphKitAuthParityProviderWeakReference {
    param(
        [Parameter(Mandatory)][WeakReference] $WeakReference,
        [Parameter(Mandatory)] $ProviderContext
    )
    if (-not $WeakReference.IsAlive -or
        -not [object]::ReferenceEquals($WeakReference.Target, $ProviderContext)) {
        throw [InvalidOperationException]::new(
            'The provider unload observer does not identify the inspected load context.')
    }
    return $true
}

function New-GraphKitAuthParityModeRecord {
    param(
        [Parameter(Mandatory)][string] $Execution,
        [Parameter(Mandatory)][string] $Mode,
        [Parameter(Mandatory)][string] $StartedUtc,
        [string] $ModuleVersion = '0.0.0-rejected',
        [string] $Digest = $('0' * 64)
    )
    $checks = [ordered]@{}
    foreach ($name in $script:GraphKitAuthParityChecks) { $checks[$name] = $false }
    $adapter = [ordered]@{}
    foreach ($name in $script:GraphKitAuthParityAdapterChecks) { $adapter[$name] = $false }
    return [pscustomobject][ordered]@{
        schemaVersion = [int] 1
        execution = $Execution
        moduleVersion = $ModuleVersion
        packageSha256 = $Digest
        authMode = $(if ($Mode -cin $script:GraphKitAuthParityModes) { $Mode } else { 'Certificate' })
        state = 'Failed'
        failureStage = 'Artifact'
        failureCode = 'ArtifactRejected'
        checks = [pscustomobject] $checks
        adapter = [pscustomobject] $adapter
        read = [pscustomobject][ordered]@{
            operation = 'ManagedDevice.List'
            attempted = $false
            succeeded = $false
            rowCount = [long] 0
        }
        startedUtc = $StartedUtc
        completedUtc = $StartedUtc
    }
}

function Set-GraphKitAuthParityFailure {
    param(
        [Parameter(Mandatory)] $Record,
        [Parameter(Mandatory)][string] $Stage,
        [Parameter(Mandatory)][string] $Code
    )
    if ($Stage -cnotin $script:GraphKitAuthParityFailureStages -or
        $Code -cnotin $script:GraphKitAuthParityFailureCodes -or
        $Stage -ceq 'None' -or $Code -ceq 'None') {
        throw [InvalidOperationException]::new('The protected parity failure mapping is invalid.')
    }
    $Record.state = 'Failed'
    $Record.failureStage = $Stage
    $Record.failureCode = $Code
}

function Set-GraphKitAuthParityPassed {
    param([Parameter(Mandatory)] $Record)
    $Record.state = 'Passed'
    $Record.failureStage = 'None'
    $Record.failureCode = 'None'
}

function Test-GraphKitAuthParityEvidence {
    param([Parameter(Mandatory)] $Record)
    $top = @(
        'schemaVersion','execution','moduleVersion','packageSha256','authMode','state','failureStage',
        'failureCode','checks','adapter','read','startedUtc','completedUtc')
    if (-not (Test-GraphKitAuthParityExactProperties $Record $top)) {
        throw [InvalidOperationException]::new('The mode-run evidence schema is not exact.')
    }
    if ($Record.schemaVersion.GetType() -ne [int] -or [int]$Record.schemaVersion -ne 1 -or
        $Record.execution.GetType() -ne [string] -or $Record.execution -cnotin @('DryRun','Live') -or
        $Record.moduleVersion.GetType() -ne [string] -or
        $Record.moduleVersion -cnotmatch '^\d+\.\d+\.\d+-[0-9A-Za-z][0-9A-Za-z.-]*$' -or
        $Record.packageSha256.GetType() -ne [string] -or
        $Record.packageSha256 -cnotmatch '^[0-9a-f]{64}$' -or
        $Record.authMode.GetType() -ne [string] -or
        $Record.authMode -cnotin $script:GraphKitAuthParityModes -or
        $Record.state.GetType() -ne [string] -or $Record.state -cnotin @('Passed','Failed') -or
        $Record.failureStage.GetType() -ne [string] -or
        $Record.failureStage -cnotin $script:GraphKitAuthParityFailureStages -or
        $Record.failureCode.GetType() -ne [string] -or
        $Record.failureCode -cnotin $script:GraphKitAuthParityFailureCodes) {
        throw [InvalidOperationException]::new('The mode-run evidence has an invalid scalar.')
    }
    if (($Record.state -ceq 'Passed') -ne
        ($Record.failureStage -ceq 'None' -and $Record.failureCode -ceq 'None')) {
        throw [InvalidOperationException]::new('The mode-run state and failure tuple disagree.')
    }
    $failureMap = @{
        Artifact='ArtifactRejected'; Import='ImportRejected'; Context='ContextRejected'
        Acquisition='AcquisitionFailed'; Read='ReadFailed'; Diagnostics='DiagnosticsRejected'
        Cleanup='CleanupFailed'; Evidence='EvidenceRejected'
    }
    if ($Record.state -ceq 'Failed' -and
        (-not $failureMap.ContainsKey($Record.failureStage) -or
            $failureMap[$Record.failureStage] -cne $Record.failureCode)) {
        throw [InvalidOperationException]::new('The mode-run failure tuple is not allowlisted.')
    }
    if (-not (Test-GraphKitAuthParityExactProperties $Record.checks $script:GraphKitAuthParityChecks)) {
        throw [InvalidOperationException]::new('The mode-run checks object is not exact.')
    }
    foreach ($property in $Record.checks.PSObject.Properties) {
        if ($property.Value.GetType() -ne [bool]) {
            throw [InvalidOperationException]::new('A mode-run check is not Boolean.')
        }
    }
    if (-not (Test-GraphKitAuthParityExactProperties $Record.adapter $script:GraphKitAuthParityAdapterChecks)) {
        throw [InvalidOperationException]::new('The adapter evidence object is not exact.')
    }
    foreach ($property in $Record.adapter.PSObject.Properties) {
        if ($property.Value.GetType() -ne [bool]) {
            throw [InvalidOperationException]::new('An adapter check is not Boolean.')
        }
    }
    if (-not (Test-GraphKitAuthParityExactProperties $Record.read @(
        'operation','attempted','succeeded','rowCount')) -or
        $Record.read.operation.GetType() -ne [string] -or
        $Record.read.operation -cne 'ManagedDevice.List' -or
        $Record.read.attempted.GetType() -ne [bool] -or
        $Record.read.succeeded.GetType() -ne [bool] -or
        $Record.read.rowCount.GetType() -ne [long] -or
        [long]$Record.read.rowCount -lt 0) {
        throw [InvalidOperationException]::new('The read evidence is invalid.')
    }
    if ($Record.startedUtc.GetType() -ne [string] -or
        $Record.completedUtc.GetType() -ne [string] -or
        -not (Test-GraphKitAuthParityUtcText $Record.startedUtc) -or
        -not (Test-GraphKitAuthParityUtcText $Record.completedUtc)) {
        throw [InvalidOperationException]::new('The mode-run timestamp is not canonical UTC.')
    }
    foreach ($value in @(
        $Record.execution,$Record.moduleVersion,$Record.packageSha256,$Record.authMode,$Record.state,
        $Record.failureStage,$Record.failureCode,$Record.read.operation,$Record.startedUtc,$Record.completedUtc)) {
        if (Test-GraphKitAuthParityForbiddenString $value) {
            throw [InvalidOperationException]::new('The mode-run evidence contains a forbidden string.')
        }
    }
    if ($Record.state -ceq 'Passed') {
        foreach ($name in @(
            'packageDigestMatched','snapshotBound','archiveValidated','extractionSealed',
            'exactImport','routeMatched','cleanupVerified')) {
            if (-not [bool]$Record.checks.$name) {
                throw [InvalidOperationException]::new('Passed evidence is missing a required check.')
            }
        }
        if ($Record.execution -ceq 'DryRun') {
            if ($Record.checks.contextMatched -or $Record.checks.sourceMatched -or
                $Record.checks.tenantProofVerified -or $Record.read.attempted -or
                $Record.read.succeeded -or [long]$Record.read.rowCount -ne 0) {
                throw [InvalidOperationException]::new('DryRun evidence contains live behavior.')
            }
        }
        else {
            foreach ($name in $script:GraphKitAuthParityChecks) {
                if (-not [bool]$Record.checks.$name) {
                    throw [InvalidOperationException]::new('Passed live evidence is missing a required check.')
                }
            }
            if (-not $Record.read.attempted -or -not $Record.read.succeeded) {
                throw [InvalidOperationException]::new('Passed live evidence did not complete its read.')
            }
        }
        foreach ($name in $script:GraphKitAuthParityAdapterChecks) {
            if (-not [bool]$Record.adapter.$name) {
                throw [InvalidOperationException]::new('Passed evidence is missing an adapter check.')
            }
        }
    }
    return $true
}

function Test-GraphKitAuthParityFrozenArtifact {
    param([Parameter(Mandatory)] $Record)
    if (-not (Test-GraphKitAuthParityExactProperties $Record @(
        'schemaVersion','moduleVersion','sourceRevision','packageSha256','proofSha256'))) {
        throw [InvalidOperationException]::new('The frozen-artifact schema is not exact.')
    }
    if ($Record.schemaVersion.GetType() -ne [int] -or [int]$Record.schemaVersion -ne 1 -or
        $Record.moduleVersion.GetType() -ne [string] -or
        $Record.moduleVersion -cnotmatch '^\d+\.\d+\.\d+-[0-9A-Za-z][0-9A-Za-z.-]*$' -or
        $Record.sourceRevision.GetType() -ne [string] -or
        $Record.sourceRevision -cnotmatch '^[0-9a-f]{40}$' -or
        $Record.packageSha256.GetType() -ne [string] -or
        $Record.packageSha256 -cnotmatch '^[0-9a-f]{64}$' -or
        $Record.proofSha256.GetType() -ne [string] -or
        $Record.proofSha256 -cnotmatch '^[0-9a-f]{64}$') {
        throw [InvalidOperationException]::new('The frozen-artifact evidence has an invalid scalar.')
    }
    foreach ($value in @(
        $Record.moduleVersion,$Record.sourceRevision,$Record.packageSha256,$Record.proofSha256)) {
        if (Test-GraphKitAuthParityForbiddenString $value) {
            throw [InvalidOperationException]::new('The frozen artifact contains a forbidden string.')
        }
    }
    return $true
}

function Test-GraphKitAuthParityRetention {
    param(
        [Parameter(Mandatory)] $Artifact,
        [Parameter(Mandatory)][object[]] $ModeRecords
    )
    $null = Test-GraphKitAuthParityFrozenArtifact $Artifact
    if ($ModeRecords.Count -ne 4) {
        throw [InvalidOperationException]::new('Retention requires exactly four mode records.')
    }
    $modes = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($record in $ModeRecords) {
        $null = Test-GraphKitAuthParityEvidence $record
        if ($record.execution -cne 'Live' -or
            $record.state -cne 'Passed' -or
            $record.failureStage -cne 'None' -or
            $record.failureCode -cne 'None' -or
            $record.moduleVersion -cne $Artifact.moduleVersion -or
            $record.packageSha256 -cne $Artifact.packageSha256 -or
            -not $modes.Add([string]$record.authMode)) {
            throw [InvalidOperationException]::new('A retained mode is not bound uniquely to the artifact.')
        }
    }
    if (($modes | Sort-Object) -join '|' -cne
        (($script:GraphKitAuthParityModes | Sort-Object) -join '|')) {
        throw [InvalidOperationException]::new('Retention does not contain the four literal modes.')
    }
    return $true
}

function Initialize-GraphKitAuthParityNative {
    if ($null -ne $script:GraphKitAuthParityNativeType) { return }
    $helperGzipBase64 = @'
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
/w8A/PyyYBQBAA==
'@
    $compressed = [Convert]::FromBase64String(($helperGzipBase64 -replace '\s',''))
    $compressedStream = [IO.MemoryStream]::new($compressed, $false)
    try {
        $gzip = [IO.Compression.GZipStream]::new(
            $compressedStream, [IO.Compression.CompressionMode]::Decompress, $false)
        try {
            $reader = [IO.StreamReader]::new(
                $gzip, [Text.UTF8Encoding]::new($false, $true), $true, 4096, $false)
            try { $template = $reader.ReadToEnd() }
            finally { $reader.Dispose() }
        }
        finally { $gzip.Dispose() }
    }
    finally { $compressedStream.Dispose() }
    $marker = '__GRAPHKIT_AUTH_STAGE_CAPTURE_NAMESPACE__'
    if (($template.Split([string[]]@($marker), [StringSplitOptions]::None).Length - 1) -ne 1) {
        throw [InvalidOperationException]::new('The embedded native helper marker is invalid.')
    }
    $helperBytes = [Text.UTF8Encoding]::new($false, $true).GetBytes($template)
    $hash = [Convert]::ToHexString(
        [Security.Cryptography.SHA256]::HashData($helperBytes)).ToLowerInvariant()
    if ($hash -cne $script:GraphKitAuthParityExpectedNativeSourceSha256) {
        throw [InvalidOperationException]::new('The embedded native helper digest is invalid.')
    }
    $nonce = [Convert]::ToHexString(
        [Security.Cryptography.RandomNumberGenerator]::GetBytes(16)).ToLowerInvariant()
    $namespace = "GraphKit.R8.Parity.H$hash.N$nonce"
    $expected = "$namespace.GraphKitAuthStageCapture"
    $types = @(Add-Type -TypeDefinition $template.Replace($marker, $namespace) `
        -PassThru -ErrorAction Stop)
    $match = @($types | Where-Object FullName -CEQ $expected)
    if ($match.Count -ne 1) {
        throw [InvalidOperationException]::new('The embedded native helper did not load exactly once.')
    }
    $script:GraphKitAuthParityNativeType = $match[0]
}

function Get-GraphKitAuthParityTestHooks {
    $hooks = [AppDomain]::CurrentDomain.GetData('GraphKit.Task8.ParityTestHooks/1')
    if ($null -eq $hooks -or
        $null -eq $hooks.PSObject.Properties['ContractMarker'] -or
        [string]$hooks.ContractMarker -cne 'GraphKit.Task8.ParityTestHooks/1') {
        return $null
    }
    return $hooks
}

function Invoke-GraphKitAuthParityHook {
    param(
        [AllowNull()] $Hooks,
        [Parameter(Mandatory)][string] $Name,
        [object[]] $Arguments = @(),
        [switch] $PassThru,
        [switch] $PreserveExceptionType
    )
    if ($null -eq $Hooks) { return }
    $property = $Hooks.PSObject.Properties[$Name]
    if ($null -eq $property -or $property.Value -isnot [scriptblock]) { return }
    try {
        $records = @(& $property.Value @Arguments 2>&1 3>&1 4>&1 5>&1 6>&1)
    }
    catch {
        if ($PreserveExceptionType) { throw }
        throw [InvalidOperationException]::new('A protected parity internal seam failed.')
    }
    $streamRecords = @($records | Where-Object {
        $_ -is [Management.Automation.ErrorRecord] -or
        $_ -is [Management.Automation.WarningRecord] -or
        $_ -is [Management.Automation.VerboseRecord] -or
        $_ -is [Management.Automation.DebugRecord] -or
        $_ -is [Management.Automation.InformationRecord]
    })
    $allowStreamRecords = $null -ne $Hooks.PSObject.Properties['AllowStreamRecords'] -and
        [bool]$Hooks.AllowStreamRecords
    if ($streamRecords.Count -gt 0 -and -not $allowStreamRecords) {
        throw [InvalidOperationException]::new('A protected parity internal seam wrote to a diagnostic stream.')
    }
    if (-not $PassThru) { return }
    $success = @($records | Where-Object {
        $_ -isnot [Management.Automation.ErrorRecord] -and
        $_ -isnot [Management.Automation.WarningRecord] -and
        $_ -isnot [Management.Automation.VerboseRecord] -and
        $_ -isnot [Management.Automation.DebugRecord] -and
        $_ -isnot [Management.Automation.InformationRecord]
    })
    if ($success.Count -ne 1 -or $null -eq $success[0]) {
        throw [InvalidOperationException]::new('A protected parity internal seam returned an invalid result count.')
    }
    return $success[0]
}

function Test-GraphKitAuthParityContainedPhysicalPath {
    param([Parameter(Mandatory)][string] $Root, [Parameter(Mandatory)][string] $Candidate)
    $comparison = if ($IsWindows) { [StringComparison]::OrdinalIgnoreCase } else { [StringComparison]::Ordinal }
    $rootPath = [IO.Path]::GetFullPath($Root).TrimEnd(
        [IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar)
    $candidatePath = [IO.Path]::GetFullPath($Candidate)
    return $candidatePath.StartsWith(
        $rootPath + [IO.Path]::DirectorySeparatorChar, $comparison)
}

function Test-GraphKitAuthParitySealedPermission {
    param([Parameter(Mandatory)] $Evidence, [Parameter(Mandatory)][bool] $Directory)
    if ([bool]$Evidence.OwnerWritable) { return $false }
    if ($IsWindows) {
        $currentSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
        return -not [string]::IsNullOrWhiteSpace([string]$Evidence.CurrentOwnerSid) -and
            [string]$Evidence.OwnerSid -ceq [string]$Evidence.CurrentOwnerSid -and
            [string]$Evidence.CurrentIdentitySid -ceq $currentSid -and
            [bool]$Evidence.AccessRulesProtected -and
            -not [bool]$Evidence.HasInheritedAccessRules -and
            [bool]$Evidence.ExactOwnerOnlyAccess -and
            ($Directory -or [bool]$Evidence.FileReadOnly)
    }
    return [int]$Evidence.UnixMode -eq $(if ($Directory) { 0x140 } else { 0x100 }) -and
        [uint32]$Evidence.OwnerUid -eq [uint32]$Evidence.EffectiveUid
}

function Assert-GraphKitAuthParityPortableNameSet {
    param([Parameter(Mandatory)][string[]] $Names, [Parameter(Mandatory)][string] $Kind)
    $portable = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $normalized = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($name in $Names) {
        if ([string]::IsNullOrWhiteSpace($name) -or
            $name.IndexOf('\') -ge 0 -or
            -not $name.IsNormalized([Text.NormalizationForm]::FormC) -or
            -not $portable.Add($name) -or
            -not $normalized.Add($name.Normalize([Text.NormalizationForm]::FormC))) {
            throw [InvalidOperationException]::new("The protected parity $Kind name set is ambiguous.")
        }
    }
}

function Get-GraphKitAuthParityFullVersion {
    param([Parameter(Mandatory)][string] $ManifestPath)
    $manifest = Import-PowerShellDataFile -Path $ManifestPath -ErrorAction Stop
    $base = [string]$manifest.ModuleVersion
    $prerelease = [string]$manifest.PrivateData.PSData.Prerelease
    if ($base -cnotmatch '^\d+\.\d+\.\d+$' -or [string]::IsNullOrWhiteSpace($prerelease) -or
        $prerelease -cnotmatch '^[0-9A-Za-z][0-9A-Za-z.-]*$') {
        throw [InvalidOperationException]::new('The extracted module is not one exact prerelease.')
    }
    return "$base-$prerelease"
}

function Read-GraphKitAuthParityArchiveEntry {
    param([Parameter(Mandatory)][IO.Compression.ZipArchiveEntry] $Entry)
    if ([long]$Entry.Length -lt 0 -or [long]$Entry.Length -gt $script:GraphKitAuthParityMaxEntryBytes) {
        throw [InvalidOperationException]::new('An archive entry exceeds the protected size bound.')
    }
    $stream = $Entry.Open()
    try {
        $memory = [IO.MemoryStream]::new([int][Math]::Min([long]$Entry.Length, 1MB))
        try {
            $buffer = [byte[]]::new(131072)
            [long]$total = 0
            while (($read = $stream.Read($buffer, 0, $buffer.Length)) -gt 0) {
                $total += $read
                if ($total -gt $script:GraphKitAuthParityMaxEntryBytes -or
                    $total -gt [long]$Entry.Length) {
                    throw [InvalidOperationException]::new('An archive entry exceeded its validated byte bound.')
                }
                $memory.Write($buffer, 0, $read)
            }
            if ($total -ne [long]$Entry.Length) {
                throw [InvalidOperationException]::new('An archive entry length changed while streaming.')
            }
            return $memory.ToArray()
        }
        finally { $memory.Dispose() }
    }
    finally { $stream.Dispose() }
}

function Test-GraphKitAuthParityPortableArchiveSegment {
    param([Parameter(Mandatory)][string] $Segment)

    if ([string]::IsNullOrEmpty($Segment) -or
        $Segment -ceq '.' -or $Segment -ceq '..' -or
        $Segment.EndsWith('.', [StringComparison]::Ordinal) -or
        $Segment.EndsWith(' ', [StringComparison]::Ordinal) -or
        $Segment.IndexOfAny([char[]]'<>:"\|?*') -ge 0) {
        return $false
    }
    foreach ($character in $Segment.ToCharArray()) {
        if ([int]$character -lt 32 -or [int]$character -eq 127) {
            return $false
        }
    }
    $dot = $Segment.IndexOf('.')
    $baseName = if ($dot -lt 0) { $Segment } else { $Segment.Substring(0, $dot) }
    if ($baseName -match '(?i)^(?:CON|PRN|AUX|NUL|CLOCK\$|CONIN\$|CONOUT\$|' +
        'COM[1-9¹²³]|LPT[1-9¹²³])$') {
        return $false
    }
    return $true
}

function Get-GraphKitAuthParityArchivePlan {
    param([Parameter(Mandatory)][IO.Compression.ZipArchive] $Archive)
    if ($Archive.Entries.Count -lt 1 -or
        $Archive.Entries.Count -gt $script:GraphKitAuthParityMaxEntries) {
        throw [InvalidOperationException]::new('The archive entry count is outside the protected bound.')
    }
    $portable = [Collections.Generic.Dictionary[string,string]]::new([StringComparer]::OrdinalIgnoreCase)
    $normalized = [Collections.Generic.Dictionary[string,string]]::new([StringComparer]::OrdinalIgnoreCase)
    $files = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $directories = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $records = [Collections.Generic.List[object]]::new()
    [long]$totalLength = 0
    foreach ($entry in $Archive.Entries) {
        $path = [string]$entry.FullName
        $segments = @($path -split '/')
        $portableSegments = @($segments | Where-Object {
            -not (Test-GraphKitAuthParityPortableArchiveSegment -Segment $_)
        })
        if ([string]::IsNullOrWhiteSpace($path) -or
            [string]::IsNullOrEmpty([string]$entry.Name) -or
            $path.EndsWith('/') -or [IO.Path]::IsPathRooted($path) -or
            $path -match '^[A-Za-z]:' -or $path.IndexOf('\') -ge 0 -or
            $segments -contains '' -or $segments -contains '.' -or $segments -contains '..' -or
            $portableSegments.Count -ne 0 -or
            -not $path.IsNormalized([Text.NormalizationForm]::FormC) -or
            -not $portable.TryAdd($path, $path) -or
            -not $normalized.TryAdd($path.Normalize([Text.NormalizationForm]::FormC), $path)) {
            throw [InvalidOperationException]::new('The archive contains an unsafe or ambiguous entry path.')
        }
        $external = ([int64]$entry.ExternalAttributes) -band 0xffffffffL
        $unixMode = ($external -shr 16) -band 0xffff
        $unixType = $unixMode -band 0xf000
        $windowsAttributes = $external -band 0xffff
        if (($windowsAttributes -band 0x0010) -ne 0 -or
            ($windowsAttributes -band 0x0400) -ne 0 -or
            ($unixType -ne 0 -and $unixType -ne 0x8000)) {
            throw [InvalidOperationException]::new('The archive contains a link, reparse point, or non-regular entry.')
        }
        if ([long]$entry.Length -lt 0 -or [long]$entry.Length -gt $script:GraphKitAuthParityMaxEntryBytes) {
            throw [InvalidOperationException]::new('An archive entry exceeds the protected size bound.')
        }
        $totalLength += [long]$entry.Length
        if ($totalLength -gt $script:GraphKitAuthParityMaxTotalBytes) {
            throw [InvalidOperationException]::new('The archive exceeds the protected total-size bound.')
        }
        if ([long]$entry.Length -gt $script:GraphKitAuthParityRatioThresholdBytes -and
            ([long]$entry.CompressedLength -le 0 -or
                [long]$entry.Length -gt
                    [long]$entry.CompressedLength * $script:GraphKitAuthParityMaxCompressionRatio)) {
            throw [InvalidOperationException]::new('The archive entry compression ratio exceeds the protected bound.')
        }
        if (-not $files.Add($path) -or $directories.Contains($path)) {
            throw [InvalidOperationException]::new('The archive file/directory closure is ambiguous.')
        }
        if ($segments.Count -gt 1) {
            for ($index = 1; $index -lt $segments.Count; $index++) {
                $directory = ($segments[0..($index - 1)] -join '/')
                if ($files.Contains($directory)) {
                    throw [InvalidOperationException]::new('The archive file/directory prefix is ambiguous.')
                }
                $null = $directories.Add($directory)
            }
        }
        $records.Add([pscustomobject]@{
            Path = $path
            Length = [long]$entry.Length
            Entry = $entry
        })
    }
    if (-not $files.Contains('GraphKit.psd1') -or -not $files.Contains('GraphKit.psm1')) {
        throw [InvalidOperationException]::new('The archive does not contain the exact module entry points.')
    }
    return [pscustomobject]@{
        Records = $records.ToArray()
        Files = @($files | Sort-Object)
        Directories = @($directories | Sort-Object {
            ($_ -split '/').Count
        }, { $_ })
        TotalLength = $totalLength
    }
}

function Assert-GraphKitAuthParitySameIdentity {
    param(
        [Parameter(Mandatory)] $Expected,
        [Parameter(Mandatory)] $Actual,
        [Parameter(Mandatory)][bool] $Directory,
        [switch] $RequireSealed,
        [switch] $RequireContent
    )
    $comparison = if ($IsWindows) {
        [StringComparison]::OrdinalIgnoreCase
    }
    else {
        [StringComparison]::Ordinal
    }
    if ([string]$Expected.NativeIdentity -cne [string]$Actual.NativeIdentity -or
        -not [string]::Equals(
            [string]$Expected.PhysicalPath, [string]$Actual.PhysicalPath, $comparison) -or
        [bool]$Actual.IsDirectory -ne $Directory -or
        [bool]$Actual.IsReparsePoint -or
        (-not $Directory -and (-not [bool]$Actual.IsRegularFile -or
            [long]$Expected.LinkCount -ne [long]$Actual.LinkCount -or
            [long]$Actual.LinkCount -ne 1))) {
        throw [InvalidOperationException]::new('A protected parity path changed physical identity.')
    }
    if ($RequireContent -and
        ([long]$Expected.Length -ne [long]$Actual.Length -or
            [string]$Expected.Sha256 -cne [string]$Actual.Sha256)) {
        throw [InvalidOperationException]::new('A protected parity file changed content.')
    }
    if ($RequireSealed -and
        -not (Test-GraphKitAuthParitySealedPermission -Evidence $Actual -Directory $Directory)) {
        throw [InvalidOperationException]::new('A protected parity path is not sealed.')
    }
}

function Get-GraphKitAuthParityExpectedChildren {
    param([Parameter(Mandatory)] $State)
    $children = [Collections.Generic.Dictionary[string,Collections.Generic.List[string]]]::new(
        [StringComparer]::Ordinal)
    foreach ($relative in @($State.ExpectedDirectories) + @($State.ExpectedFiles)) {
        $separator = $relative.LastIndexOf('/')
        $parent = if ($separator -lt 0) { '' } else { $relative.Substring(0, $separator) }
        $name = if ($separator -lt 0) { $relative } else { $relative.Substring($separator + 1) }
        if (-not $children.ContainsKey($parent)) {
            $children[$parent] = [Collections.Generic.List[string]]::new()
        }
        $children[$parent].Add($name)
    }
    return $children
}

function Assert-GraphKitAuthParityExactClosure {
    param([Parameter(Mandatory)] $State)
    $expected = Get-GraphKitAuthParityExpectedChildren -State $State
    foreach ($parent in @('') + @($State.ExpectedDirectories)) {
        $parentPath = if ([string]::IsNullOrEmpty($parent)) {
            $State.RootPath
        }
        else {
            Join-Path $State.RootPath ($parent -replace '/', [IO.Path]::DirectorySeparatorChar)
        }
        $actualNames = @([IO.Directory]::EnumerateFileSystemEntries($parentPath) |
            ForEach-Object { [IO.Path]::GetFileName($_) })
        Assert-GraphKitAuthParityPortableNameSet -Names $actualNames -Kind 'directory child'
        $expectedNames = if ($expected.ContainsKey($parent)) { @($expected[$parent]) } else { @() }
        if (($actualNames | Sort-Object -CaseSensitive) -join "`n" -cne
            (($expectedNames | Sort-Object -CaseSensitive) -join "`n")) {
            throw [InvalidOperationException]::new('The protected parity extraction closure changed.')
        }
    }
}

function Assert-GraphKitAuthParityState {
    param(
        [Parameter(Mandatory)] $State,
        [ValidateSet('Import','Cleanup')][string] $Purpose
    )
    $native = $script:GraphKitAuthParityNativeType
    $requireSealed = $Purpose -ceq 'Import' -or
        ($Purpose -ceq 'Cleanup' -and [bool]$State.Sealed)
    $parent = $native::InspectDirectory($State.TempParentParent, $State.TempParentName)
    Assert-GraphKitAuthParitySameIdentity -Expected $State.TempParentEvidence -Actual $parent `
        -Directory $true
    $root = $native::InspectDirectory($State.TempParentPath, $State.RootName)
    Assert-GraphKitAuthParitySameIdentity -Expected $State.RootEvidence -Actual $root `
        -Directory $true -RequireSealed:$requireSealed
    if (-not (Test-GraphKitAuthParityContainedPhysicalPath `
        -Root $State.TempParentEvidence.PhysicalPath -Candidate $root.PhysicalPath)) {
        throw [InvalidOperationException]::new('The protected parity root escaped its parent.')
    }
    foreach ($relative in $State.ExpectedDirectories) {
        $actual = $native::InspectDirectory($State.RootPath, $relative)
        Assert-GraphKitAuthParitySameIdentity -Expected $State.DirectoryEvidence[$relative] `
            -Actual $actual -Directory $true -RequireSealed:$requireSealed
        if (-not (Test-GraphKitAuthParityContainedPhysicalPath `
            -Root $root.PhysicalPath -Candidate $actual.PhysicalPath)) {
            throw [InvalidOperationException]::new('A protected parity directory escaped its root.')
        }
    }
    foreach ($relative in $State.ExpectedFiles) {
        $actual = $native::InspectFile($State.RootPath, $relative)
        Assert-GraphKitAuthParitySameIdentity -Expected $State.FileEvidence[$relative] `
            -Actual $actual -Directory $false -RequireSealed:$requireSealed -RequireContent
        if (-not (Test-GraphKitAuthParityContainedPhysicalPath `
            -Root $root.PhysicalPath -Candidate $actual.PhysicalPath)) {
            throw [InvalidOperationException]::new('A protected parity file escaped its root.')
        }
    }
    Assert-GraphKitAuthParityExactClosure -State $State
}

function Protect-GraphKitAuthParityFile {
    param(
        [Parameter(Mandatory)] $State,
        [Parameter(Mandatory)][string] $Relative,
        [AllowNull()] $Hooks
    )
    if ($State.FilePermissionEvidence.ContainsKey($Relative)) { return }
    Invoke-GraphKitAuthParityHook -Hooks $Hooks -Name BeforeSealFile `
        -Arguments @($State, $Relative)
    $native = $script:GraphKitAuthParityNativeType
    $path = Join-Path $State.RootPath (
        $Relative -replace '/', [IO.Path]::DirectorySeparatorChar)
    $native::SetOwnerOnly($path, $false, $false)
    $sealed = $native::InspectFile($State.RootPath, $Relative)
    Assert-GraphKitAuthParitySameIdentity -Expected $State.FileEvidence[$Relative] `
        -Actual $sealed -Directory $false -RequireContent -RequireSealed
    $State.FilePermissionEvidence[$Relative] = $sealed
}

function Protect-GraphKitAuthParityDirectory {
    param(
        [Parameter(Mandatory)] $State,
        [Parameter(Mandatory)][string] $Relative,
        [AllowNull()] $Hooks
    )
    if ($State.DirectoryPermissionEvidence.ContainsKey($Relative)) { return }
    Invoke-GraphKitAuthParityHook -Hooks $Hooks -Name BeforeSealDirectory `
        -Arguments @($State, $Relative)
    $native = $script:GraphKitAuthParityNativeType
    $path = Join-Path $State.RootPath (
        $Relative -replace '/', [IO.Path]::DirectorySeparatorChar)
    $native::SetOwnerOnly($path, $true, $false)
    $sealed = $native::InspectDirectory($State.RootPath, $Relative)
    Assert-GraphKitAuthParitySameIdentity -Expected $State.DirectoryEvidence[$Relative] `
        -Actual $sealed -Directory $true -RequireSealed
    $State.DirectoryPermissionEvidence[$Relative] = $sealed
}

function Protect-GraphKitAuthParityState {
    param(
        [Parameter(Mandatory)] $State,
        [AllowNull()] $Hooks
    )
    foreach ($relative in $State.ExpectedFiles) {
        Protect-GraphKitAuthParityFile -State $State -Relative $relative -Hooks $Hooks
    }
    foreach ($relative in @($State.ExpectedDirectories | Sort-Object {
        ($_ -split '/').Count
    } -Descending)) {
        Protect-GraphKitAuthParityDirectory -State $State -Relative $relative -Hooks $Hooks
    }
    if ($null -eq $State.RootPermissionEvidence) {
        Invoke-GraphKitAuthParityHook -Hooks $Hooks -Name BeforeSealRoot -Arguments @($State)
        $native = $script:GraphKitAuthParityNativeType
        $native::SetOwnerOnly($State.RootPath, $true, $false)
        $sealedRoot = $native::InspectDirectory($State.TempParentPath, $State.RootName)
        Assert-GraphKitAuthParitySameIdentity -Expected $State.RootEvidence -Actual $sealedRoot `
            -Directory $true -RequireSealed
        $State.RootPermissionEvidence = $sealedRoot
    }
    $State.Sealed = $true
}

function Expand-GraphKitAuthParitySnapshot {
    param(
        [Parameter(Mandatory)] $State,
        [AllowNull()] $Hooks
    )
    $native = $script:GraphKitAuthParityNativeType
    $snapshot = $native::InspectFile($State.RootPath, $script:GraphKitAuthParitySnapshotName)
    $expectedSnapshot = $State.FileEvidence[$script:GraphKitAuthParitySnapshotName]
    Assert-GraphKitAuthParitySameIdentity -Expected $expectedSnapshot -Actual $snapshot `
        -Directory $false
    if ([long]$snapshot.Length -gt $script:GraphKitAuthParityMaxPackageBytes) {
        throw [InvalidOperationException]::new('The package snapshot exceeds the protected bound.')
    }
    $snapshotBytes = $native::ReadFile($State.RootPath, $script:GraphKitAuthParitySnapshotName)
    $capturedSha256 = [Convert]::ToHexString(
        [Security.Cryptography.SHA256]::HashData($snapshotBytes)).ToLowerInvariant()
    if ([long]$snapshotBytes.LongLength -ne [long]$expectedSnapshot.Length -or
        $capturedSha256 -cne [string]$expectedSnapshot.Sha256 -or
        $capturedSha256 -cne [string]$State.CandidateSha256) {
        throw [InvalidOperationException]::new(
            'The captured package snapshot bytes changed before archive validation.')
    }
    $memory = [IO.MemoryStream]::new($snapshotBytes, $false)
    try {
        $archive = [IO.Compression.ZipArchive]::new(
            $memory, [IO.Compression.ZipArchiveMode]::Read, $false)
        try {
            $plan = Get-GraphKitAuthParityArchivePlan -Archive $archive
            Invoke-GraphKitAuthParityHook -Hooks $Hooks -Name AfterArchivePlan `
                -Arguments @($State, $plan)
            $moduleEvidence = $native::CreateDirectoryOwnerOnly(
                $State.RootPath, $script:GraphKitAuthParityModuleName)
            if (-not $native::HasInitialOwnerOnlyDirectoryAccess($moduleEvidence)) {
                throw [InvalidOperationException]::new('The module root was not created owner-only.')
            }
            $State.DirectoryEvidence['module'] = $moduleEvidence
            $State.ExpectedDirectories.Add('module')
            foreach ($directory in $plan.Directories) {
                $segments = @($directory -split '/')
                $parentRelative = 'module'
                foreach ($segment in $segments) {
                    $relative = "$parentRelative/$segment"
                    if (-not $State.DirectoryEvidence.ContainsKey($relative)) {
                        $parentPath = Join-Path $State.RootPath (
                            $parentRelative -replace '/', [IO.Path]::DirectorySeparatorChar)
                        $created = $native::CreateDirectoryOwnerOnly($parentPath, $segment)
                        if (-not $native::HasInitialOwnerOnlyDirectoryAccess($created)) {
                            throw [InvalidOperationException]::new(
                                'An archive directory was not created owner-only.')
                        }
                        $State.DirectoryEvidence[$relative] = $created
                        $State.ExpectedDirectories.Add($relative)
                    }
                    $parentRelative = $relative
                }
            }
            foreach ($record in $plan.Records) {
                $bytes = Read-GraphKitAuthParityArchiveEntry -Entry $record.Entry
                $relative = "module/$($record.Path)"
                $written = $native::WriteFileCreateNew($State.RootPath, $relative, $bytes, $true)
                if (-not $native::HasInitialOwnerOnlyAccess($written.DestinationInitial) -or
                    [long]$written.Destination.Length -ne [long]$record.Length) {
                    throw [InvalidOperationException]::new(
                        'An archive file was not created with its exact protected bytes.')
                }
                $State.FileEvidence[$relative] = $written.Destination
                $State.ExpectedFiles.Add($relative)
                Protect-GraphKitAuthParityFile -State $State -Relative $relative -Hooks $Hooks
            }
        }
        finally { $archive.Dispose() }
    }
    finally {
        $memory.Dispose()
        [Array]::Clear($snapshotBytes, 0, $snapshotBytes.Length)
        $snapshotBytes = $null
    }

    Protect-GraphKitAuthParityState -State $State -Hooks $Hooks
    $State.ModuleRoot = Join-Path $State.RootPath $script:GraphKitAuthParityModuleName
    $State.ExtractedManifestPath = Join-Path $State.ModuleRoot 'GraphKit.psd1'
    $State.ExtractedModulePath = Join-Path $State.ModuleRoot 'GraphKit.psm1'
}

function Remove-GraphKitAuthParityState {
    param(
        [Parameter(Mandatory)] $State,
        [AllowNull()] $Hooks
    )
    Assert-GraphKitAuthParityState -State $State -Purpose Cleanup
    $native = $script:GraphKitAuthParityNativeType
    if (-not [bool]$State.Sealed) {
        Protect-GraphKitAuthParityState -State $State -Hooks $Hooks
        Assert-GraphKitAuthParityState -State $State -Purpose Cleanup
    }
    $native::SetOwnerOnly($State.RootPath, $true, $true)
    Invoke-GraphKitAuthParityHook -Hooks $Hooks -Name OnCleanupRoot `
        -Arguments @($State, 'AfterWritable', $native)
    $writableRoot = $native::InspectDirectory($State.TempParentPath, $State.RootName)
    Assert-GraphKitAuthParitySameIdentity -Expected $State.RootEvidence -Actual $writableRoot `
        -Directory $true
    foreach ($relative in @($State.ExpectedDirectories | Sort-Object {
        ($_ -split '/').Count
    })) {
        $native::SetOwnerOnly((Join-Path $State.RootPath (
            $relative -replace '/', [IO.Path]::DirectorySeparatorChar)), $true, $true)
        Invoke-GraphKitAuthParityHook -Hooks $Hooks -Name OnCleanupDirectory `
            -Arguments @($State, $relative, 'AfterWritable', $native)
        $writableDirectory = $native::InspectDirectory($State.RootPath, $relative)
        Assert-GraphKitAuthParitySameIdentity -Expected $State.DirectoryEvidence[$relative] `
            -Actual $writableDirectory -Directory $true
    }
    foreach ($relative in $State.ExpectedFiles) {
        $path = Join-Path $State.RootPath (
            $relative -replace '/', [IO.Path]::DirectorySeparatorChar)
        $expected = $State.FileEvidence[$relative]
        Invoke-GraphKitAuthParityHook -Hooks $Hooks -Name OnCleanupFile `
            -Arguments @($State, $relative, 'BeforeWritable', $native)
        $actual = $native::InspectFile($State.RootPath, $relative)
        Assert-GraphKitAuthParitySameIdentity -Expected $expected `
            -Actual $actual -Directory $false -RequireSealed -RequireContent
        $native::SetOwnerOnly($path, $false, $true)
        Invoke-GraphKitAuthParityHook -Hooks $Hooks -Name OnCleanupFile `
            -Arguments @($State, $relative, 'AfterWritable', $native)
        $reopened = $native::InspectFile($State.RootPath, $relative)
        Assert-GraphKitAuthParitySameIdentity -Expected $expected -Actual $reopened `
            -Directory $false -RequireContent
        [IO.File]::Delete($path)
    }
    foreach ($relative in @($State.ExpectedDirectories | Sort-Object {
        ($_ -split '/').Count
    } -Descending)) {
        $path = Join-Path $State.RootPath (
            $relative -replace '/', [IO.Path]::DirectorySeparatorChar)
        if ([IO.Directory]::EnumerateFileSystemEntries($path).GetEnumerator().MoveNext()) {
            throw [InvalidOperationException]::new('A protected parity directory was not empty at cleanup.')
        }
        Invoke-GraphKitAuthParityHook -Hooks $Hooks -Name OnCleanupDirectory `
            -Arguments @($State, $relative, 'BeforeDelete', $native)
        $deleteDirectory = $native::InspectDirectory($State.RootPath, $relative)
        Assert-GraphKitAuthParitySameIdentity -Expected $State.DirectoryEvidence[$relative] `
            -Actual $deleteDirectory -Directory $true
        [IO.Directory]::Delete($path, $false)
    }
    if ([IO.Directory]::EnumerateFileSystemEntries($State.RootPath).GetEnumerator().MoveNext()) {
        throw [InvalidOperationException]::new('The protected parity root was not empty at cleanup.')
    }
    Invoke-GraphKitAuthParityHook -Hooks $Hooks -Name OnCleanupRoot `
        -Arguments @($State, 'BeforeDelete', $native)
    $deleteRoot = $native::InspectDirectory($State.TempParentPath, $State.RootName)
    Assert-GraphKitAuthParitySameIdentity -Expected $State.RootEvidence -Actual $deleteRoot `
        -Directory $true
    [IO.Directory]::Delete($State.RootPath, $false)
}

function Get-GraphKitAuthParityDescriptorRoute {
    param(
        [Parameter(Mandatory)][string] $ManifestRoot,
        [Parameter(Mandatory)][string] $Mode
    )
    $route = New-GraphKitAuthParityRoute -Mode $Mode
    $descriptorPath = Join-Path $ManifestRoot 'Data/Operations/ManagedDevice.List.psd1'
    $descriptor = Import-PowerShellDataFile -Path $descriptorPath -ErrorAction Stop
    if ([int]$descriptor.SchemaVersion -ne 1 -or
        [string]$descriptor.Type -cne $route.OperationType -or
        [string]$descriptor.Operation -cne $route.Operation -or
        [string]$descriptor.IdentityRequirement -cne 'Verified' -or
        [string]$descriptor.PagingStrategy -cne 'NextLink' -or
        [string]$descriptor.Method -cne 'GET' -or
        [string]$descriptor.ReplayPolicy -cne 'Safe' -or
        $Mode -cnotin @($descriptor.SupportedAuthModes)) {
        throw [InvalidOperationException]::new('The package does not declare the protected parity route.')
    }
    return $route
}

function Invoke-GraphKitAuthParityCaptured {
    param(
        [Parameter(Mandatory)][scriptblock] $Action,
        [Parameter(Mandatory)][int] $ExpectedCount
    )
    $records = @(& $Action 2>&1 3>&1 4>&1 5>&1 6>&1)
    $streamRecords = @($records | Where-Object {
        $_ -is [Management.Automation.ErrorRecord] -or
        $_ -is [Management.Automation.WarningRecord] -or
        $_ -is [Management.Automation.VerboseRecord] -or
        $_ -is [Management.Automation.DebugRecord] -or
        $_ -is [Management.Automation.InformationRecord]
    })
    if ($streamRecords.Count -ne 0) {
        throw [InvalidOperationException]::new(
            'A protected parity command wrote to a diagnostic stream.')
    }
    $success = @($records | Where-Object {
        $_ -isnot [Management.Automation.ErrorRecord] -and
        $_ -isnot [Management.Automation.WarningRecord] -and
        $_ -isnot [Management.Automation.VerboseRecord] -and
        $_ -isnot [Management.Automation.DebugRecord] -and
        $_ -isnot [Management.Automation.InformationRecord]
    })
    if ($success.Count -ne $ExpectedCount -or
        ($ExpectedCount -eq 1 -and $null -eq $success[0])) {
        throw [InvalidOperationException]::new(
            'A protected parity command returned an invalid result count.')
    }
    return $success
}

function Get-GraphKitAuthParityDiagnostics {
    param(
        [Parameter(Mandatory)][Management.Automation.PSModuleInfo] $Module,
        [Parameter(Mandatory)] $State
    )
    $ModuleRoot = $State.ModuleRoot
    $defaultContext = [Runtime.Loader.AssemblyLoadContext]::Default
    $defaultMsalBefore = @($defaultContext.Assemblies | Where-Object {
        $_.GetName().Name -ceq 'Microsoft.Identity.Client'
    })
    $contracts = @([AppDomain]::CurrentDomain.GetAssemblies() | Where-Object {
        $_.GetName().Name -ceq 'GraphKit.Auth.Contracts'
    })
    $hostResult = Invoke-GraphKitAuthParityCaptured -ExpectedCount 1 -Action {
        & $Module { $script:GraphKitAuthHost }
    }
    $authHost = $hostResult[0]
    if ($contracts.Count -ne 1 -or $null -eq $authHost) {
        throw [InvalidOperationException]::new('The GraphKit.Auth contracts or host is not singular.')
    }
    $contractAssembly = $contracts[0]
    $contractContext = [Runtime.Loader.AssemblyLoadContext]::GetLoadContext($contractAssembly)
    $contractPath = Join-Path $ModuleRoot 'Assemblies/GraphKit.Auth/GraphKit.Auth.Contracts.dll'
    $contractLocation = [IO.Path]::GetFullPath($contractAssembly.Location)
    $logicalContractLocation = [IO.Path]::GetFullPath($contractPath)
    $expectedContractLocation = [string]$State.FileEvidence[
        'module/Assemblies/GraphKit.Auth/GraphKit.Auth.Contracts.dll'].PhysicalPath
    $hostType = $authHost.GetType()
    $marker = $hostType.GetField(
        'ContractMarker', [Reflection.BindingFlags]'Public,Static')
    $providerField = $hostType.GetField(
        '_providerAssembly', [Reflection.BindingFlags]'Instance,NonPublic')
    $providerAssembly = if ($null -eq $providerField) {
        $null
    }
    else { $providerField.GetValue($authHost) }
    $providerContext = if ($null -eq $providerAssembly) {
        $null
    }
    else {
        [Runtime.Loader.AssemblyLoadContext]::GetLoadContext($providerAssembly)
    }
    $msalPath = Join-Path $ModuleRoot 'Assemblies/GraphKit.Auth/Microsoft.Identity.Client.dll'
    if ($null -eq $providerContext -or
        [object]::ReferenceEquals($providerContext, $defaultContext)) {
        throw [InvalidOperationException]::new('The provider load context was rejected.')
    }
    Assert-GraphKitAuthParityState -State $State -Purpose Import
    $msalRelative = 'module/Assemblies/GraphKit.Auth/Microsoft.Identity.Client.dll'
    $msalEvidence = $script:GraphKitAuthParityNativeType::InspectFile(
        $State.RootPath, $msalRelative)
    Assert-GraphKitAuthParitySameIdentity -Expected $State.FileEvidence[$msalRelative] `
        -Actual $msalEvidence -Directory $false -RequireSealed -RequireContent
    $providerMsalBefore = @($providerContext.Assemblies | Where-Object {
        $_.GetName().Name -ceq 'Microsoft.Identity.Client'
    })
    if ($providerMsalBefore.Count -eq 0) {
        $null = $providerContext.LoadFromAssemblyPath([IO.Path]::GetFullPath($msalPath))
    }
    $providerMsal = @($providerContext.Assemblies | Where-Object {
        $_.GetName().Name -ceq 'Microsoft.Identity.Client'
    })
    $defaultMsalAfter = @($defaultContext.Assemblies | Where-Object {
        $_.GetName().Name -ceq 'Microsoft.Identity.Client'
    })
    $defaultMsalUnchanged = $defaultMsalAfter.Count -eq $defaultMsalBefore.Count
    if ($defaultMsalUnchanged) {
        foreach ($assembly in $defaultMsalBefore) {
            if (-not @($defaultMsalAfter | Where-Object {
                [object]::ReferenceEquals($_, $assembly)
            }).Count) {
                $defaultMsalUnchanged = $false
                break
            }
        }
    }
    $locationComparison = if ($IsWindows) {
        [StringComparison]::OrdinalIgnoreCase
    }
    else {
        [StringComparison]::Ordinal
    }
    $publicAbiHash = Get-GraphKitAuthParityPublicAbiSha256 -Assembly $contractAssembly
    $expectedProviderLocation = [string]$State.FileEvidence[
        'module/Assemblies/GraphKit.Auth/GraphKit.Auth.dll'].PhysicalPath
    $logicalProviderLocation = [IO.Path]::GetFullPath(
        (Join-Path $ModuleRoot 'Assemblies/GraphKit.Auth/GraphKit.Auth.dll'))
    $expectedMsalLocation = [string]$State.FileEvidence[$msalRelative].PhysicalPath
    $logicalMsalLocation = [IO.Path]::GetFullPath($msalPath)
    $checks = [pscustomobject][ordered]@{
        abiMarkerExact = $null -ne $marker -and
            [string]$marker.GetValue($null) -ceq 'GraphKit.Auth.Abi/1'
        contractsDefault = (Test-GraphKitAuthParityContractsIdentity `
            -Name $contractAssembly.GetName()) -and
            [object]::ReferenceEquals($contractContext, $defaultContext) -and
            ([string]::Equals(
                $contractLocation, $expectedContractLocation, $locationComparison) -or
                [string]::Equals(
                    $contractLocation, $logicalContractLocation, $locationComparison))
        providerCollectibleNonDefault = $null -ne $providerAssembly -and
            $providerAssembly.GetName().Name -ceq 'GraphKit.Auth' -and
            $null -ne $providerContext -and
            -not [object]::ReferenceEquals($providerContext, $defaultContext) -and
            [bool]$providerContext.IsCollectible -and
            ([string]::Equals(
                [IO.Path]::GetFullPath($providerAssembly.Location),
                $expectedProviderLocation, $locationComparison) -or
                [string]::Equals(
                    [IO.Path]::GetFullPath($providerAssembly.Location),
                    $logicalProviderLocation, $locationComparison))
        msalVersionExact = $providerMsal.Count -eq 1 -and
            $providerMsal[0].GetName().Version -eq [version]'4.82.1.0' -and
            ([string]::Equals(
                [IO.Path]::GetFullPath($providerMsal[0].Location),
                $expectedMsalLocation, $locationComparison) -or
                [string]::Equals(
                    [IO.Path]::GetFullPath($providerMsal[0].Location),
                    $logicalMsalLocation, $locationComparison))
        providerMsalSameContext = $providerMsal.Count -eq 1 -and
            [object]::ReferenceEquals(
                [Runtime.Loader.AssemblyLoadContext]::GetLoadContext($providerMsal[0]),
                $providerContext) -and $defaultMsalUnchanged
        publicAbiExact = $publicAbiHash -ceq $script:GraphKitAuthParityExpectedPublicAbiSha256
    }
    $providerWeakReference = $authHost.LoadContextWeakReference
    $null = Assert-GraphKitAuthParityProviderWeakReference `
        -WeakReference $providerWeakReference -ProviderContext $providerContext
    return [pscustomobject]@{
        Checks = $checks
        InterfaceType = $contractAssembly.GetType('GraphKit.Auth.IGraphTokenSource', $true, $false)
        ContractsAssembly = $contractAssembly
        ProviderWeakReference = $providerWeakReference
    }
}

function Test-GraphKitAuthParityAcquisitionFailure {
    param(
        [Parameter(Mandatory)][Exception] $Exception,
        [Parameter(Mandatory)][Reflection.Assembly] $ContractsAssembly
    )
    $current = $Exception
    for ($depth = 0; $depth -lt 8 -and $null -ne $current; $depth++) {
        if ($current.GetType().FullName -ceq 'GraphKit.Auth.GraphAuthException' -and
            [object]::ReferenceEquals($current.GetType().Assembly, $ContractsAssembly) -and
            [string]$current.Category -ceq 'Acquisition') {
            return $true
        }
        $current = $current.InnerException
    }
    return $false
}

function Get-GraphKitAuthParityMember {
    param(
        [AllowNull()] $Value,
        [Parameter(Mandatory)][string] $Name
    )
    if ($null -eq $Value) {
        return [pscustomobject]@{ Exists = $false; Value = $null }
    }
    if ($Value -is [Collections.IDictionary]) {
        $exists = $Value.Contains($Name)
        return [pscustomobject]@{
            Exists = $exists
            Value = $(if ($exists) { $Value[$Name] } else { $null })
        }
    }
    $property = $Value.PSObject.Properties[$Name]
    return [pscustomobject]@{
        Exists = $null -ne $property
        Value = $(if ($null -ne $property) { $property.Value } else { $null })
    }
}

function Test-GraphKitAuthParityClientScope {
    param(
        [AllowNull()] $ContextClientId,
        [AllowNull()][string] $SourceClientId,
        [Parameter(Mandatory)][string] $AuthMode
    )
    $contextText = if ($null -eq $ContextClientId) { '' } else { [string]$ContextClientId }
    $sourceText = if ($null -eq $SourceClientId) { '' } else { [string]$SourceClientId }
    if ($AuthMode -ceq 'BearerToken') {
        return [string]::IsNullOrEmpty($contextText) -and
            [string]::IsNullOrEmpty($sourceText)
    }
    if ([string]::IsNullOrEmpty($contextText) -or [string]::IsNullOrEmpty($sourceText)) {
        return $AuthMode -ceq 'ManagedIdentity' -and
            [string]::IsNullOrEmpty($contextText) -and
            [string]::IsNullOrEmpty($sourceText)
    }
    $contextGuid = [guid]::Empty
    $sourceGuid = [guid]::Empty
    return [guid]::TryParse($contextText, [ref]$contextGuid) -and
        [guid]::TryParse($sourceText, [ref]$sourceGuid) -and
        $contextGuid -ne [guid]::Empty -and $sourceGuid -ne [guid]::Empty -and
        $contextGuid -eq $sourceGuid
}

function Assert-GraphKitAuthParityLiveContext {
    param(
        [Parameter(Mandatory)] $Context,
        [Parameter(Mandatory)] $Route,
        [Parameter(Mandatory)] $Diagnostics,
        [Parameter(Mandatory)][string] $RequestedProfileId
    )
    $tenantId = if ($null -ne $Context.PSObject.Properties['TenantId'] -and
        $Context.TenantId -is [guid]) { [guid]$Context.TenantId } else { [guid]::Empty }
    $source = if ($null -ne $Context.PSObject.Properties['TokenSource']) {
        $Context.TokenSource
    }
    else { $null }
    $cloud = if ($null -ne $Context.PSObject.Properties['Cloud']) {
        [string]$Context.Cloud
    }
    else { '' }
    $graphBaseUri = if ($null -ne $Context.PSObject.Properties['GraphBaseUri'] -and
        $Context.GraphBaseUri -is [uri]) { [uri]$Context.GraphBaseUri } else { $null }
    $contextClientId = if ($null -ne $Context.PSObject.Properties['ClientId']) {
        $Context.ClientId
    }
    else { $null }
    $sourceGeneration = if ($null -ne $source -and
        $null -ne $source.PSObject.Properties['CredentialGeneration']) {
        [string]$source.CredentialGeneration
    }
    else { '' }
    $expectedCredentialFingerprint = if ([string]::IsNullOrWhiteSpace($sourceGeneration)) {
        ''
    }
    else {
        [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData(
            [Text.Encoding]::UTF8.GetBytes($sourceGeneration))).ToLowerInvariant()
    }
    $credentialFingerprint = if (
        $null -ne $Context.PSObject.Properties['CredentialFingerprint']) {
        [string]$Context.CredentialFingerprint
    }
    else { '' }
    $audience = if ($null -ne $source -and
        $null -ne $source.PSObject.Properties['Audience']) {
        [string]$source.Audience
    }
    else { '' }
    $baseText = if ($null -eq $graphBaseUri) { '' } else {
        $graphBaseUri.AbsoluteUri.TrimEnd('/')
    }
    $audienceUri = $null
    try { $audienceUri = [uri]$audience } catch { $audienceUri = $null }
    $audienceText = if ($null -eq $audienceUri -or -not $audienceUri.IsAbsoluteUri) {
        ''
    }
    else { $audienceUri.AbsoluteUri.TrimEnd('/') }
    if ($Context.PSObject.TypeNames.Count -lt 1 -or
        [string]$Context.PSObject.TypeNames[0] -cne 'GraphKit.Context' -or
        $null -eq $Context.PSObject.Properties['ProfileId'] -or
        [string]$Context.ProfileId -cne $RequestedProfileId -or
        $tenantId -eq [guid]::Empty -or
        -not $Diagnostics.InterfaceType.IsInstanceOfType($source) -or
        [string]$source.AuthMode -cne [string]$Route.AuthMode -or
        [bool]$source.CanRefresh -ne [bool]$Route.CanRefresh -or
        [string]::IsNullOrWhiteSpace($sourceGeneration) -or
        [string]::IsNullOrWhiteSpace($cloud) -or
        $null -eq $graphBaseUri -or -not $graphBaseUri.IsAbsoluteUri -or
        -not [string]::Equals($baseText, $audienceText, [StringComparison]::OrdinalIgnoreCase) -or
        -not (Test-GraphKitAuthParityClientScope -ContextClientId $contextClientId `
            -SourceClientId ([string]$source.ClientId) -AuthMode ([string]$Route.AuthMode)) -or
        [string]::IsNullOrWhiteSpace($credentialFingerprint) -or
        $credentialFingerprint -cne $expectedCredentialFingerprint) {
        throw [InvalidOperationException]::new('The protected parity context or source was rejected.')
    }
}

function Assert-GraphKitAuthParityLiveResult {
    param(
        [Parameter(Mandatory)] $Result,
        [Parameter(Mandatory)] $Context
    )
    if ($Result.PSObject.TypeNames.Count -lt 1 -or
        [string]$Result.PSObject.TypeNames[0] -cne 'GraphKit.OperationResult' -or
        $null -eq $Result.PSObject.Properties['Outcome'] -or
        [string]$Result.Outcome -cne 'Succeeded' -or
        $null -eq $Result.PSObject.Properties['Certainty'] -or
        [string]$Result.Certainty -cne 'Known' -or
        $null -eq $Result.PSObject.Properties['Truncated'] -or
        $Result.Truncated -isnot [bool] -or [bool]$Result.Truncated -or
        $null -eq $Result.PSObject.Properties['Data'] -or
        $null -eq $Result.PSObject.Properties['Provenance'] -or
        $null -eq $Result.Provenance) {
        throw [InvalidOperationException]::new('The protected parity read envelope was rejected.')
    }
    $provenance = $Result.Provenance
    $identityStateMember = Get-GraphKitAuthParityMember $provenance IdentityState
    $tenantMember = Get-GraphKitAuthParityMember $provenance TenantId
    $actualTenantMember = Get-GraphKitAuthParityMember $provenance ActualTenantId
    $fingerprintMember = Get-GraphKitAuthParityMember $provenance TokenFingerprint
    $generationMember = Get-GraphKitAuthParityMember $provenance CredentialGeneration
    $cloudMember = Get-GraphKitAuthParityMember $provenance Cloud
    $identityState = $identityStateMember.Value
    $tenantId = $tenantMember.Value
    $actualTenantId = $actualTenantMember.Value
    $fingerprint = [string]$fingerprintMember.Value
    $generation = [string]$generationMember.Value
    $cloud = [string]$cloudMember.Value
    $sourceTenantId = $Context.TokenSource.VerifiedTenantId
    $parsedTenant = [guid]::Empty
    $parsedActual = [guid]::Empty
    $parsedSource = [guid]::Empty
    $sourceGeneration = [string]$Context.TokenSource.CredentialGeneration
    $sourceFingerprintMember = Get-GraphKitAuthParityMember `
        $Context.TokenSource TokenFingerprint
    $resultFingerprintMember = Get-GraphKitAuthParityMember $Result TokenFingerprint
    if (-not $identityStateMember.Exists -or -not $tenantMember.Exists -or
        -not $actualTenantMember.Exists -or -not $fingerprintMember.Exists -or
        -not $generationMember.Exists -or -not $cloudMember.Exists -or
        [string]$identityState -cne 'VerifiedForToken' -or
        -not [guid]::TryParse([string]$tenantId, [ref]$parsedTenant) -or
        -not [guid]::TryParse([string]$actualTenantId, [ref]$parsedActual) -or
        -not [guid]::TryParse([string]$sourceTenantId, [ref]$parsedSource) -or
        $parsedTenant -eq [guid]::Empty -or $parsedActual -eq [guid]::Empty -or
        $parsedSource -eq [guid]::Empty -or
        $parsedTenant -ne [guid]$Context.TenantId -or
        $parsedActual -ne [guid]$Context.TenantId -or
        $parsedSource -ne [guid]$Context.TenantId -or
        [string]::IsNullOrWhiteSpace($fingerprint) -or
        [string]::IsNullOrWhiteSpace($generation) -or
        [string]::IsNullOrWhiteSpace($cloud) -or
        $generation -cne $sourceGeneration -or
        $cloud -cne [string]$Context.Cloud -or
        ($sourceFingerprintMember.Exists -and
            ([string]::IsNullOrWhiteSpace([string]$sourceFingerprintMember.Value) -or
                [string]$sourceFingerprintMember.Value -cne $fingerprint)) -or
        ($resultFingerprintMember.Exists -and
            ([string]::IsNullOrWhiteSpace([string]$resultFingerprintMember.Value) -or
                [string]$resultFingerprintMember.Value -cne $fingerprint))) {
        throw [InvalidOperationException]::new('The protected parity tenant proof was rejected.')
    }
    return [long]@($Result.Data).Count
}

function Invoke-GraphKitAuthParityLiveCore {
    param(
        [Parameter(Mandatory)] $Route,
        [Parameter(Mandatory)] $Diagnostics,
        [Parameter(Mandatory)][string] $ProfileId,
        [AllowNull()][string] $StorePath,
        [Parameter(Mandatory)][bool] $StorePathBound,
        [Parameter(Mandatory)][scriptblock] $GetContextAction,
        [Parameter(Mandatory)][scriptblock] $ReadAction
    )
    $core = [pscustomobject][ordered]@{
        recordKind = 'GraphKit.Task8.LiveCoreTestResult/1'
        authMode = [string]$Route.AuthMode
        state = 'Failed'
        failureStage = 'Context'
        failureCode = 'ContextRejected'
        contextMatched = $false
        sourceMatched = $false
        tenantProofVerified = $false
        readAttempted = $false
        readSucceeded = $false
        rowCount = [long]0
    }
    $context = $null
    $readResult = $null
    try {
        try {
            $context = Invoke-GraphKitAuthParityHook -Hooks ([pscustomobject]@{
                Action = $GetContextAction
            }) -Name Action -Arguments @(
                $ProfileId, $(if ($StorePathBound) { $StorePath } else { $null }), $Route) -PassThru
            Assert-GraphKitAuthParityLiveContext -Context $context -Route $Route `
                -Diagnostics $Diagnostics -RequestedProfileId $ProfileId
            $core.contextMatched = $true
            $core.sourceMatched = $true
        }
        catch { return $core }

        $core.failureStage = 'Read'
        $core.failureCode = 'ReadFailed'
        $core.readAttempted = $true
        try {
            $readResult = Invoke-GraphKitAuthParityHook -Hooks ([pscustomobject]@{
                Action = $ReadAction
            }) -Name Action -Arguments @($context, 'ManagedDevice', 'List', $true) `
                -PassThru -PreserveExceptionType
        }
        catch {
            if (Test-GraphKitAuthParityAcquisitionFailure -Exception $_.Exception `
                -ContractsAssembly $Diagnostics.ContractsAssembly) {
                $core.failureStage = 'Acquisition'
                $core.failureCode = 'AcquisitionFailed'
            }
            return $core
        }
        try {
            $core.rowCount = Assert-GraphKitAuthParityLiveResult `
                -Result $readResult -Context $context
        }
        catch { return $core }
        $core.readSucceeded = $true
        $core.tenantProofVerified = $true
        $core.state = 'Passed'
        $core.failureStage = 'None'
        $core.failureCode = 'None'
        return $core
    }
    finally {
        $readResult = $null
        $context = $null
    }
}

$task8Hooks = if ($MyInvocation.InvocationName -ceq '.') {
    Get-GraphKitAuthParityTestHooks
}
else { $null }
if ($null -ne $task8Hooks -and
    $null -ne $task8Hooks.PSObject.Properties['ExportFunctionsOnly'] -and
    [bool]$task8Hooks.ExportFunctionsOnly) {
    return
}

$task8StartedUtc = Get-GraphKitAuthParityUtcText
$task8Execution = if ($PSCmdlet.ParameterSetName -ceq 'DryRun') { 'DryRun' } else { 'Live' }
$task8Record = New-GraphKitAuthParityModeRecord -Execution $task8Execution `
    -Mode $AuthMode -StartedUtc $task8StartedUtc
$task8State = $null
$task8ImportedModule = $null
$task8Imported = $null
$task8Context = $null
$task8ContextCommand = $null
$task8ContextResult = $null
$task8ContextParameters = $null
$task8ReadResult = $null
$task8ReadCommand = $null
$task8ReadResultRecords = $null
$task8GetContextAction = $null
$task8ReadAction = $null
$task8LiveCoreResult = $null
$task8StorePathBound = $false
$task8Diagnostics = $null
$task8ProviderWeakReference = $null
$task8PrimaryFailed = $false
$task8FailureStage = 'Artifact'
$task8FailureCode = 'ArtifactRejected'
$task8HadModulePath = Test-Path -LiteralPath Env:PSModulePath
$task8SavedModulePath = if ($task8HadModulePath) { [string]$env:PSModulePath } else { $null }
$task8ModulePathChanged = $false

try {
    if ([string]::IsNullOrWhiteSpace($PackagePath) -or
        [IO.Path]::GetExtension($PackagePath) -cne '.nupkg' -or
        $PackageSha256 -cnotmatch '^[0-9a-f]{64}$' -or
        $AuthMode -cnotin $script:GraphKitAuthParityModes -or
        ($task8Execution -ceq 'Live' -and
            ($ProfileId -cnotmatch '^[a-z0-9][a-z0-9-]{0,63}$' -or
                ($PSBoundParameters.ContainsKey('StorePath') -and
                    [string]::IsNullOrWhiteSpace($StorePath))))) {
        throw [InvalidOperationException]::new('The protected parity invocation was rejected.')
    }

    $task8FailureStage = 'Import'
    $task8FailureCode = 'ImportRejected'
    if (@(Get-Module -Name GraphKit -All).Count -ne 0) {
        throw [InvalidOperationException]::new('A GraphKit module is already loaded.')
    }

    $task8FailureStage = 'Artifact'
    $task8FailureCode = 'ArtifactRejected'
    Initialize-GraphKitAuthParityNative
    $task8SourcePath = [IO.Path]::GetFullPath($PackagePath)
    $task8SourceParent = [IO.Path]::GetDirectoryName($task8SourcePath)
    $task8SourceName = [IO.Path]::GetFileName($task8SourcePath)
    if ([string]::IsNullOrWhiteSpace($task8SourceParent) -or
        [string]::IsNullOrWhiteSpace($task8SourceName)) {
        throw [InvalidOperationException]::new('The package source path was rejected.')
    }
    $task8Native = $script:GraphKitAuthParityNativeType
    Invoke-GraphKitAuthParityHook -Hooks $task8Hooks -Name BeforeSourceMetadata `
        -Arguments @($task8SourcePath)
    $task8SourceEvidence = $task8Native::InspectFileMetadata(
        $task8SourceParent, $task8SourceName,
        [long]$script:GraphKitAuthParityMaxPackageBytes)
    $null = Assert-GraphKitAuthParitySourceBound -Evidence $task8SourceEvidence
    if ([long]$task8SourceEvidence.LinkCount -ne 1) {
        throw [InvalidOperationException]::new('The package source is not link-count one.')
    }

    $task8TempParent = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd(
        [IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar)
    $task8TempParentParent = [IO.Path]::GetDirectoryName($task8TempParent)
    $task8TempParentName = [IO.Path]::GetFileName($task8TempParent)
    if ([string]::IsNullOrWhiteSpace($task8TempParentParent) -or
        [string]::IsNullOrWhiteSpace($task8TempParentName)) {
        throw [InvalidOperationException]::new('The protected temporary parent was rejected.')
    }
    $task8TempParentEvidence = $task8Native::InspectDirectory(
        $task8TempParentParent, $task8TempParentName)
    $task8RootName = 'graphkit-task8-' + [guid]::NewGuid().ToString('N')
    $task8RootEvidence = $task8Native::CreateDirectoryOwnerOnly(
        $task8TempParent, $task8RootName)
    $task8RootPath = Join-Path $task8TempParent $task8RootName
    $task8State = [pscustomobject]@{
        TempParentPath = $task8TempParent
        TempParentParent = $task8TempParentParent
        TempParentName = $task8TempParentName
        TempParentEvidence = $task8TempParentEvidence
        RootName = $task8RootName
        RootPath = $task8RootPath
        RootEvidence = $task8RootEvidence
        RootPermissionEvidence = $null
        CandidateSha256 = $PackageSha256
        SnapshotPath = Join-Path $task8RootPath $script:GraphKitAuthParitySnapshotName
        ModuleRoot = $null
        ExtractedManifestPath = $null
        ExtractedModulePath = $null
        ImportedManifestPath = $null
        ImportedModulePath = $null
        ModuleVersion = $null
        Sealed = $false
        FileEvidence = [Collections.Generic.Dictionary[string,object]]::new(
            [StringComparer]::Ordinal)
        FilePermissionEvidence = [Collections.Generic.Dictionary[string,object]]::new(
            [StringComparer]::Ordinal)
        DirectoryEvidence = [Collections.Generic.Dictionary[string,object]]::new(
            [StringComparer]::Ordinal)
        DirectoryPermissionEvidence = [Collections.Generic.Dictionary[string,object]]::new(
            [StringComparer]::Ordinal)
        ExpectedFiles = [Collections.Generic.List[string]]::new()
        ExpectedDirectories = [Collections.Generic.List[string]]::new()
    }
    if (-not $task8Native::HasInitialOwnerOnlyDirectoryAccess($task8RootEvidence)) {
        throw [InvalidOperationException]::new('The protected parity root was not created owner-only.')
    }
    $task8MarkerBytes = [Text.UTF8Encoding]::new($false).GetBytes(
        'GraphKit.Task8.ParityRunner/1')
    $task8MarkerWrite = $task8Native::WriteFileCreateNew(
        $task8RootPath, $script:GraphKitAuthParityMarkerName, $task8MarkerBytes, $true)
    if (-not $task8Native::HasInitialOwnerOnlyAccess($task8MarkerWrite.DestinationInitial)) {
        throw [InvalidOperationException]::new('The protected parity marker was not created owner-only.')
    }
    $task8State.FileEvidence[$script:GraphKitAuthParityMarkerName] =
        $task8MarkerWrite.Destination
    $task8State.ExpectedFiles.Add($script:GraphKitAuthParityMarkerName)
    Invoke-GraphKitAuthParityHook -Hooks $task8Hooks -Name AfterRootCreated `
        -Arguments @($task8State)

    Invoke-GraphKitAuthParityHook -Hooks $task8Hooks -Name BeforeSourceHash `
        -Arguments @($task8SourcePath)
    $task8Copy = $task8Native::CopyFileCreateNew(
        $task8SourceParent, $task8SourceName,
        $task8RootPath, $script:GraphKitAuthParitySnapshotName, $true,
        [long]$script:GraphKitAuthParityMaxPackageBytes)
    $task8State.FileEvidence[$script:GraphKitAuthParitySnapshotName] =
        $task8Copy.Destination
    $task8State.ExpectedFiles.Add($script:GraphKitAuthParitySnapshotName)
    if (-not $task8Native::HasInitialOwnerOnlyAccess($task8Copy.DestinationInitial) -or
        [string]$task8Copy.Source.NativeIdentity -cne [string]$task8SourceEvidence.NativeIdentity -or
        [long]$task8Copy.Source.Length -ne [long]$task8SourceEvidence.Length -or
        [long]$task8Copy.Source.LinkCount -ne 1 -or
        [long]$task8Copy.Destination.LinkCount -ne 1 -or
        [string]$task8Copy.Source.Sha256 -cne $PackageSha256 -or
        [string]$task8Copy.Destination.Sha256 -cne $PackageSha256) {
        throw [InvalidOperationException]::new('The package snapshot digest or identity was rejected.')
    }
    $task8Record.packageSha256 = $PackageSha256
    $task8Record.checks.packageDigestMatched = $true
    $task8Record.checks.snapshotBound = $true
    Invoke-GraphKitAuthParityHook -Hooks $task8Hooks -Name AfterSnapshot `
        -Arguments @($task8State)

    Expand-GraphKitAuthParitySnapshot -State $task8State -Hooks $task8Hooks
    $task8Record.checks.archiveValidated = $true
    Invoke-GraphKitAuthParityHook -Hooks $task8Hooks -Name AfterExtraction `
        -Arguments @($task8State)
    Invoke-GraphKitAuthParityHook -Hooks $task8Hooks -Name BeforeImport `
        -Arguments @($task8State)
    Assert-GraphKitAuthParityState -State $task8State -Purpose Import
    $task8Record.checks.extractionSealed = $true

    $task8Route = Get-GraphKitAuthParityDescriptorRoute `
        -ManifestRoot $task8State.ModuleRoot -Mode $AuthMode
    $task8Record.checks.routeMatched = $true
    $task8Record.moduleVersion = Get-GraphKitAuthParityFullVersion `
        -ManifestPath $task8State.ExtractedManifestPath
    $task8State.ModuleVersion = $task8Record.moduleVersion

    $task8FailureStage = 'Import'
    $task8FailureCode = 'ImportRejected'
    $env:PSModulePath = if ($task8HadModulePath -and
        -not [string]::IsNullOrEmpty($task8SavedModulePath)) {
        $task8State.ModuleRoot + [IO.Path]::PathSeparator + $task8SavedModulePath
    }
    else { $task8State.ModuleRoot }
    $task8ModulePathChanged = $true
    Invoke-GraphKitAuthParityHook -Hooks $task8Hooks -Name BeforeFinalImportRecheck `
        -Arguments @($task8State)
    Assert-GraphKitAuthParityState -State $task8State -Purpose Import
    $task8Imported = Invoke-GraphKitAuthParityCaptured -ExpectedCount 1 -Action {
        Import-Module -Name $task8State.ExtractedManifestPath -PassThru -Force -ErrorAction Stop
    }
    $task8ImportedModule = $task8Imported[0]
    $task8LocationComparison = if ($IsWindows) {
        [StringComparison]::OrdinalIgnoreCase
    }
    else { [StringComparison]::Ordinal }
    if ($task8ImportedModule.Name -cne 'GraphKit' -or
        -not [string]::Equals(
            [IO.Path]::GetFullPath($task8ImportedModule.ModuleBase),
            [IO.Path]::GetFullPath($task8State.ModuleRoot),
            $task8LocationComparison) -or
        -not [string]::Equals(
            [IO.Path]::GetFullPath($task8ImportedModule.Path),
            [IO.Path]::GetFullPath($task8State.ExtractedModulePath),
            $task8LocationComparison) -or
        "$($task8ImportedModule.Version)-$($task8ImportedModule.PrivateData.PSData.Prerelease)" -cne
            $task8Record.moduleVersion) {
        throw [InvalidOperationException]::new('The exact extracted GraphKit module was not imported.')
    }
    $task8State.ImportedManifestPath = $task8State.ExtractedManifestPath
    $task8State.ImportedModulePath = $task8ImportedModule.Path
    $task8Record.checks.exactImport = $true
    Invoke-GraphKitAuthParityHook -Hooks $task8Hooks -Name AfterImport `
        -Arguments @($task8State)

    $task8FailureStage = 'Diagnostics'
    $task8FailureCode = 'DiagnosticsRejected'
    $task8Diagnostics = Get-GraphKitAuthParityDiagnostics `
        -Module $task8ImportedModule -State $task8State
    $task8ProviderWeakReference = $task8Diagnostics.ProviderWeakReference
    foreach ($property in $task8Diagnostics.Checks.PSObject.Properties) {
        $task8Record.adapter.$($property.Name) = [bool]$property.Value
    }
    if (@($task8Record.adapter.PSObject.Properties.Value | Where-Object {
        -not [bool]$_
    }).Count -ne 0) {
        throw [InvalidOperationException]::new('The GraphKit.Auth adapter diagnostics were rejected.')
    }

    if ($task8Execution -ceq 'Live') {
        $task8StorePathBound = $PSBoundParameters.ContainsKey('StorePath')
        Invoke-GraphKitAuthParityHook -Hooks $task8Hooks -Name PrepareLiveModule `
            -Arguments @(
                $task8ImportedModule, $task8State, $task8Route, $ProfileId,
                $(if ($task8StorePathBound) { $StorePath } else { $null }),
                $task8StorePathBound)
        Assert-GraphKitAuthParityState -State $task8State -Purpose Import
        $task8ContextCommand = @(Get-Command -Name Get-GraphContext -Module GraphKit `
            -CommandType Function -ErrorAction Stop)
        $task8ReadCommand = @(Get-Command -Name Get-GraphObject -Module GraphKit `
            -CommandType Function -ErrorAction Stop)
        if ($task8ContextCommand.Count -ne 1 -or
            -not [object]::ReferenceEquals($task8ContextCommand[0].Module, $task8ImportedModule) -or
            $task8ReadCommand.Count -ne 1 -or
            -not [object]::ReferenceEquals($task8ReadCommand[0].Module, $task8ImportedModule)) {
            throw [InvalidOperationException]::new('The exact public live commands were not found.')
        }
        $task8GetContextAction = {
            param($requestedProfileId, $requestedStorePath, $route)
            $parameters = @{ ProfileId = $requestedProfileId; ErrorAction = 'Stop' }
            if ($task8StorePathBound) { $parameters.StorePath = $requestedStorePath }
            $records = Invoke-GraphKitAuthParityCaptured -ExpectedCount 1 -Action {
                & $task8ContextCommand[0] @parameters
            }
            return $records[0]
        }.GetNewClosure()
        $task8ReadAction = {
            param($context, $type, $operation, $passThruResult)
            $records = Invoke-GraphKitAuthParityCaptured -ExpectedCount 1 -Action {
                & $task8ReadCommand[0] -Context $context -Type $type `
                    -Operation $operation -PassThruResult:$passThruResult -ErrorAction Stop
            }
            return $records[0]
        }.GetNewClosure()
        $task8LiveCoreResult = Invoke-GraphKitAuthParityLiveCore -Route $task8Route `
            -Diagnostics $task8Diagnostics -ProfileId $ProfileId -StorePath $StorePath `
            -StorePathBound:$task8StorePathBound -GetContextAction $task8GetContextAction `
            -ReadAction $task8ReadAction
        $task8Record.checks.contextMatched = [bool]$task8LiveCoreResult.contextMatched
        $task8Record.checks.sourceMatched = [bool]$task8LiveCoreResult.sourceMatched
        $task8Record.checks.tenantProofVerified = [bool]$task8LiveCoreResult.tenantProofVerified
        $task8Record.read.attempted = [bool]$task8LiveCoreResult.readAttempted
        $task8Record.read.succeeded = [bool]$task8LiveCoreResult.readSucceeded
        $task8Record.read.rowCount = [long]$task8LiveCoreResult.rowCount
        if ($task8LiveCoreResult.state -cne 'Passed') {
            $task8FailureStage = [string]$task8LiveCoreResult.failureStage
            $task8FailureCode = [string]$task8LiveCoreResult.failureCode
            throw [InvalidOperationException]::new('The protected parity live core was rejected.')
        }
    }
}
catch {
    $task8PrimaryFailed = $true
    Set-GraphKitAuthParityFailure -Record $task8Record `
        -Stage $task8FailureStage -Code $task8FailureCode
}
finally {
    $task8LiveCoreResult = $null
    $task8GetContextAction = $null
    $task8ReadAction = $null
    $task8ReadResult = $null
    $task8ReadResultRecords = $null
    $task8ReadCommand = $null
    $task8Context = $null
    $task8ContextResult = $null
    $task8ContextCommand = $null
    $task8ContextParameters = $null
    $task8Diagnostics = $null
    $task8Imported = $null
    $task8CleanupFailed = $false
    if ($null -ne $task8ImportedModule) {
        try {
            $null = Invoke-GraphKitAuthParityCaptured -ExpectedCount 0 -Action {
                Remove-Module -ModuleInfo $task8ImportedModule -Force -ErrorAction Stop
            }
        }
        catch { $task8CleanupFailed = $true }
        $task8ImportedModule = $null
    }
    if ($null -ne $task8ProviderWeakReference) {
        for ($task8GcAttempt = 0;
            $task8GcAttempt -lt 30 -and $task8ProviderWeakReference.IsAlive;
            $task8GcAttempt++) {
            [GC]::Collect()
            [GC]::WaitForPendingFinalizers()
            [GC]::Collect()
        }
        if ($task8ProviderWeakReference.IsAlive) { $task8CleanupFailed = $true }
        $task8ProviderWeakReference = $null
    }
    if ($task8ModulePathChanged) {
        if ($task8HadModulePath) { $env:PSModulePath = $task8SavedModulePath }
        else { Remove-Item -LiteralPath Env:PSModulePath -ErrorAction SilentlyContinue }
        $task8ModulePathChanged = $false
    }
    if ($null -ne $task8State) {
        try {
            Invoke-GraphKitAuthParityHook -Hooks $task8Hooks -Name BeforeCleanup `
                -Arguments @($task8State)
        }
        catch { $task8CleanupFailed = $true }
        try { Remove-GraphKitAuthParityState -State $task8State -Hooks $task8Hooks }
        catch { $task8CleanupFailed = $true }
    }
    if ($task8CleanupFailed) {
        Set-GraphKitAuthParityFailure -Record $task8Record `
            -Stage Cleanup -Code CleanupFailed
        $task8PrimaryFailed = $true
    }
    else {
        $task8Record.checks.cleanupVerified = $true
    }
}

if (-not $task8PrimaryFailed) {
    Set-GraphKitAuthParityPassed -Record $task8Record
}
$task8Record.completedUtc = Get-GraphKitAuthParityUtcText
try {
    Invoke-GraphKitAuthParityHook -Hooks $task8Hooks -Name MutateEvidence `
        -Arguments @($task8Record)
    $null = Test-GraphKitAuthParityEvidence -Record $task8Record
}
catch {
    $task8CandidateVersion = [string]$task8Record.moduleVersion
    $task8SafeVersion = if ($task8CandidateVersion -match
        '^\d+\.\d+\.\d+-[0-9A-Za-z][0-9A-Za-z.-]*$' -and
        -not (Test-GraphKitAuthParityForbiddenString -Value $task8CandidateVersion)) {
        $task8CandidateVersion
    }
    else { '0.0.0-rejected' }
    $task8SafeDigest = if ($task8Record.packageSha256 -cmatch '^[0-9a-f]{64}$') {
        [string]$task8Record.packageSha256
    }
    else { '0' * 64 }
    $task8Record = New-GraphKitAuthParityModeRecord -Execution $task8Execution `
        -Mode $AuthMode -StartedUtc $task8StartedUtc -ModuleVersion $task8SafeVersion `
        -Digest $task8SafeDigest
    Set-GraphKitAuthParityFailure -Record $task8Record `
        -Stage Evidence -Code EvidenceRejected
    $task8Record.completedUtc = Get-GraphKitAuthParityUtcText
    $null = Test-GraphKitAuthParityEvidence -Record $task8Record
}

$task8Json = $task8Record | ConvertTo-Json -Compress -Depth 5
Write-Output $task8Json
