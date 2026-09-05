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
    '4f3c2283640bfe503b5a8e4af68d8aaeb7266a619590afc7d287d8348a4ff459'
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
        return [string]$Evidence.OwnerSid -ceq $currentSid -and
            [string]$Evidence.CurrentIdentitySid -ceq $currentSid -and
            [bool]$Evidence.AccessRulesProtected -and
            -not [bool]$Evidence.HasInheritedAccessRules -and
            [bool]$Evidence.ExactOwnerOnlyAccess -and
            ($Directory -or [bool]$Evidence.FileReadOnly)
    }
    return [int]$Evidence.UnixMode -eq $(if ($Directory) { 0x140 } else { 0x100 })
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
