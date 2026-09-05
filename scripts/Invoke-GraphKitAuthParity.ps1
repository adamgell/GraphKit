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
    '0bfc3f8631cd26cc74d4a445ae12a5221995fadeb811217616a4da51595029c2'
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
H4sIAAAAAAAAE+09a3PbOJLf8ysQVWos1Sga28lmctFochrHTlyb2C7L2ezdzFQKJiGLF4rUkpAfa/u/XzVexJOkZCWzezeqVCyRjUaj0QC6G43GskyyC/QhiYq8zKd08CnJnu0OJnhK3uEsTkk5fLRkIJObkpK5+Wuwl6cpiWiSZ+XgLclIkUQWxOGx9eB0mdFkTgaHGSVFvpiQ4jKJ7GoGExIti4TeDMZRRMpyL89okachoL3iZkHziwIvZjchmJMiyaJkgW0kZ+SaDh89yvCclAscEfT589vT8cm7vx6efR5/PHv3eXI2frv/eW98cvbxdP/z0fjD/uRkvLf/+fPw0aPF8jxNIlQSnJIYRSkuS/QWyPhrQsdLOjvBdLZ/mcQki8ij20cIISSL0AKIOCUppsklAUB0iy4IHaIkS+gQ3aORABrszxf0ZugpfTK7KZMIp+uVPmI1H8Ykowm9Wb38ZIZ3//JihXJpnl2g9yS7cKh1oZLsy16+zGgNYJJR9DFLrj/kMakBk7wixTwpyyTPZIesQPl5nqfosHyTFCSieWEzywN6Si6WKS4OkpS0AV7goiQnOTSpAfr4KiPFpyKh+Dxt0WwGPkni1bt3b1kUJKNSPlbDwUjlY/d0mZLypMgpiSixcThl3uHyMJuRIqEk1sq34spxlt7wMk3g+9c4ouuUkYxXZZVItEMC8nBKcAxFbdj75vlkL1/c+OeT0KyDJvmy8Ml6Rq66vWErFG9ISZMMwzR/mCU0wemm0AXxtOAFdAVZkRl/bEsopknkacmE4guyhxd0WaiGFMklpgRFeVZStIR5QayvID1ohLavX27zzzBUYDLDBVHgAnqnHpwxVYffrYd/Q1JiFngeLHC8INn+dQIsu0Aj9CwICIPkIMUXUMCYGnk1u/XNlqV/wdGX5WJC5jijSVTywrxsfeExpUVyvqTEUzc0EIqb8yXr16CUHGblgkQUUHfF3FrkOQWYvpxsC00P6DHk8Bn9LAt3qxI6aB+Ra3itZqFXaIrTkvTRDJcz0JpIRl8hWixJb22iPxCKY0xxV9Flt8J5oZOoXrKFfY6vk/lyzrUA3lIu8fBJpqhrAKCf0HbFjgoQPnRW5FcwytC4uFjOSUaPl/R4eoqzC7J/HZEFDMsu6HX51MTaE8MbPnyKhk+QFUR+GaneMAh5UNewZxo9wAJZ4UAw4Wcf1+oYcnhcMeBJR6wAW7c6efdbiFxHhMQlSmiJzvNlFpMYJbyBMKGlrLJBx8usgtBlkSnWcJD7dSRM8ecbjA0YBwH+eyiv9BG2UljqQrdRXmzplmJ6tExT1T+DM+i1wyk8VB2vsVww+nhBCgwTpzSryk9JFudXZbfiCHxeq9oHtnrz3XcGJHweC/3tsITqj4tPs4SSCVhBlQxKBbLnQyD1v38scVq6ZfoVNa422UcTVnovny9wkZR5Njgu4iTDqdmkVxUSpe2PYDbeebldI3eh3rMUtn/5btStDk8PmDxXdkEdpFct90mHKhFSyhvpqRc/BdtOtf4/IMBmZwYFe69OsIMCu1cQTImqQPHRWbcXGFriXbmjWZLGR3juSL1RFI0QlB68JfRgmTL3Q7dCqom9jhWN0Ckp8/SSSKeHKNPXaq2K7mflsiDjLCIlzYuyFlY4dPCUgL7CHVeCVPFjxLRPUIaP8oM8TfMrhTA21wcNLXeQHOCIlgLbL2SaF4DtLaHa265eV1/AWov6Yx2DIQh3dwb2gekPWG2177Bef5qDeakahiKQDFjTC/KPZVKQEuUZQQvhPZKdquCtNb9qRkYRKYq8MFtWM6mFiFeNl+45VMovhgEmPxKMj75pQgqUQ0PRCIm65LgEmRRDtdsbfCxJ4Yz5169DzDubERTxwhIvSqR/bIZLlOVocvjG4A8Tc+lknBDuVegy6mqgqllUTMFQf1LNx1JXWRSkJMUlEdMvziLi6owG8nGsTdFdaCKMCd412guHK4ziaj6Qn6rwaXIxo+UABrxwx7rQGplggpUDgMRJRgrxBt25MMfn/0MiKh67OE+KfIEvmPxy+KM8Iy6Y4Sg+u1mQwRiGua7rw+f8hpJff0cxKaMiWdAcREjx7i2hUtLeKIBfkgwXNwd5Mbel8u2enGqSLCNxVQQmCPGOURF1q/r66hUj8oQVtRDT4sb4bQ4e+Egyla1aIlx9FWPIKeXigY+wMkboAy7KGU4Hk+Sf5Hj6k1vHz92ey3idHIMFNldANIvjKW8x7/QQPiEMavLedqDuTY6pWdZaBD912XoBlsFU41CvLW/YdKex5i2h73FJ2S7JPryzZUInRhQeoZfbMMmrnzsvn7n1h2mAj3/CCoLD50lnTPN5EvGRbS8Jsea6ivI0TcAz/gpt3ar19X4L4bQgOL5BBLw2pTPtuWbhA0h+0tnLl2mMspwizAjHaSqWLuJvg0lsl3UKumVsvu95qTUpNX9NQXNLmwaeI9QHBSG2EFSIq28kLUlgNYR1tSDlMgXFav4lTgpsuRhYzZqOMXgDXo4iX5ZviXjU7Q3O8sOMPtv1DSrFKPeVcGvt7G33huiHH9D2j9vmcANRFuQ9Hun+GD+H1hoyxnDZ+bHt8FxZxr7FkHCHwwpkPnwYkKLI8vAw0GWz2feVCC/5yHXXrKyQFyRfkIzEJ9KG2IhKPp5SpgdaGrlZWSudfILnRCxLGuqgDlujQ3q7SWjZ0QyGboziJTONeB8rDb3e3SZ6o87rwdUb4OqK/mbH1JsKy85jt/kdbjXGW2MBr8DMgrabpM0QFVst1mXlPGC48Sr6qrG2gJxXJlm1n3t3J/BZppr2Qnluk4wOPuDrv+F0SVaTpCcdx2ObgAVCmfEGsxDz9BScMDRNUhKQHiEUEfd5cu2QP4xmJPpC4m4XDE2D9N7vQ9Nxn0+nJWHbINWLqxmwoyte/WQ2vle72rFdqVOcxbmwSgbQwao/BK2DcTlZ4Kxr0Mmr6/X6giZrguPLFeBvsVhVrN/P4uPphBYEz2v7gDA/uRi9JfNYPRWCGvEtvJopFz6CW9+PGBd8/aULLvZPby3lVpvSGKKeK6KPR7wO+VsDUDEYFYx89GBRtqbBZkY6k6EQkZaeMn3nHMEPGMncWDgiV46LrGR7Jqd5rhmk5ivvFpcA0TQJLwr9vRcPc14LZ43twEYjsZFkjk9z32zEHlozz62/KYFJXmOBp82uk09rVACjzZYQH2oWktZE2QVXqLt+UeK1ht2KFU9bL068SMi3qFcoG+0b8joWd8Fy3q7rYdT2E90OsNcovjRl+dMpY07dIuXd+3Uo3/COqLcFvn1RMSP5N0UtgWEuM7aQ6EImnnCJ0QJHqjnIGkBaFZYIaoBKDp2aBmahYbOuH7vBMSMk3x4U+VwYmgaLHVqMkSWGQWC6C+yQW4Idmga/+w49Du/Ouo1ZUZF/0jkiV4ZNuHUbaMj9FooTbrKdk4skQ1cJnelGAOYajl/wpc+YbdW4vHPCB67EPpljGwk173w5nTKVQWl5O892tn/cXUeh84y9erXuH0tSwnbiCDFV7QPsEn1Isi4nSqDoe8f004A6V6cumnOjqETojNv9ip5voys2TCu64thOVQTyRF9YMx56ypjSnuTVJ0CIBmk3A7qEGz3FYsp0ya7pLxzsqma12aj0IF2Ws7P8TVJ+cavWF3l3IQ54FNZahzUFXEPO1HDfGHg80mloGHHrda5UvPlQTyi6wmAea0IZh5a34MrBK1I/m1eNEC99Sl2LZaLNkrYCdV9/TXtsxh2Y/BvwwHqjDuddMPQA3d15WK3KV4Lmw76ewInQ1bj9apkTriXOMY1mbJrhZIYkT5h8UHUwHNpPsxgMclxJaNMN7gkLNvgjHgYLmdAORfctbVQjohmxX/VW6sPtTMMztJr9uXpclKjmDzId17cA/1To/1To/wiFvp0WJQcv2g4VbdKFVllG//DlU0wZHI7E73AJ88Venl2Sgg7O8nfkmq+N3cm78e5fXkDw4uwNhK/L6Qc2St/nVxCTcomLBEOkkLk8a9RpC6b0Sb/PswvlLDVabi3rOhq5but016ziqy7BIB2UZA9agZeLRZqQmC0KIdkOLMTmWRw/6ZtdZFstrpd5EpvDUUgPPi/zdEmFzLHVTo1L8VuOymAgJFunnDBIHXPvwXFyOu0SeGFOI9X8YRlMvKu86hSEm7KTHRByOmdxpxVCA8lr1JXoHePytYGHxdqx00Z37nN+rMjzYv+aREvq4n7VHrdAYcfcbo7utsRp/Id3EOanw4mOA3b3mmT2Q35ZxTBV+p/jtlf7ubbvUFEy+jmITHdU2/NzmcyXKabkfZItr08JnKL5mOFLnKR8pao5NlHXgPAGRJ3u6tkbqaevdrvDN2q91rxLiK9o2GtrtdEKnFbcgdAJQUCDZlyLQYO05p1wjLxOGvdJBEEdQtaJixDBDlVMxDy/JFVQciggOQkuRx5bWnIH/oKeL1nbR84bnWVuXFTNdI1eB1fuw4ssL8geLgl6tanlvYZ382UJ7tE5TjKUwz/C9lhKRjIL+6jfq+iutbvlRuj0WuHlktO8d+aPAmqqwxHRcEUOaF1tZhe5/kL+vZW/0FqiXVycmlqMetsq35kV3WRjdxocqCLAQ2uF8FSmuT4ZJvuEg/nKippxxp7ApJHqx2cCNGL1c8FGHYTyb5q6IrKhWbDaNg1NhHxIf9WTGlAMFnMYZ/vXn6oJoGISWJ5N7LCVUZPytcJGV4qwbttBDhh8nnSkrTMAY0d1YCheVHvhRIwOUQd9762lI9QTnJmO1CtSEGaqCc99w9ZL0EnrCytNspLiNHVohg3MfAkryyLFEQG3Xm18tS56Xjn7gKPjSY2UZWCJRqcyCLpgGt3152wREDiVbcAjFBWif/tw5W8hdw+Sva8V71wnmCApxxNNRtDpPqRl+rz/9733wWY+6ViR0UM4zTXFaXqOoy9sFwxTSuYL2jjEaizrKpS/eq2f5nEn1zaWjL+0yen9jBY3bGk6yukBbNpqy85hBluQJBZMw3QXLWUlSQpHn5pabAxMTHe7T3e2t6X60Uf8l3+M7nhV94g5nro1ZLN9aPZtNXXZYVKH8VZru5CXo+PT/ZP34719CFpS/EhJjWSwEUJnpksUIJgvbUkxkx7XmKiaUsOLN2n6r8MEdE4ivCwJSpPzCEVqkJ4TlOY4JrF/Rul8Y9YFD6fcblC7sGf4/z/ahMGGZy8NJWt3twfnhfaPjif/NUF5gfYPj/42fv/KkKKCp/v7QbNKF0UyT8DkGGySqauKd16gZQY+77wA4XQWhyBjHyjgayhvjzaxaDbyx9fgtRfNe8PBKfIstcwI89A8Q8xBaO0jWW+1FDD/1qdfrFa6CUea9urscwQNKXSM5DmWF7tlJ9dR5OWA0+uK1q8hDmjE3T+WVGzgLJE6MlQ5Gx6PbMJst0X3sQ0AYa++U0lO4I/3iNKmjiDBNCc8FrHmqLjt2uS+Rh3l6OigV6ijn1fq9O5DZqToUugZb55JyVUff5zR7bZX4IVdWCGEsvfMM0xe2r7u+Zzm/u9u5ARPb2NneGQoYSmO8cipC5YHkVAsHFQY2FHW54wAnUbuXDBNqp+DU+646G799ttWH239sGU5+I3MuZI3+kMT3EqVKwvIByawyIs7YkJmvlKnc/QOs0BUnzldZgJWOYMEnHxgtdTNe6va67wyi+pTlWpy9cwG1k+cVODaU7eAkV+xKlE9NouYOa5kCeOppwBkrjVgIXeTAeZJdSsLeNI+GUW9ybRkYd9Ls3gos5bEEHjvaaWWastobPXcLORNgStL+l56ijem7DLwNUGbFRiZciUe/WE1mdTpIWId0SZ6v5LBz0Tw4HZ78efq2WEWFcwTilMWdCSWEOvxgG92w9cu/DdOL/IiobM5bNIOeEjS1z2zobfBbMfKxzTS9U9mzP4lzmR0xkzPEGcv6tYpHgEPfdpopAHQYLxYkCxmcWW8iX0kDzCsem5BrIC+EDZWFUvxUc7GWXxKSkK7NQFstWPAOeC5Rm6A+ngCiaohlsCooH16V61bYfuemdsSFYvHKhEuKrW0JmSAqQiHpQwEILFJElBvaBMii1XJ1ImV9SbJcB4z5tOol1mJp6GDkZyPv/6OSnIBbIBZ1aBuskgT2gUdpyoO6h8Gn6IMQuFlUZIpNHU7fjUhI7w072GJtESdQQc8Kp3BoOPfz+WggDEv5jhN/knirvzKc3vlxXwA/+01biY+lNFAKRgxRwd7TzNFTrudVW3Q+KKB1AhwInmifH6eZGzOdUoJIWMADIUIVpGPVJfp2czs4BKoQX4drZBptDmSxSgQjmpxmrwoyDS5BnGFOJT9LC4/JbK1WgbABS4wzYu9GS5s2qCgVTvj/PeoBollaknGDyYUF5STwCmD2GnZiE2PalJGeEH4IWJPGI6Ty4DTWDeLs7g65zz8+vldVhBhf7wNAIZDbLgYrxNVAyUD4SlVlX0G5gtCUcXtuA79xcNDOZ7wRWjrFtBWjhFcF79xs8ocs+KML6cZkb6SDzpjQWC6HkqymMCY3B6Krz+paqqTuDvi5fffhzqsqseYqcTjvsL5K8Pzu9XsFR2eCms4MZQtRFO/AKn8MhyjT36mPtmZblBu5OiFE5oml8z0CUqQ2olPeOaw+OyG3Vl+VSsg3qcDrhPLHuhtbjDBm0/uTofr65Uf7ToM92V19cWdfq/FnX5phS97KT2hxeC/SZF7w0HV7RX+NKneKyvuULcK9HodvJziFdru1RLkkVTOwcFhCWZAmjQeBldBYatGu4iK3iTlIi+dZIftgo4gGxvaupX9qcUY8TmSncqAeCNgHVow3jVldPRFZQhig8EZmRB6r4okopTQa5UUcXsbugZ+sJtDNNVCT5gMPdoC4Q7DKRHuuAijNC/JcQYnGprRcWwK3UsX3RSUTWC8tmOk2n9n1GaJqdkyEE7LgT2N213N8TBxSJPsi9qZrRFZJxrNkgmgxJx+ul0+tnrTuA8H+0r+2FhW/JOpdhg0mMml7lBGxalLXKCcsUZk7NVwH/PnAf4Kt686gaJq9vkmBaDmnGGToeOzZltajAL4zgAtN6OiFaDEL34uEU75Li9mtktOSsvjNZYLwRnm1ebtE61e7fBOg1RUHHdPagoKaqVBVzksVSPgZ9TOj21oYWUcBg0+SclhNgWDFgj/5cba2YLRJR9asCjJpvnadnc1rMVuD9q6hfZpSXnbD16zq+DDLmaiNwvofKCTeYGrpNRmUVN1AQcnK/kdXKuw3WMxQp4Cct2pwIMXQflwMN/sFe8ntcXT7cLjnqIYsmq/Sy5m6Kef0LPdHrpDxqv3+ZWJVAiKyj8/Qk86t6zI3/J0OScTUiQ4PVrOz0nx6vrl/Sv+kvdsTK6hLnhuPX6fX8HTjrcypXIyxVlInr4tJoTJ6i8JqPaTRIJW9Vto4n44+0Sj9xwjEzt9eEm+9BXRfbML+py/nEHHU9hFK5mTtjo66fqpYmOfXYgF+HXFF61J1r6T8WoSx57s+E5hdomI/tR3yYj+vnlDya4ntIHkEhPa6bExNu8NeUustvtjo9A3fvz7yGInBeZlfR9l9y8vtE0UmCoPs8v8C2GrxYRiKtXohozaDDGkEQb/cF2kYfMkOWU0VlPkGvpN5ZlhU09M4A7dofU0yfLYeQgqlTZlsrkVjqRaG01852f4sKh+ThYaoV8SKnY3SDE4yz9ypnKO6lkL4COOI3uK7LwQReygf9amhjL6phtrEDDHX+bFc1HmpV2PnNqtQnqZ/9ArMrO/B5jIAvO6zu1E4p5kbZEenBQ5jJRxEYE/PmLpuEYjpP8ejIv5i+ehDvnhB3QB4bxbJbrg5jN68fzpeUJFdCATzPEvh6i7LFkiADQG5C+e9xALpyhtbNBZP2RMTU/mcxInmBJIj8GCYiBGSKAXkgA7Npzx04SkcTloLS6Kv9sb6MewiCmp3HnRXsZUod3tNQTm+cs/VmD+HhaXb9YhNcxVZZweadGLu8832yGNU/5Jiimw/yinExlaXBvHa4aCl3ARrMq0p3J0xGSaZARhBNbJJbc9UIpvuLkMfkRP3x9P5CUVPAiYJQRpJyP3WwFzmq0WsKEOV9fAXRXQBaBaHxi+B6ZSJ0bwUFUILjh77gMXgUIO8EsfMGhzDuTY8YAsqxgpFujQVRRvHxwcuN5zgNeivJ50bvkYeHXN1Os8hm+a6mypzSKa7C1P/GDozVzH1fH3dRa5kbu2vmuaRDoe441OSt8j++YzlVedmSpsGFpuSMlB86lGuf1CdKP9GDrMfNZVnQP98VIYZ1ZgloqJEAERihz0sjc4wfF7MqXd5320tW1H+Okho33rl0i81PinTVSFr7M1G18Z/DLxT9X99V527p+Ck1cQtBEz25OFCBUEp4tKpPw+YnEsxiw6MoDX1l8FXj1dA9sBfYA+a3aaanSbM3QSVnNqn9BCCszHs4OXNiN67W+E05sdkwiE1d/qQHvsO4VM0qdwdZBNXE2yBuc+FZab1X+RSsiiXttMErV9QzupIOdJFn8NMdOtpgZHe73pgl611o00m2wF7UgNCMb8VZYmT2oUdwqy8G4wIdmJ0VlupLjqVeXfgig8ORjq3fnm9OCfnWH1t0WY7dloF/FpY6HWL1t/gLeFWewW1FrTUm8vrxIaVR72MFr4uCYhJIJijgfjKkJ4ELiCzzYSFILPTNhePG+L6DOUXFtFXldV5mfEp8qiDerJIf236cZB95zk46Cp1t6xvgZ36jkT4Ux3zMNgQHNCcYwpDtoElu3QbuM1IF1f/+z3Ro0ulYYFvBfs6DOXIQK0in1pmjsbHasdXG5SKH2Od+92km9L8XyZpLEKJucT+i/8WffZ7o8v9OWFGXTKKGZ7SBmvD8LV5WbRJy2am+Hpoy6U7Imfgz28wBFbP/QVD8aExD3id3mInz+PkF304eoodBi/803d3cs0htW3oJwFR8Ws+jpGtkTZKHKvvLaXa1EKmEvf1T1RnpW0MiooC23/mEUnMtjyPzu//fb6t49He79Z2gBDp0dBOqXXWP8Fh6DSDvqekzyYLM85gW4VvoN1Fi6HTt6iTl3S89dOzc9BOWMP63ojsHMV3qsyTLt6C666Otl3y3Uo36Z+W3O6D+zjOyBv5aXR4opjdrWzssJh9mZaf69v3oQ84XdLy60jdBd4zbZl7ByaK9Eit5Q3QIYW5Oxe/F1FHq529fdmr/2uuZG8677r6VdM8xvCYZ85n/pgtVpggcoLESEPG3d7eZpyXqFCHBTTUWs7fF1+gbj4v01l9lXfLLEs+YBL8LQ594Cz6Ao4/4Lu3JfV6RhkHgbwo2GiFZNYu836LgCqg9Rj5lF+k+W5lj1tnLFrMb3oOXwT1j1myVSzghfVGf7C9znLWbKoYbA0yMTPkekfs+MGjSrA3B+DwsSS3xpjVYPoNTVncpNFsyLPkn9qO4BsWsuts5bMIWbBzIKnF33QuXPYkD2R1qkMyYWddybbA34M9ucR2rEwEf/ZRTUSxgXxnsu0dkxaVT8KVN/i7KMeTGD6JpsJXYc4dehHn7cldlYOzv+w8jXn4r09ejdi5ViwqXhtHXOzeuM7WUDMo6dkSgp2x4jbJNcyhpLGAiGd/M7DwRgcXp4ThKuiYAfrWSlnmH5XzYS2T8vloGKGNnZgEq6zoLzy/CAOPrZ7ayNsDiJxWDYa2ZNbqKigEENKkBRfsKL2s8ERxMOHMJwU+QJf8ENkEoP9jGEwu6DdKP537wVnxodzPgLlSn3SdTpFnIqEY6jsDbpzO44ntxCPe5vswntzTp6ax8WrqddOqMFSs4OqpBQJrrDaMX98AWXxRpKPnnfebbuA6eBfAt4SKtUy6XTJC4gfg7OQ3Qco0aZDwpiSPK8G7J5Ya3eQi7bvVdMK1m+zqnjICIWU+WZID8RqQWa6zNTa7M49EjImt8YabLhGwrJd9DDPOrOmlQEicTEbaMN2T0ujFr1m1WkHNDlMF6xyFXitHmobHlKwJLu7rFUBiEqYhORBu5JKDHk8fx9OopakuCTa/OTeLONMn4WYRVUnBk11d261LOmNKPMVqc4EnVQPLMVTEY9eo4dP4eiVf3H2dM841sa68hDYainv3r7gNcTsKuxWHhvfctAPrZH2eRXLSeN2uengmLR2tnQdEVe2vkaCETy0csW2Z4Xr9zXVsd0IT5NNTVVeUmKthNWFMkJUtWWPey2FgPqWyiZPN8Ep3CWa4rIMLJPWPMk2xTOchhZVmd8AAq49hqva12NPnew95qFZI+ya4cK+pa3W9jXx++xeUb55RWtvawqUxnoW6HTQLMBUjmPtvL4vt5LBRg8oT5Ik2TpszqfkMnnYKpOS5/GwZQ6lQB95WuO6JaonwzZ5k3zd6SnYwmvQqseHdbmSdDnwKcxqTAnxZzJxiy4IHfqgmGyZ4hEGFiiViDRCemSlgRSvoDSUCclIm1Zr/dwA7pWNNmUaxaIBiSEABmzdBKyFF4ZmXeP6EfNAUhUyoYcc6scH5A9//jo9PlNMYHpYoRUWyvLHVc9CGeJqVoCFm+3uz8XBXBy0+CLZy8O6tIl6z5uA6hScfZDETnGohGMYSm4oZWRYk5tQE5xhbVZCQ56G9fkITTlbe7X0JmB0hfHPJfb/8hKrRlbjemgMsTA0m1nFKGuCUsMtDAgSr8Zcw2KjD71GUH34tQDWBuBmFRLPKPxTifl3UWJcWC1xsn4EP6czSKI8+tlj5UmHfRXsyqCrJL414SX2/p1546Ch/3Ck4VTCX/tqQcOP+euEFsuIvmdnhbr8z1+TLB5MIAtnBvft9n63PJ5QgPXFWTKHQSJu92ShYnBI3XgAh8yHD65N+jIqj4Klj4oqGQmWQiFeieMSrivdgeSRwcwW4OFtm+FYILOCvyGMd6E0BgJGdQHLfpHkGfwIQ0FMGx9nzXA8Z4cPjBHm5hfww+lZDeohjOQGOoBxOj+MQyU0aABR9cjefJOmh3MICe12vpAiI+mz3UGcpp0+gkyBE5ZLV3yDTCNwwqMPnn7gEgsOlPcB/O7bF4DotiKzz2XoCa1kaq0kJRBR2ef0xqSEDKXSecOelZB1xTxpJWRaOvgqWRFFIiEYPDFTwq9d4mf0wEM6zrSAGnlQCMFtHXDfFLszYPgt2cQmbs4ctTIoDnHPY0GmnsnAw4EWlK9FXk0aFauXoUubc6qI79+W0UwEwsG83oYYccK8N5QcMnzwSCbWqGTsD5Ag4zZKGQbL87IdqGEmXmTkqnpWTzXEeq8hNYCTpdgy5Phr1cRj7O1zLL8eL+nv+mmWmlqrmHs0Qh2G78nh0fGb/RfPH0KTOhTyENrWqX3+JU4KyZPKeWT0hkpyscG61fFMcRjTqNA+u8mzqW6y2foFmWKJKfK5ajfNv6K4V3cAMuFPY81pJ3dbUtZoPhAycuVCZOSKQ7Qgs5YitjfPTlIKrrMzGmzH+P7R/wK58mKw3rwAAA==
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
