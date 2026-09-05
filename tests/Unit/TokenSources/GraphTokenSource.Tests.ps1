BeforeAll {
    $repoRoot = Split-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) -Parent
    $built = Get-ChildItem -Path (Join-Path $repoRoot 'output/module/GraphKit') -Directory |
        Sort-Object Name -Descending | Select-Object -First 1
    if ($null -eq $built) {
        throw 'GraphKit is not built. Run ./build.ps1 -Tasks build first, then re-run the tests.'
    }
    $script:BuiltManifest = Join-Path $built.FullName 'GraphKit.psd1'
    Import-Module $script:BuiltManifest -Force

    if ($null -eq ('GraphKit.Tests.Task6CredentialFixture' -as [type])) {
        Add-Type -CompilerOptions '/nowarn:SYSLIB0057' -TypeDefinition @'
using System;
using System.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace GraphKit.Tests;

public static class Task6CredentialFixture
{
    public static X509Certificate2 CreateCertificate()
    {
        using RSA rsa = RSA.Create(2048);
        CertificateRequest request = new(
            "CN=GraphKit-Task6-Test",
            rsa,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        using X509Certificate2 source = request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddMinutes(-1),
            DateTimeOffset.UtcNow.AddHours(1));
#pragma warning disable SYSLIB0057
        return new X509Certificate2(
            source.Export(X509ContentType.Pkcs12),
            (string)null,
            X509KeyStorageFlags.Exportable);
#pragma warning restore SYSLIB0057
    }

    public static SecureString CreateSecret()
    {
        SecureString secret = new();
        foreach (char character in "task6-secret") secret.AppendChar(character);
        secret.MakeReadOnly();
        return secret;
    }
}

'@
    }

    if ($null -eq ('GraphKit.Tests.Task6CountingCertificate' -as [type])) {
        Add-Type -CompilerOptions '/nowarn:SYSLIB0057' -TypeDefinition @'
using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace GraphKit.Tests;

public sealed class Task6CountingCertificate : X509Certificate2, IDisposable
{
    private int _disposeCount;

    private Task6CountingCertificate(byte[] pfx) : base(pfx) { }

    public int DisposeCount => System.Threading.Volatile.Read(ref _disposeCount);

    public static Task6CountingCertificate Create()
    {
        using RSA rsa = RSA.Create(2048);
        CertificateRequest request = new(
            "CN=GraphKit-Task6-Counting",
            rsa,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        using X509Certificate2 source = request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddMinutes(-1),
            DateTimeOffset.UtcNow.AddHours(1));
        return new Task6CountingCertificate(source.Export(X509ContentType.Pkcs12));
    }

    public new void Dispose()
    {
        System.Threading.Interlocked.Increment(ref _disposeCount);
        base.Dispose();
    }

    public void DisposeWithoutCounting() => base.Dispose();
}
'@
    }

    if ($null -eq ('GraphKit.Tests.Task6CleanupProbe' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace GraphKit.Tests;

public sealed class Task6CleanupProbe : IDisposable
{
    public const string SensitiveDetail = "task6-sensitive-bridge-cleanup-detail";
    private int _disposeCount;

    public Task6CleanupProbe(bool throwOnDispose)
    {
        ThrowOnDispose = throwOnDispose;
    }

    public int DisposeCount => System.Threading.Volatile.Read(ref _disposeCount);
    public bool ThrowOnDispose { get; }

    public void Dispose()
    {
        System.Threading.Interlocked.Increment(ref _disposeCount);
        if (ThrowOnDispose)
        {
            throw new InvalidOperationException(SensitiveDetail);
        }
    }
}

public static class Task6PfxFixture
{
    public static byte[] CreatePfxBytes(string password)
    {
        using RSA rsa = RSA.Create(2048);
        CertificateRequest request = new(
            "CN=GraphKit-Task6-PFX",
            rsa,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        using X509Certificate2 source = request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddMinutes(-1),
            DateTimeOffset.UtcNow.AddHours(1));
        return source.Export(X509ContentType.Pkcs12, password);
    }

    public static string GetThumbprint(byte[] pfx, string password)
    {
#pragma warning disable SYSLIB0057
        using X509Certificate2 certificate = new(
            pfx,
            password,
            X509KeyStorageFlags.Exportable);
#pragma warning restore SYSLIB0057
        return certificate.Thumbprint;
    }
}
'@
    }

    function Test-Task6SecretDisposed {
        param([Parameter(Mandatory)] [Security.SecureString] $Secret)
        try {
            $copy = $Secret.Copy()
            $copy.Dispose()
            return $false
        }
        catch [ObjectDisposedException] {
            return $true
        }
    }

    function Test-Task6CertificateDisposed {
        param([Parameter(Mandatory)] [Security.Cryptography.X509Certificates.X509Certificate2] $Certificate)
        try {
            $null = $Certificate.GetCertHash()
            return $false
        }
        catch [ObjectDisposedException] {
            return $true
        }
        catch [Security.Cryptography.CryptographicException] {
            return $true
        }
    }

    if ($null -eq ('GraphKit.Tests.ConcurrentApplicationHarness' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.Threading;
using System.Threading.Tasks;

namespace GraphKit.Tests
{
    public sealed class ConcurrentApplicationHarness
    {
        public const string ContractMarker = "GraphKit.Task7.ConcurrentApplicationHarness/1";
        private static int _factoryCalls;
        private static int _disposed;
        private static ManualResetEventSlim _entered = new(false);
        private static ManualResetEventSlim _release = new(false);

        public static int FactoryCalls { get { return Volatile.Read(ref _factoryCalls); } }
        public static bool WaitUntilEntered(int millisecondsTimeout) => _entered.Wait(millisecondsTimeout);
        public static void Release() => _release.Set();

        public static void Reset()
        {
            Interlocked.Exchange(ref _factoryCalls, 0);
            Interlocked.Exchange(ref _disposed, 0);
            ManualResetEventSlim oldEntered = Interlocked.Exchange(
                ref _entered, new ManualResetEventSlim(false));
            ManualResetEventSlim oldRelease = Interlocked.Exchange(
                ref _release, new ManualResetEventSlim(false));
            oldEntered.Dispose();
            oldRelease.Dispose();
        }

        public static void ResetAndDispose()
        {
            if (Interlocked.Exchange(ref _disposed, 1) != 0)
                return;
            _release.Set();
            _entered.Dispose();
            _release.Dispose();
            Interlocked.Exchange(ref _factoryCalls, 0);
        }

        public static ConcurrentConfidentialApplication Create()
        {
            Interlocked.Increment(ref _factoryCalls);
            _entered.Set();
            _release.Wait();
            return new ConcurrentConfidentialApplication();
        }
    }

    public sealed class ConcurrentConfidentialApplication
    {
        public ConcurrentConfidentialBuilder AcquireTokenForClient(string[] scopes)
        {
            return new ConcurrentConfidentialBuilder();
        }
    }

    public sealed class ConcurrentConfidentialBuilder
    {
        public ConcurrentConfidentialBuilder WithForceRefresh(bool forceRefresh)
        {
            return this;
        }

        public Task<ConcurrentAuthenticationResult> ExecuteAsync(CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return Task.FromResult(new ConcurrentAuthenticationResult
            {
                AccessToken = "single-confidential-app-token",
                ExpiresOn = DateTimeOffset.UtcNow.AddHours(1)
            });
        }
    }

    public sealed class ConcurrentAuthenticationResult
    {
        public string AccessToken { get; set; }
        public DateTimeOffset ExpiresOn { get; set; }
    }
}
'@
    }

    $concurrentHarnessType = 'GraphKit.Tests.ConcurrentApplicationHarness' -as [type]
    $concurrentHarnessMarker = if ($null -ne $concurrentHarnessType) {
        $concurrentHarnessType.GetField('ContractMarker')
    }
    else {
        $null
    }
    if ($null -eq $concurrentHarnessMarker -or
        [string] $concurrentHarnessMarker.GetRawConstantValue() -cne
            'GraphKit.Task7.ConcurrentApplicationHarness/1') {
        throw (
            'The process-global ConcurrentApplicationHarness contract is stale. ' +
            'Run this test file in a fresh PowerShell process.'
        )
    }

    function New-ConcurrentHarnessSource {
        InModuleScope GraphKit {
            # ScriptBlock.Create keeps the fake itself runspace-neutral; the
            # legacy source is intentionally created in this parent runspace.
            $factory = [scriptblock]::Create(
                '[GraphKit.Tests.ConcurrentApplicationHarness]::Create()'
            )

            [ConfidentialClientTokenSource]::new(
                $factory,
                'Certificate',
                'https://graph.microsoft.com',
                'client-id',
                'generation'
            )
        }
    }

    function Get-Task7OuterFlightState {
        param([Parameter(Mandatory)] [string] $Key)

        return InModuleScope GraphKit -Parameters @{ Key = $Key } {
            param($Key)
            $flight = [GraphTokenFlight] $null
            $exists = [GraphTokenFlightRegistry]::Flights.TryGetValue($Key, [ref] $flight)
            [pscustomobject] @{
                Exists = $exists
                Flight = [object] $flight
                WaiterCount = if ($exists) {
                    [int] (Get-GraphTokenFlightWaiterCount -Flight $flight)
                }
                else {
                    -1
                }
                RegistryCount = [GraphTokenFlightRegistry]::Flights.Count
                IsCompleted = $exists -and $flight.Completion.Task.IsCompleted
            }
        }
    }

    function Wait-Task7OuterFollowerCount {
        param(
            [Parameter(Mandatory)] [string] $Key,
            [Parameter(Mandatory)] [int] $ExpectedCount
        )

        $deadline = [Environment]::TickCount64 + 5000
        $spin = [Threading.SpinWait]::new()
        while ([Environment]::TickCount64 -lt $deadline) {
            $state = Get-Task7OuterFlightState -Key $Key
            if ($state.Exists -and $state.WaiterCount -eq $ExpectedCount) {
                return $true
            }
            $spin.SpinOnce()
        }
        return $false
    }

    function Get-Task7ExactFlightWaiterCount {
        param([Parameter(Mandatory)] [object] $Flight)

        return InModuleScope GraphKit -Parameters @{ Flight = $Flight } {
            param($Flight)
            [int] (Get-GraphTokenFlightWaiterCount -Flight $Flight)
        }
    }

    function Receive-Task7BoundedJobs {
        param(
            [Parameter(Mandatory)] [object[]] $Jobs,
            [Parameter(Mandatory)] [int] $ExpectedCount
        )

        $completed = @($Jobs | Wait-Job -Timeout 10)
        if ($completed.Count -ne $ExpectedCount) {
            throw "Task 7 expected $ExpectedCount completed jobs but observed $($completed.Count)."
        }
        return @($Jobs | Receive-Job -ErrorAction Stop)
    }
}

AfterAll {
    if ($null -ne ('GraphKit.Tests.ConcurrentApplicationHarness' -as [type])) {
        [GraphKit.Tests.ConcurrentApplicationHarness]::ResetAndDispose()
    }
    Remove-Module GraphKit -Force -ErrorAction SilentlyContinue
}

Describe 'GraphTokenSource' {

    Context 'Token source implementations' {

        It 'ConfidentialClientTokenSource reports CanRefresh true and Certificate metadata' {
            InModuleScope GraphKit {
                $source = [ConfidentialClientTokenSource]::new(
                    { throw 'not invoked at construction' },
                    'Certificate',
                    'https://graph.microsoft.com',
                    '7d6e5f44-9999-8888-7777-666655554444',
                    'gen-cert'
                )
                $source.CanRefresh | Should -BeTrue
                $source.AuthMode | Should -Be 'Certificate'
                $source.Audience | Should -Be 'https://graph.microsoft.com'
                $source.CredentialGeneration | Should -Be 'gen-cert'
            }
        }

        It 'ManagedIdentityTokenSource reports CanRefresh true and ManagedIdentity metadata' {
            InModuleScope GraphKit {
                $source = [ManagedIdentityTokenSource]::new(
                    { throw 'not invoked at construction' },
                    'https://graph.microsoft.com',
                    '7d6e5f44-9999-8888-7777-666655554444',
                    'gen-mi'
                )
                $source.CanRefresh | Should -BeTrue
                $source.AuthMode | Should -Be 'ManagedIdentity'
            }
        }

        It 'ProviderTokenSource reports CanRefresh true and honors token plus expiry' {
            InModuleScope GraphKit {
                $state = @{ calls = 0 }
                $provider = {
                    $state.calls++
                    @{ Token = 'provider-token'; ExpiresOnUtc = (Get-Date).ToUniversalTime().AddHours(1) }
                }
                $source = [ProviderTokenSource]::new($provider, 'https://graph.microsoft.com', $null, 'gen-prov')

                $source.CanRefresh | Should -BeTrue
                $source.AuthMode | Should -Be 'Provider'

                $result = $source.Acquire($false, [System.Threading.CancellationToken]::None)
                $result.AccessToken | Should -Be 'provider-token'
                $result.TokenFingerprint | Should -Not -BeNullOrEmpty
                $state.calls | Should -Be 1

                # A cached token is reused without a second provider call.
                $null = $source.Acquire($false, [System.Threading.CancellationToken]::None)
                $state.calls | Should -Be 1
            }
        }

        It 'FixedBearerTokenSource reports CanRefresh false and fails immediately on forceRefresh' {
            InModuleScope GraphKit {
                $source = [FixedBearerTokenSource]::new('fixed-bearer', 'https://graph.microsoft.com', 'gen-fixed')
                $source.CanRefresh | Should -BeFalse
                $source.Acquire($false, [System.Threading.CancellationToken]::None).AccessToken | Should -Be 'fixed-bearer'

                { $source.Acquire($true, [System.Threading.CancellationToken]::None) } | Should -Throw
            }
        }

        It 'fails legacy cross-runspace acquisition quickly instead of hanging before GraphKit.Auth cutover' {
            [GraphKit.Tests.ConcurrentApplicationHarness]::Reset()
            $ready = [System.Threading.CountdownEvent]::new(2)
            $go = [System.Threading.ManualResetEventSlim]::new($false)
            [System.AppDomain]::CurrentDomain.SetData('GraphKitTest.ApplicationReady', $ready)
            [System.AppDomain]::CurrentDomain.SetData('GraphKitTest.ApplicationGo', $go)

            $source = New-ConcurrentHarnessSource
            $jobs = $null
            try {
                $jobs = @($false, $true) | ForEach-Object {
                    Start-ThreadJob -ThrottleLimit 2 -ScriptBlock {
                        param($ForceRefresh, $Manifest, $Source)
                        Import-Module $Manifest
                        $ready = [System.AppDomain]::CurrentDomain.GetData('GraphKitTest.ApplicationReady')
                        $go = [System.AppDomain]::CurrentDomain.GetData('GraphKitTest.ApplicationGo')
                        $null = $ready.Signal()
                        $null = $go.Wait()
                        try {
                            & (Get-Module GraphKit) {
                                param($TokenSource, [bool] $Refresh)
                                $null = Send-GraphHttpRequest `
                                    -Uri ([uri] 'https://graph.microsoft.com/v1.0/me') `
                                    -Method GET `
                                    -CredentialPolicy GraphBearer `
                                    -ExpectedAuthority ([uri] 'https://graph.microsoft.com') `
                                    -TokenSource $TokenSource `
                                    -ForceRefresh:$Refresh
                            } $Source $ForceRefresh
                            [pscustomobject] @{ Succeeded = $true; Message = $null }
                        }
                        catch {
                            [pscustomobject] @{ Succeeded = $false; Message = $_.Exception.Message }
                        }
                    } -ArgumentList $_, $script:BuiltManifest, $source
                }

                $ready.Wait(15000) | Should -BeTrue
                $go.Set()
                $completed = @(Wait-Job -Job $jobs -Timeout 10)
                $completed.Count | Should -Be 2 -Because 'cross-runspace containment must fail, never hang'
                $results = Receive-Task7BoundedJobs -Jobs $jobs -ExpectedCount 2

                [GraphKit.Tests.ConcurrentApplicationHarness]::FactoryCalls | Should -Be 0
                $results.Count | Should -Be 2
                @($results | Where-Object Succeeded).Count | Should -Be 0
                @($results | Where-Object { $_.Message -notmatch 'bound to the runspace.*GraphKit\.Auth' }).Count |
                    Should -Be 0
            }
            finally {
                [GraphKit.Tests.ConcurrentApplicationHarness]::Release()
                $go.Set()
                if ($null -ne $jobs) {
                    $null = @($jobs | Wait-Job -Timeout 10)
                    $jobs | Remove-Job -Force -ErrorAction SilentlyContinue
                }
                [System.AppDomain]::CurrentDomain.SetData('GraphKitTest.ApplicationReady', $null)
                [System.AppDomain]::CurrentDomain.SetData('GraphKitTest.ApplicationGo', $null)
                $ready.Dispose()
                $go.Dispose()
            }
        }

        It 'rejects a wrong-runspace sender before it can wait on an existing token flight' {
            [GraphKit.Tests.ConcurrentApplicationHarness]::Reset()
            $source = New-ConcurrentHarnessSource
            $acquisitionKey = 'wrong-runspace-flight-' + [guid]::NewGuid().ToString('N')

            $seed = InModuleScope GraphKit -Parameters @{ AcquisitionKey = $acquisitionKey } {
                param($AcquisitionKey)
                $flightKey = Get-GraphTokenFlightKey -AcquisitionKey $AcquisitionKey -ForceRefresh:$false
                $flight = [GraphTokenFlight]::new()
                [GraphTokenFlightRegistry]::Flights[$flightKey] = $flight
                [pscustomobject] @{ Key = $flightKey; Flight = $flight }
            }

            $job = $null
            try {
                $job = Start-ThreadJob -ScriptBlock {
                    param($Manifest, $Source, $AcquisitionKey)
                    Import-Module $Manifest
                    try {
                        & (Get-Module GraphKit) {
                            param($TokenSource, $Key)
                            $null = Send-GraphHttpRequest `
                                -Uri ([uri] 'https://graph.microsoft.com/v1.0/me') `
                                -Method GET `
                                -CredentialPolicy GraphBearer `
                                -ExpectedAuthority ([uri] 'https://graph.microsoft.com') `
                                -TokenSource $TokenSource `
                                -TokenAcquisitionKey $Key
                        } $Source $AcquisitionKey
                        'unexpected-success'
                    }
                    catch {
                        $_.Exception.Message
                    }
                } -ArgumentList $script:BuiltManifest, $source, $acquisitionKey

                $completed = Wait-Job -Job $job -Timeout 5
                $completed | Should -Not -BeNullOrEmpty -Because 'preflight must run before waiting on a shared flight'
                $message = $job | Receive-Job -ErrorAction Stop

                $message | Should -Match 'bound to the runspace.*GraphKit\.Auth'
                [GraphKit.Tests.ConcurrentApplicationHarness]::FactoryCalls | Should -Be 0
                $seed.Flight.Completion.Task.IsCompleted | Should -BeFalse
                $seed.Flight.PSObject.Properties['WaiterCount'] |
                    Should -Not -BeNullOrEmpty
                Get-Task7ExactFlightWaiterCount -Flight $seed.Flight | Should -Be 0

                InModuleScope GraphKit -Parameters @{ FlightKey = $seed.Key; Flight = $seed.Flight } {
                    param($FlightKey, $Flight)
                    [GraphTokenFlightRegistry]::Flights.ContainsKey($FlightKey) | Should -BeTrue
                    [object]::ReferenceEquals([GraphTokenFlightRegistry]::Flights[$FlightKey], $Flight) |
                        Should -BeTrue
                }
            }
            finally {
                [GraphKit.Tests.ConcurrentApplicationHarness]::Release()
                $null = $seed.Flight.Completion.TrySetResult($null)
                InModuleScope GraphKit -Parameters @{ FlightKey = $seed.Key; Flight = $seed.Flight } {
                    param($FlightKey, $Flight)
                    $current = [GraphTokenFlight] $null
                    if ([GraphTokenFlightRegistry]::Flights.TryGetValue($FlightKey, [ref] $current) -and
                        [object]::ReferenceEquals($current, $Flight)) {
                        $removed = [GraphTokenFlight] $null
                        $null = [GraphTokenFlightRegistry]::Flights.TryRemove($FlightKey, [ref] $removed)
                    }
                }
                if ($null -ne $job) {
                    $null = @($job | Wait-Job -Timeout 10)
                    $job | Remove-Job -Force -ErrorAction SilentlyContinue
                }
            }
        }

        It 'does not poison application initialization when the first factory call fails' {
            InModuleScope GraphKit {
                $state = @{ Calls = 0 }
                $factory = {
                    $state.Calls++
                    if ($state.Calls -eq 1) {
                        throw 'first-application-build-failed'
                    }

                    $app = [pscustomobject] @{}
                    $app | Add-Member ScriptMethod AcquireTokenForClient {
                        param($Scopes)
                        $null = $Scopes
                        $builder = [pscustomobject] @{}
                        $builder | Add-Member ScriptMethod WithForceRefresh { param($Value); $null = $Value; return $this }
                        $builder | Add-Member ScriptMethod ExecuteAsync {
                            param($Cancellation)
                            $null = $Cancellation
                            $auth = [pscustomobject] @{
                                AccessToken = 'retry-application-token'
                                ExpiresOn = [System.DateTimeOffset]::UtcNow.AddHours(1)
                            }
                            $task = [pscustomobject] @{ Auth = $auth }
                            $task | Add-Member ScriptMethod GetAwaiter {
                                $awaiter = [pscustomobject] @{ Auth = $this.Auth }
                                $awaiter | Add-Member ScriptMethod GetResult { return $this.Auth }
                                return $awaiter
                            }
                            return $task
                        }
                        return $builder
                    }
                    return $app
                }.GetNewClosure()

                $source = [ConfidentialClientTokenSource]::new(
                    $factory,
                    'Certificate',
                    'https://graph.microsoft.com',
                    'client-id',
                    'generation'
                )

                { $null = $source.Acquire($false, [System.Threading.CancellationToken]::None) } |
                    Should -Throw -ExpectedMessage '*first-application-build-failed*'
                $source.Acquire($false, [System.Threading.CancellationToken]::None).AccessToken |
                    Should -Be 'retry-application-token'
                $state.Calls | Should -Be 2
            }
        }
    }

    Context 'New-GraphTokenSource factory' {

        BeforeEach {
            Mock Get-GraphVaultCredential -ModuleName GraphKit {
                param($Credential, $VaultName, $AuthMethod)
                $null = $VaultName
                switch ($AuthMethod) {
                    Certificate {
                        [pscustomobject]@{ Material = [GraphKit.Tests.Task6CredentialFixture]::CreateCertificate(); OwnsMaterial = $true; CredentialGeneration = 'cert-generation' }
                    }
                    ClientSecret {
                        [pscustomobject]@{ Material = [GraphKit.Tests.Task6CredentialFixture]::CreateSecret(); OwnsMaterial = $true; CredentialGeneration = 'secret-generation' }
                    }
                    BearerToken {
                        [pscustomobject]@{ Material = 'fixed-value'; OwnsMaterial = $false; CredentialGeneration = 'bearer-generation' }
                    }
                    ManagedIdentity {
                        [pscustomobject]@{ Material = $null; ManagedIdentityClientId = $Credential.ClientId; OwnsMaterial = $false; CredentialGeneration = 'mi-generation' }
                    }
                }
            }
        }

        It 'builds the correct source per AuthMethod with the right CanRefresh' {
            InModuleScope GraphKit {
                $cloud = @{ GraphBaseUri = 'https://graph.microsoft.com'; Authority = 'https://login.microsoftonline.com'; Resource = 'https://graph.microsoft.com' }

                $secret = New-GraphTokenSource -Profile @{
                    AuthMethod = 'ClientSecret'; ClientId = '7d6e5f44-9999-8888-7777-666655554444'
                    Credential = @{ VaultName = 'v'; SecretName = 's' }
                } -Cloud $cloud -MsalFactory { throw 'not invoked' }
                $secret.CanRefresh | Should -BeTrue
                $secret.AuthMode | Should -Be 'ClientSecret'

                $cert = New-GraphTokenSource -Profile @{
                    AuthMethod = 'Certificate'; ClientId = '7d6e5f44-9999-8888-7777-666655554444'
                    Credential = @{ VaultName = 'v'; CertificateName = 'cert'; Version = '1' }
                } -Cloud $cloud -MsalFactory { throw 'not invoked' }
                $cert.CanRefresh | Should -BeTrue
                $cert.AuthMode | Should -Be 'Certificate'

                $mi = New-GraphTokenSource -Profile @{ AuthMethod = 'ManagedIdentity'; Credential = @{} } -Cloud $cloud -MsalFactory { throw 'not invoked' }
                $mi.CanRefresh | Should -BeTrue
                $mi.AuthMode | Should -Be 'ManagedIdentity'

                $bearer = New-GraphTokenSource -Profile @{
                    AuthMethod = 'BearerToken'; Credential = @{ Token = 'fixed-value' }
                } -Cloud $cloud -MsalFactory { throw 'not invoked' }
                $bearer.CanRefresh | Should -BeFalse
                $bearer.AuthMode | Should -Be 'BearerToken'
            }
        }

        It 'routes every no-factory built-in through the exact compiled contract' -ForEach @(
            @{ Mode = 'Certificate'; ClientId = '7d6e5f44-9999-8888-7777-666655554444'; Credential = @{ VaultName = 'v'; CertificateName = 'cert'; Version = 'v1' } }
            @{ Mode = 'ClientSecret'; ClientId = '7d6e5f44-9999-8888-7777-666655554444'; Credential = @{ VaultName = 'v'; SecretName = 'secret'; Version = 'v1' } }
            @{ Mode = 'ManagedIdentity'; ClientId = $null; Credential = @{} }
            @{ Mode = 'ManagedIdentity'; ClientId = $null; Credential = @{ ClientId = '11111111-2222-3333-4444-555555555555' } }
            @{ Mode = 'BearerToken'; ClientId = $null; Credential = @{ VaultName = 'v'; SecretName = 'bearer'; Version = 'v1' } }
        ) {
            $source = InModuleScope GraphKit -Parameters @{
                Mode = $Mode; ClientId = $ClientId; Credential = $Credential
            } {
                param($Mode, $ClientId, $Credential)
                New-GraphTokenSource -Profile @{
                    TenantId = '3a4b5c6d-1111-2222-3333-444455556666'
                    ClientId = $ClientId
                    AuthMethod = $Mode
                    Environment = 'Global'
                    Credential = $Credential
                } -Cloud @{
                    Name = 'Global'
                    Authority = [uri]'https://login.microsoftonline.com'
                    Resource = [uri]'https://graph.microsoft.com'
                }
            }

            $source -is [GraphKit.Auth.IGraphTokenSource] | Should -BeTrue
            $source.AuthMode | Should -BeExactly $Mode
            $source.ExpiresOn | Should -Be ([datetimeoffset]::MinValue) -Because 'construction must perform zero acquisition'
        }

    }

    Context 'Unsupported persisted credential versions' {

        It 'checks unsupported PFX version metadata before any PFX bytes or vault are touched' {
            Mock Get-GraphPfxSnapshot -ModuleName GraphKit { throw 'PFX_BYTES_WERE_TOUCHED' }
            Mock Assert-GraphVaultRegistered -ModuleName GraphKit { throw 'VAULT_WAS_TOUCHED' }

            {
                InModuleScope GraphKit {
                    New-GraphTokenSource -Profile @{
                        TenantId = '3a4b5c6d-1111-2222-3333-444455556666'
                        ClientId = '7d6e5f44-9999-8888-7777-666655554444'
                        AuthMethod = 'Certificate'; Environment = 'Global'
                        Credential = @{
                            PfxPath = 'must-not-open.pfx'
                            Password = @{ VaultName = 'v'; SecretName = 'password'; Version = 'unsupported-v1' }
                        }
                    } -Cloud @{
                        Name = 'Global'; Authority = [uri]'https://login.microsoftonline.com'; Resource = [uri]'https://graph.microsoft.com'
                    }
                }
            } | Should -Throw -ExpectedMessage '*does not support per-secret versions*'
            Should -Invoke Get-GraphPfxSnapshot -ModuleName GraphKit -Times 0 -Exactly
            Should -Invoke Assert-GraphVaultRegistered -ModuleName GraphKit -Times 0 -Exactly
        }
    }

    Context 'Compiled persisted PFX bridge' {

        It 'reads one hashed snapshot and imports the exact same PFX bytes' {
            $passwordText = 'task6-pfx-password'
            $snapshotBytes = [GraphKit.Tests.Task6PfxFixture]::CreatePfxBytes($passwordText)
            $expectedThumbprint = [GraphKit.Tests.Task6PfxFixture]::GetThumbprint(
                $snapshotBytes,
                $passwordText)
            $expectedSha = [Convert]::ToHexString(
                [Security.Cryptography.SHA256]::HashData($snapshotBytes)).ToLowerInvariant()
            $script:Task6CompiledPfxSnapshot = [byte[]]$snapshotBytes.Clone()

            Mock Get-GraphPfxSnapshot -ModuleName GraphKit {
                [pscustomobject]@{
                    Path = '/task6/credential.pfx'
                    Bytes = $script:Task6CompiledPfxSnapshot
                    Sha256 = $expectedSha
                }
            }
            Mock Resolve-GraphVaultPassword -ModuleName GraphKit {
                $secret = [Security.SecureString]::new()
                foreach ($character in $passwordText.ToCharArray()) {
                    $secret.AppendChar($character)
                }
                $secret.MakeReadOnly()
                $secret
            }

            $source = $null
            try {
                $source = InModuleScope GraphKit {
                    New-GraphTokenSource -Profile @{
                        TenantId = '3a4b5c6d-1111-2222-3333-444455556666'
                        ClientId = '7d6e5f44-9999-8888-7777-666655554444'
                        AuthMethod = 'Certificate'; Environment = 'Global'
                        Credential = @{
                            PfxPath = 'must-not-be-opened-directly.pfx'
                            Password = @{ VaultName = 'v'; SecretName = 'password' }
                        }
                    } -Cloud @{
                        Name = 'Global'
                        Authority = [uri]'https://login.microsoftonline.com'
                        Resource = [uri]'https://graph.microsoft.com'
                    }
                }

                $inner = [GraphKit.Auth.IGraphTokenSource].Assembly.GetType(
                    'GraphKit.Auth.GraphTokenSourceProxy', $true, $false
                ).GetField('_inner', [Reflection.BindingFlags]'Instance,NonPublic').GetValue($source)
                $credential = $inner.GetType().GetField(
                    '_credentialReference', [Reflection.BindingFlags]'Instance,NonPublic').GetValue($inner)

                $credential.GetType().FullName | Should -BeExactly 'GraphKit.Auth.CertificateCredential'
                $credential.Certificate.Thumbprint | Should -BeExactly $expectedThumbprint
                $source.CredentialGeneration | Should -Match ([regex]::Escape("sha256:$expectedSha"))
                Should -Invoke Get-GraphPfxSnapshot -ModuleName GraphKit -Times 1 -Exactly
                @($script:Task6CompiledPfxSnapshot | Where-Object { $_ -ne 0 }).Count |
                    Should -Be 0 -Because 'the exact imported snapshot is zeroed after the transfer'
            }
            finally {
                if ($null -ne $source) { $source.Dispose() }
            }
        }
    }

    Context 'Compiled bridge credential ownership failures' {

        It 'cleans an owned client secret exactly once when request construction fails before host entry' {
            $script:Task6RequestFailureSecret = [GraphKit.Tests.Task6CredentialFixture]::CreateSecret()
            Mock Get-GraphVaultCredential -ModuleName GraphKit {
                [pscustomobject]@{
                    Material = $script:Task6RequestFailureSecret
                    OwnsMaterial = $true
                    CredentialGeneration = 'task6-request-failure-secret'
                }
            }

            {
                InModuleScope GraphKit {
                    New-GraphAuthTokenSource -Profile @{
                        TenantId = 'not-a-guid'
                        ClientId = '7d6e5f44-9999-8888-7777-666655554444'
                        AuthMethod = 'ClientSecret'; Environment = 'Global'
                        Credential = @{ VaultName = 'v'; SecretName = 's'; Version = 'v1' }
                    } -Cloud @{
                        Name = 'Global'; Authority = [uri]'https://login.microsoftonline.com'; Resource = [uri]'https://graph.microsoft.com'
                    }
                }
            } | Should -Throw

            Test-Task6SecretDisposed -Secret $script:Task6RequestFailureSecret | Should -BeTrue
            Should -Invoke Get-GraphVaultCredential -ModuleName GraphKit -Times 1 -Exactly
        }

        It 'cleans an owned certificate exactly once when request construction fails before host entry' {
            $script:Task6RequestFailureCertificate = [GraphKit.Tests.Task6CountingCertificate]::Create()
            Mock Get-GraphVaultCredential -ModuleName GraphKit {
                [pscustomobject]@{
                    Material = $script:Task6RequestFailureCertificate
                    OwnsMaterial = $true
                    CredentialGeneration = 'task6-request-failure-certificate'
                }
            }

            {
                InModuleScope GraphKit {
                    New-GraphAuthTokenSource -Profile @{
                        TenantId = 'not-a-guid'
                        ClientId = '7d6e5f44-9999-8888-7777-666655554444'
                        AuthMethod = 'Certificate'; Environment = 'Global'
                        Credential = @{ VaultName = 'v'; CertificateName = 'c'; Version = 'v1' }
                    } -Cloud @{
                        Name = 'Global'; Authority = [uri]'https://login.microsoftonline.com'; Resource = [uri]'https://graph.microsoft.com'
                    }
                }
            } | Should -Throw

            Test-Task6CertificateDisposed -Certificate $script:Task6RequestFailureCertificate | Should -BeTrue
            $script:Task6RequestFailureCertificate.DisposeCount | Should -Be 1
            Should -Invoke Get-GraphVaultCredential -ModuleName GraphKit -Times 1 -Exactly
        }

        It 'sanitizes a cleanup failure after credential construction is rejected before host entry' {
            $script:Task6BridgeCleanupProbe = [GraphKit.Tests.Task6CleanupProbe]::new($true)
            Mock Get-GraphVaultCredential -ModuleName GraphKit {
                [pscustomobject]@{
                    Material = $script:Task6BridgeCleanupProbe
                    OwnsMaterial = $true
                    CredentialGeneration = 'task6-cleanup-failure'
                }
            }

            $failure = $null
            try {
                InModuleScope GraphKit {
                    New-GraphAuthTokenSource -Profile @{
                        TenantId = '3a4b5c6d-1111-2222-3333-444455556666'
                        ClientId = '7d6e5f44-9999-8888-7777-666655554444'
                        AuthMethod = 'ClientSecret'; Environment = 'Global'
                        Credential = @{ VaultName = 'v'; SecretName = 's'; Version = 'v1' }
                    } -Cloud @{
                        Name = 'Global'; Authority = [uri]'https://login.microsoftonline.com'; Resource = [uri]'https://graph.microsoft.com'
                    }
                }
            }
            catch {
                $failure = $_.Exception
            }

            $failure | Should -Not -BeNullOrEmpty
            $failure.GetType().FullName | Should -BeExactly 'GraphKit.Auth.GraphAuthException'
            $failure.Code | Should -BeExactly 'credential_material_cleanup_failed'
            $failure.Category | Should -BeExactly 'CredentialOwnership'
            $failure.Message | Should -BeExactly 'GraphKit.Auth could not clean up credential material after request construction failed before host entry.'
            $failure.ToString() | Should -Not -Match ([regex]::Escape([GraphKit.Tests.Task6CleanupProbe]::SensitiveDetail))
            $failure.InnerException | Should -BeNullOrEmpty
            $failure.Data.Count | Should -Be 0
            $script:Task6BridgeCleanupProbe.DisposeCount | Should -Be 1
        }

        It 'disposes an owned client secret exactly once when lifecycle registration refuses the returned source' {
            $script:Task6RegistrationSecret = [GraphKit.Tests.Task6CredentialFixture]::CreateSecret()
            Mock Get-GraphVaultCredential -ModuleName GraphKit {
                [pscustomobject]@{
                    Material = $script:Task6RegistrationSecret
                    OwnsMaterial = $true
                    CredentialGeneration = 'task6-registration-secret'
                }
            }
            Mock Register-GraphModuleOwnedResource -ModuleName GraphKit { throw 'task6-registration-refused' }

            {
                InModuleScope GraphKit {
                    New-GraphAuthTokenSource -Profile @{
                        TenantId = '3a4b5c6d-1111-2222-3333-444455556666'
                        ClientId = '7d6e5f44-9999-8888-7777-666655554444'
                        AuthMethod = 'ClientSecret'; Environment = 'Global'
                        Credential = @{ VaultName = 'v'; SecretName = 's'; Version = 'v1' }
                    } -Cloud @{
                        Name = 'Global'; Authority = [uri]'https://login.microsoftonline.com'; Resource = [uri]'https://graph.microsoft.com'
                    }
                }
            } | Should -Throw -ExpectedMessage '*task6-registration-refused*'

            Test-Task6SecretDisposed -Secret $script:Task6RegistrationSecret | Should -BeTrue
            Should -Invoke Register-GraphModuleOwnedResource -ModuleName GraphKit -Times 1 -Exactly
        }

        It 'disposes an owned certificate exactly once when lifecycle registration refuses the returned source' {
            $script:Task6RegistrationCertificate = [GraphKit.Tests.Task6CountingCertificate]::Create()
            Mock Get-GraphVaultCredential -ModuleName GraphKit {
                [pscustomobject]@{
                    Material = $script:Task6RegistrationCertificate
                    OwnsMaterial = $true
                    CredentialGeneration = 'task6-registration-certificate'
                }
            }
            Mock Register-GraphModuleOwnedResource -ModuleName GraphKit { throw 'task6-registration-refused' }

            {
                InModuleScope GraphKit {
                    New-GraphAuthTokenSource -Profile @{
                        TenantId = '3a4b5c6d-1111-2222-3333-444455556666'
                        ClientId = '7d6e5f44-9999-8888-7777-666655554444'
                        AuthMethod = 'Certificate'; Environment = 'Global'
                        Credential = @{ VaultName = 'v'; CertificateName = 'c'; Version = 'v1' }
                    } -Cloud @{
                        Name = 'Global'; Authority = [uri]'https://login.microsoftonline.com'; Resource = [uri]'https://graph.microsoft.com'
                    }
                }
            } | Should -Throw -ExpectedMessage '*task6-registration-refused*'

            Test-Task6CertificateDisposed -Certificate $script:Task6RegistrationCertificate | Should -BeTrue
            $script:Task6RegistrationCertificate.DisposeCount | Should -Be 1
            Should -Invoke Register-GraphModuleOwnedResource -ModuleName GraphKit -Times 1 -Exactly
        }

        It 'never disposes an injected caller-owned certificate when lifecycle registration refuses the returned source' {
            $certificate = [GraphKit.Tests.Task6CredentialFixture]::CreateCertificate()
            Mock Get-GraphVaultCredential -ModuleName GraphKit { throw 'vault resolution must not run for an injected certificate' }
            Mock Register-GraphModuleOwnedResource -ModuleName GraphKit { throw 'task6-registration-refused' }

            try {
                {
                    InModuleScope GraphKit -Parameters @{ InjectedCertificate = $certificate } {
                        param($InjectedCertificate)
                        New-GraphAuthTokenSource -Profile @{
                            TenantId = '3a4b5c6d-1111-2222-3333-444455556666'
                            ClientId = '7d6e5f44-9999-8888-7777-666655554444'
                            AuthMethod = 'Certificate'; Environment = 'Global'
                            Credential = @{}
                        } -Cloud @{
                            Name = 'Global'; Authority = [uri]'https://login.microsoftonline.com'; Resource = [uri]'https://graph.microsoft.com'
                        } -Certificate $InjectedCertificate
                    }
                } | Should -Throw -ExpectedMessage '*task6-registration-refused*'

                Test-Task6CertificateDisposed -Certificate $certificate | Should -BeFalse
                Should -Invoke Get-GraphVaultCredential -ModuleName GraphKit -Times 0 -Exactly
                Should -Invoke Register-GraphModuleOwnedResource -ModuleName GraphKit -Times 1 -Exactly
            }
            finally {
                $certificate.Dispose()
            }
        }
    }

    Context 'Assert-GraphTokenSource duck contract' {

        It 'accepts a source that satisfies the contract' {
            InModuleScope GraphKit {
                $source = [ProviderTokenSource]::new({ @{ Token = 't'; ExpiresOnUtc = (Get-Date).AddHours(1) } }, 'https://graph.microsoft.com', $null, 'g')
                { Assert-GraphTokenSource -Source $source } | Should -Not -Throw
            }
        }

        It 'names every missing member on a contract violation' {
            InModuleScope GraphKit {
                { Assert-GraphTokenSource -Source ([pscustomobject]@{ CanRefresh = $true }) } |
                    Should -Throw -ExpectedMessage '*AuthMode*'
            }
        }
    }

    Context 'Single-flight acquisition' {

        It 'runs the leader acquisition once and cleans up the flight' {
            InModuleScope GraphKit {
                $state = @{ calls = 0 }
                $result = Invoke-GraphTokenSingleFlight -Key 'leader-key' -AcquireScript { $state.calls++; 'leader-result' }
                $result | Should -Be 'leader-result'
                $state.calls | Should -Be 1
                [GraphTokenFlightRegistry]::Flights.ContainsKey('leader-key') | Should -BeFalse
            }
        }

        It 'returns the in-flight result to a concurrent caller without a second acquisition' {
            InModuleScope GraphKit {
                $flight = [GraphTokenFlight]::new()
                $null = $flight.Completion.TrySetResult('already-acquired')
                [GraphTokenFlightRegistry]::Flights['seeded-key'] = $flight

                try {
                    $state = @{ calls = 0 }
                    $result = Invoke-GraphTokenSingleFlight -Key 'seeded-key' -AcquireScript { $state.calls++; 'should-not-run' }
                    $result | Should -Be 'already-acquired'
                    $state.calls | Should -Be 0
                }
                finally {
                    $removed = [GraphTokenFlight]$null
                    $null = [GraphTokenFlightRegistry]::Flights.TryRemove('seeded-key', [ref]$removed)
                }
            }
        }

        It 'lets a cancelled waiter leave without cancelling or removing the shared flight' {
            InModuleScope GraphKit {
                $key = 'cancelled-waiter-key'
                $flight = [GraphTokenFlight]::new()
                [GraphTokenFlightRegistry]::Flights[$key] = $flight
                $cts = [System.Threading.CancellationTokenSource]::new()
                $cts.Cancel()

                try {
                    $state = @{ calls = 0 }
                    $message = try {
                        $null = Invoke-GraphTokenSingleFlight -Key $key -CancellationToken $cts.Token `
                            -AcquireScript { $state.calls++; 'should-not-run' }
                        ''
                    }
                    catch {
                        $_.Exception.Message
                    }

                    $message | Should -BeLike '*canceled*'
                    $state.calls | Should -Be 0
                    [GraphTokenFlightRegistry]::Flights.ContainsKey($key) | Should -BeTrue
                    Get-GraphTokenFlightWaiterCount -Flight $flight | Should -Be 0
                }
                finally {
                    if ($null -ne $flight.PSObject.Properties['Completion']) {
                        $null = $flight.Completion.TrySetResult('cleanup')
                    }
                    elseif ($null -ne $flight.PSObject.Properties['Done']) {
                        $flight.Done.Set()
                    }
                    $removed = [GraphTokenFlight]$null
                    $null = [GraphTokenFlightRegistry]::Flights.TryRemove($key, [ref]$removed)
                    $cts.Dispose()
                }
            }
        }

        It 'does not make a live waiter inherit cancellation from the former leader' {
            InModuleScope GraphKit {
                $key = 'cancelled-leader-key'
                $flight = [GraphTokenFlight]::new()
                $null = $flight.Completion.TrySetException(
                    [System.OperationCanceledException]::new('former leader cancelled')
                )
                $flight.LeaderCancellationRequested = $true
                [GraphTokenFlightRegistry]::Flights[$key] = $flight

                try {
                    $state = @{ calls = 0 }
                    $result = Invoke-GraphTokenSingleFlight -Key $key `
                        -CancellationToken ([System.Threading.CancellationToken]::None) `
                        -AcquireScript { $state.calls++; 'replacement-result' }

                    $result | Should -Be 'replacement-result'
                    $state.calls | Should -Be 1
                }
                finally {
                    $removed = [GraphTokenFlight]$null
                    $null = [GraphTokenFlightRegistry]::Flights.TryRemove($key, [ref]$removed)
                }
            }
        }

        It 'fans out an unsignalled provider cancellation exception without re-electing' {
            InModuleScope GraphKit {
                $key = 'provider-oce-key'
                $flight = [GraphTokenFlight]::new()
                $null = $flight.Completion.TrySetException(
                    [System.OperationCanceledException]::new('provider timed out internally')
                )
                [GraphTokenFlightRegistry]::Flights[$key] = $flight

                try {
                    $state = @{ calls = 0 }
                    {
                        $null = Invoke-GraphTokenSingleFlight -Key $key `
                            -CancellationToken ([System.Threading.CancellationToken]::None) `
                            -AcquireScript { $state.calls++; 'must-not-re-elect' }
                    } | Should -Throw -ExpectedMessage '*provider timed out internally*'

                    $state.calls | Should -Be 0
                }
                finally {
                    $removed = [GraphTokenFlight]$null
                    $null = [GraphTokenFlightRegistry]::Flights.TryRemove($key, [ref]$removed)
                }
            }
        }

        It 'adopts a shared forced-refresh result into the follower source cache' {
            InModuleScope GraphKit {
                $key = 'forced-refresh-cache-adoption-key'
                $leaderState = @{ calls = 0 }
                $followerState = @{ calls = 0 }
                $expiry = [System.DateTimeOffset]::UtcNow.AddHours(1)

                $leader = [ProviderTokenSource]::new({
                    $leaderState.calls++
                    $token = if ($leaderState.calls -eq 1) { 'leader-old-token' } else { 'shared-fresh-token' }
                    @{ Token = $token; ExpiresOnUtc = $expiry }
                }.GetNewClosure(), 'https://graph.microsoft.com', 'shared-client', 'shared-generation')
                $follower = [ProviderTokenSource]::new({
                    $followerState.calls++
                    @{ Token = 'follower-rejected-token'; ExpiresOnUtc = $expiry }
                }.GetNewClosure(), 'https://graph.microsoft.com', 'shared-client', 'shared-generation')

                $delayedOrdinary = $leader.Acquire($false, [System.Threading.CancellationToken]::None)
                $null = $follower.Acquire($false, [System.Threading.CancellationToken]::None)
                $fresh = $leader.Acquire($true, [System.Threading.CancellationToken]::None)

                $flightKey = Get-GraphTokenFlightKey -AcquisitionKey $key -ForceRefresh:$true
                $flight = [GraphTokenFlight]::new()
                $null = $flight.Completion.TrySetResult($fresh)
                [GraphTokenFlightRegistry]::Flights[$flightKey] = $flight

                try {
                    {
                        $null = Send-GraphHttpRequest `
                            -Uri ([uri] 'https://graph.microsoft.com/v1.0/mutation') `
                            -Method POST -Body @{} -CredentialPolicy GraphBearer `
                            -ExpectedAuthority ([uri] 'https://graph.microsoft.com') `
                            -TokenSource $follower -TokenAcquisitionKey $key -ForceRefresh:$true `
                            -TargetTenantId ([guid] '00000000-0000-0000-0000-000000000001') `
                            -VerifyTenantBinding -TenantBindingProver {
                                param($Context, $TokenResult, $CancellationToken)
                                throw 'cache-adoption-proof-sentinel'
                            }
                    } | Should -Throw -ExpectedMessage '*cache-adoption-proof-sentinel*'

                    $afterSharedRefresh = $follower.Acquire($false, [System.Threading.CancellationToken]::None)
                    $afterSharedRefresh.AccessToken | Should -Be 'shared-fresh-token'
                    $followerState.calls | Should -Be 1
                }
                finally {
                    $removed = [GraphTokenFlight]$null
                    $null = [GraphTokenFlightRegistry]::Flights.TryRemove($flightKey, [ref]$removed)
                }

                # Reproduce the dangerous ordering deterministically: the forced
                # result has already been adopted, then an ordinary flight from
                # the same clock tick, with a later expiry, reaches sender adoption
                # last. Forced-refresh precedence is the only reason it cannot win.
                $delayedOrdinary.ReceivedOnUtc = $fresh.ReceivedOnUtc
                $delayedOrdinary.ExpiresOnUtc = $fresh.ExpiresOnUtc.AddMinutes(30)
                $ordinaryFlightKey = Get-GraphTokenFlightKey -AcquisitionKey $key -ForceRefresh:$false
                $ordinaryFlight = [GraphTokenFlight]::new()
                $null = $ordinaryFlight.Completion.TrySetResult($delayedOrdinary)
                [GraphTokenFlightRegistry]::Flights[$ordinaryFlightKey] = $ordinaryFlight

                try {
                    {
                        $null = Send-GraphHttpRequest `
                            -Uri ([uri] 'https://graph.microsoft.com/v1.0/mutation') `
                            -Method POST -Body @{} -CredentialPolicy GraphBearer `
                            -ExpectedAuthority ([uri] 'https://graph.microsoft.com') `
                            -TokenSource $follower -TokenAcquisitionKey $key -ForceRefresh:$false `
                            -TargetTenantId ([guid] '00000000-0000-0000-0000-000000000001') `
                            -VerifyTenantBinding -TenantBindingProver {
                                param($Context, $TokenResult, $CancellationToken)
                                throw 'late-ordinary-proof-sentinel'
                            }
                    } | Should -Throw -ExpectedMessage '*late-ordinary-proof-sentinel*'
                }
                finally {
                    $removed = [GraphTokenFlight]$null
                    $null = [GraphTokenFlightRegistry]::Flights.TryRemove($ordinaryFlightKey, [ref]$removed)
                }

                $afterSharedRefresh = $follower.Acquire($false, [System.Threading.CancellationToken]::None)
                $afterSharedRefresh.AccessToken | Should -Be 'shared-fresh-token'
                $followerState.calls | Should -Be 1
            }
        }

        It 'collapses N concurrent same-tuple acquires to a single acquisition' {
            $key = 'tuple-key'
            $calls = [System.Collections.Concurrent.ConcurrentQueue[string]]::new()
            $ready = [System.Threading.CountdownEvent]::new(8)
            $go = [System.Threading.ManualResetEventSlim]::new($false)
            $entered = [System.Threading.ManualResetEventSlim]::new($false)
            $release = [System.Threading.ManualResetEventSlim]::new($false)
            [System.AppDomain]::CurrentDomain.SetData('GraphKitTest.OrdinaryCalls', $calls)
            [System.AppDomain]::CurrentDomain.SetData('GraphKitTest.Ready', $ready)
            [System.AppDomain]::CurrentDomain.SetData('GraphKitTest.Go', $go)
            [System.AppDomain]::CurrentDomain.SetData('GraphKitTest.OrdinaryEntered', $entered)
            [System.AppDomain]::CurrentDomain.SetData('GraphKitTest.OrdinaryRelease', $release)

            $jobs = $null
            try {
                $jobs = 1..8 | ForEach-Object {
                    Start-ThreadJob -ThrottleLimit 8 -ScriptBlock {
                        param($key, $manifest)
                        Import-Module $manifest
                        $ready = [System.AppDomain]::CurrentDomain.GetData('GraphKitTest.Ready')
                        $go = [System.AppDomain]::CurrentDomain.GetData('GraphKitTest.Go')
                        $null = $ready.Signal()
                        $null = $go.Wait()
                        & (Get-Module GraphKit) {
                            param($FlightKey)
                            Invoke-GraphTokenSingleFlight -Key $FlightKey -AcquireScript {
                                $calls = [System.AppDomain]::CurrentDomain.GetData('GraphKitTest.OrdinaryCalls')
                                $entered = [System.AppDomain]::CurrentDomain.GetData('GraphKitTest.OrdinaryEntered')
                                $release = [System.AppDomain]::CurrentDomain.GetData('GraphKitTest.OrdinaryRelease')
                                $calls.Enqueue('acquire')
                                $entered.Set()
                                $null = $release.Wait()
                                [pscustomobject]@{ Token = [guid]::NewGuid().ToString() }
                            }
                        } $key
                    } -ArgumentList $key, $script:BuiltManifest
                }

                $ready.Wait(15000) | Should -BeTrue
                $go.Set()
                $entered.Wait(5000) | Should -BeTrue
                $followerObserved = Wait-Task7OuterFollowerCount -Key $key -ExpectedCount 7
                $beforeRelease = Get-Task7OuterFlightState -Key $key
                $release.Set()
                $followerObserved | Should -BeTrue
                $beforeRelease.Exists | Should -BeTrue
                $beforeRelease.WaiterCount | Should -Be 7

                $results = Receive-Task7BoundedJobs -Jobs $jobs -ExpectedCount 8
                $calls.Count | Should -Be 1
                @($results.Token | Sort-Object -Unique).Count | Should -Be 1
                Get-Task7ExactFlightWaiterCount -Flight $beforeRelease.Flight | Should -Be 0
                (Get-Task7OuterFlightState -Key $key).Exists | Should -BeFalse
            }
            finally {
                $release.Set()
                $go.Set()
                if ($null -ne $jobs) {
                    $null = @($jobs | Wait-Job -Timeout 10)
                }
                [System.AppDomain]::CurrentDomain.SetData('GraphKitTest.Ready', $null)
                [System.AppDomain]::CurrentDomain.SetData('GraphKitTest.Go', $null)
                [System.AppDomain]::CurrentDomain.SetData('GraphKitTest.OrdinaryCalls', $null)
                [System.AppDomain]::CurrentDomain.SetData('GraphKitTest.OrdinaryEntered', $null)
                [System.AppDomain]::CurrentDomain.SetData('GraphKitTest.OrdinaryRelease', $null)
                if ($null -ne $jobs) {
                    $jobs | Remove-Job -Force -ErrorAction SilentlyContinue
                }
                $ready.Dispose()
                $go.Dispose()
                $entered.Dispose()
                $release.Dispose()
            }
        }

        It 'surfaces an acquisition failure to every concurrent waiter' {
            $key = 'failure-key'
            $calls = [System.Collections.Concurrent.ConcurrentQueue[string]]::new()
            $ready = [System.Threading.CountdownEvent]::new(8)
            $go = [System.Threading.ManualResetEventSlim]::new($false)
            $entered = [System.Threading.ManualResetEventSlim]::new($false)
            $release = [System.Threading.ManualResetEventSlim]::new($false)
            [System.AppDomain]::CurrentDomain.SetData('GraphKitTest.FailureCalls', $calls)
            [System.AppDomain]::CurrentDomain.SetData('GraphKitTest.FailureReady', $ready)
            [System.AppDomain]::CurrentDomain.SetData('GraphKitTest.FailureGo', $go)
            [System.AppDomain]::CurrentDomain.SetData('GraphKitTest.FailureEntered', $entered)
            [System.AppDomain]::CurrentDomain.SetData('GraphKitTest.FailureRelease', $release)

            $jobs = $null
            try {
                $jobs = 1..8 | ForEach-Object {
                    Start-ThreadJob -ThrottleLimit 8 -ScriptBlock {
                        param($key, $manifest)
                        Import-Module $manifest
                        $ready = [System.AppDomain]::CurrentDomain.GetData('GraphKitTest.FailureReady')
                        $go = [System.AppDomain]::CurrentDomain.GetData('GraphKitTest.FailureGo')
                        $null = $ready.Signal()
                        $null = $go.Wait()
                        try {
                            $null = & (Get-Module GraphKit) {
                                param($FlightKey)
                                Invoke-GraphTokenSingleFlight -Key $FlightKey -AcquireScript {
                                    $calls = [System.AppDomain]::CurrentDomain.GetData('GraphKitTest.FailureCalls')
                                    $entered = [System.AppDomain]::CurrentDomain.GetData('GraphKitTest.FailureEntered')
                                    $release = [System.AppDomain]::CurrentDomain.GetData('GraphKitTest.FailureRelease')
                                    $calls.Enqueue('acquire')
                                    $entered.Set()
                                    $null = $release.Wait()
                                    throw 'acquisition failed'
                                }
                            } $key
                            'ok'
                        }
                        catch {
                            'err'
                        }
                    } -ArgumentList $key, $script:BuiltManifest
                }

                $ready.Wait(15000) | Should -BeTrue
                $go.Set()
                $entered.Wait(5000) | Should -BeTrue
                $followerObserved = Wait-Task7OuterFollowerCount -Key $key -ExpectedCount 7
                $beforeRelease = Get-Task7OuterFlightState -Key $key
                $release.Set()
                $followerObserved | Should -BeTrue
                $beforeRelease.WaiterCount | Should -Be 7

                $results = Receive-Task7BoundedJobs -Jobs $jobs -ExpectedCount 8
                $calls.Count | Should -Be 1
                @($results | Where-Object { $_ -ne 'err' }).Count | Should -Be 0
                $results.Count | Should -Be 8
                Get-Task7ExactFlightWaiterCount -Flight $beforeRelease.Flight | Should -Be 0
                (Get-Task7OuterFlightState -Key $key).Exists | Should -BeFalse
            }
            finally {
                $release.Set()
                $go.Set()
                if ($null -ne $jobs) {
                    $null = @($jobs | Wait-Job -Timeout 10)
                }
                [System.AppDomain]::CurrentDomain.SetData('GraphKitTest.FailureCalls', $null)
                [System.AppDomain]::CurrentDomain.SetData('GraphKitTest.FailureReady', $null)
                [System.AppDomain]::CurrentDomain.SetData('GraphKitTest.FailureGo', $null)
                [System.AppDomain]::CurrentDomain.SetData('GraphKitTest.FailureEntered', $null)
                [System.AppDomain]::CurrentDomain.SetData('GraphKitTest.FailureRelease', $null)
                if ($null -ne $jobs) {
                    $jobs | Remove-Job -Force -ErrorAction SilentlyContinue
                }
                $ready.Dispose()
                $go.Dispose()
                $entered.Dispose()
                $release.Dispose()
            }
        }

        It 'fans one unsignalled provider cancellation exception out to concurrent waiters' {
            $key = 'provider-oce-concurrency-key'
            $calls = [System.Collections.Concurrent.ConcurrentQueue[string]]::new()
            $ready = [System.Threading.CountdownEvent]::new(8)
            $go = [System.Threading.ManualResetEventSlim]::new($false)
            $entered = [System.Threading.ManualResetEventSlim]::new($false)
            $release = [System.Threading.ManualResetEventSlim]::new($false)
            [System.AppDomain]::CurrentDomain.SetData('GraphKitTest.ProviderOceCalls', $calls)
            [System.AppDomain]::CurrentDomain.SetData('GraphKitTest.ProviderOceReady', $ready)
            [System.AppDomain]::CurrentDomain.SetData('GraphKitTest.ProviderOceGo', $go)
            [System.AppDomain]::CurrentDomain.SetData('GraphKitTest.ProviderOceEntered', $entered)
            [System.AppDomain]::CurrentDomain.SetData('GraphKitTest.ProviderOceRelease', $release)

            $jobs = $null
            try {
                $jobs = 1..8 | ForEach-Object {
                    Start-ThreadJob -ThrottleLimit 8 -ScriptBlock {
                        param($Key, $Manifest)
                        Import-Module $Manifest
                        $ready = [System.AppDomain]::CurrentDomain.GetData('GraphKitTest.ProviderOceReady')
                        $go = [System.AppDomain]::CurrentDomain.GetData('GraphKitTest.ProviderOceGo')
                        $null = $ready.Signal()
                        $null = $go.Wait()

                        try {
                            $null = & (Get-Module GraphKit) {
                                param($FlightKey)
                                Invoke-GraphTokenSingleFlight -Key $FlightKey `
                                    -CancellationToken ([System.Threading.CancellationToken]::None) `
                                    -AcquireScript {
                                        $queue = [System.AppDomain]::CurrentDomain.GetData('GraphKitTest.ProviderOceCalls')
                                        $entered = [System.AppDomain]::CurrentDomain.GetData('GraphKitTest.ProviderOceEntered')
                                        $release = [System.AppDomain]::CurrentDomain.GetData('GraphKitTest.ProviderOceRelease')
                                        $queue.Enqueue('acquire')
                                        $entered.Set()
                                        $null = $release.Wait()
                                        throw [System.OperationCanceledException]::new('provider timed out internally')
                                    }
                            } $Key
                            'unexpected-success'
                        }
                        catch {
                            $_.Exception.Message
                        }
                    } -ArgumentList $key, $script:BuiltManifest
                }

                $ready.Wait(15000) | Should -BeTrue
                $go.Set()
                $entered.Wait(5000) | Should -BeTrue
                $followerObserved = Wait-Task7OuterFollowerCount -Key $key -ExpectedCount 7
                $beforeRelease = Get-Task7OuterFlightState -Key $key
                $release.Set()
                $followerObserved | Should -BeTrue
                $beforeRelease.WaiterCount | Should -Be 7
                $results = Receive-Task7BoundedJobs -Jobs $jobs -ExpectedCount 8

                $calls.Count | Should -Be 1
                $results.Count | Should -Be 8
                @($results | Where-Object { $_ -notlike '*provider timed out internally*' }).Count | Should -Be 0
                Get-Task7ExactFlightWaiterCount -Flight $beforeRelease.Flight | Should -Be 0
                (Get-Task7OuterFlightState -Key $key).Exists | Should -BeFalse
            }
            finally {
                $release.Set()
                $go.Set()
                if ($null -ne $jobs) {
                    $null = @($jobs | Wait-Job -Timeout 10)
                }
                [System.AppDomain]::CurrentDomain.SetData('GraphKitTest.ProviderOceCalls', $null)
                [System.AppDomain]::CurrentDomain.SetData('GraphKitTest.ProviderOceReady', $null)
                [System.AppDomain]::CurrentDomain.SetData('GraphKitTest.ProviderOceGo', $null)
                [System.AppDomain]::CurrentDomain.SetData('GraphKitTest.ProviderOceEntered', $null)
                [System.AppDomain]::CurrentDomain.SetData('GraphKitTest.ProviderOceRelease', $null)
                if ($null -ne $jobs) {
                    $jobs | Remove-Job -Force -ErrorAction SilentlyContinue
                }
                $ready.Dispose()
                $go.Dispose()
                $entered.Dispose()
                $release.Dispose()
            }
        }

        It 're-elects one replacement after an actual leader cancellation' {
            $key = 'actual-cancelled-leader-key'
            $leaderCts = [System.Threading.CancellationTokenSource]::new()
            $leaderStarted = [System.Threading.CountdownEvent]::new(1)
            $waitersReady = [System.Threading.CountdownEvent]::new(7)
            $waitersGo = [System.Threading.ManualResetEventSlim]::new($false)
            $replacementStarted = [System.Threading.CountdownEvent]::new(1)
            $releaseReplacement = [System.Threading.ManualResetEventSlim]::new($false)
            $calls = [System.Collections.Concurrent.ConcurrentQueue[string]]::new()
            [System.AppDomain]::CurrentDomain.SetData('GraphKitTest.LeaderCts', $leaderCts)
            [System.AppDomain]::CurrentDomain.SetData('GraphKitTest.LeaderStarted', $leaderStarted)
            [System.AppDomain]::CurrentDomain.SetData('GraphKitTest.WaitersReady', $waitersReady)
            [System.AppDomain]::CurrentDomain.SetData('GraphKitTest.WaitersGo', $waitersGo)
            [System.AppDomain]::CurrentDomain.SetData('GraphKitTest.ReplacementStarted', $replacementStarted)
            [System.AppDomain]::CurrentDomain.SetData('GraphKitTest.ReleaseReplacement', $releaseReplacement)
            [System.AppDomain]::CurrentDomain.SetData('GraphKitTest.CancelledLeaderCalls', $calls)

            $leaderJob = $null
            $waiterJobs = $null
            try {
                $leaderJob = Start-ThreadJob -ScriptBlock {
                    param($Key, $Manifest)
                    Import-Module $Manifest
                    try {
                        $null = & (Get-Module GraphKit) {
                            param($FlightKey)
                            $cts = [System.AppDomain]::CurrentDomain.GetData('GraphKitTest.LeaderCts')
                            Invoke-GraphTokenSingleFlight -Key $FlightKey -CancellationToken $cts.Token `
                                -AcquireScript {
                                    $queue = [System.AppDomain]::CurrentDomain.GetData('GraphKitTest.CancelledLeaderCalls')
                                    $started = [System.AppDomain]::CurrentDomain.GetData('GraphKitTest.LeaderStarted')
                                    $queue.Enqueue('leader')
                                    $null = $started.Signal()
                                    $null = $cts.Token.WaitHandle.WaitOne()
                                    $cts.Token.ThrowIfCancellationRequested()
                                }.GetNewClosure()
                        } $Key
                        'unexpected-leader-success'
                    }
                    catch {
                        'leader-cancelled'
                    }
                } -ArgumentList $key, $script:BuiltManifest

                $leaderStarted.Wait(15000) | Should -BeTrue
                InModuleScope GraphKit -Parameters @{ K = $key } {
                    param($K)
                    $oldFlight = [GraphTokenFlightRegistry]::Flights[$K]
                    [System.AppDomain]::CurrentDomain.SetData('GraphKitTest.OldLeaderFlight', $oldFlight)
                }

                $waiterJobs = 1..7 | ForEach-Object {
                    Start-ThreadJob -ThrottleLimit 8 -ScriptBlock {
                        param($Key, $Manifest)
                        Import-Module $Manifest
                        $ready = [System.AppDomain]::CurrentDomain.GetData('GraphKitTest.WaitersReady')
                        $go = [System.AppDomain]::CurrentDomain.GetData('GraphKitTest.WaitersGo')
                        $null = $ready.Signal()
                        $null = $go.Wait()

                        & (Get-Module GraphKit) {
                            param($FlightKey)
                            Invoke-GraphTokenSingleFlight -Key $FlightKey `
                                -CancellationToken ([System.Threading.CancellationToken]::None) `
                                -AcquireScript {
                                    $queue = [System.AppDomain]::CurrentDomain.GetData('GraphKitTest.CancelledLeaderCalls')
                                    $started = [System.AppDomain]::CurrentDomain.GetData('GraphKitTest.ReplacementStarted')
                                    $release = [System.AppDomain]::CurrentDomain.GetData('GraphKitTest.ReleaseReplacement')
                                    $queue.Enqueue('replacement')
                                    $null = $started.Signal()
                                    $null = $release.Wait()
                                    'replacement-result'
                                }
                        } $Key
                    } -ArgumentList $key, $script:BuiltManifest
                }

                $waitersReady.Wait(15000) | Should -BeTrue
                $waitersGo.Set()
                $oldFollowersObserved = Wait-Task7OuterFollowerCount -Key $key -ExpectedCount 7
                $oldStateBeforeCancel = Get-Task7OuterFlightState -Key $key
                $leaderCts.Cancel()

                $replacementStarted.Wait(15000) | Should -BeTrue
                $replacementFollowersObserved = Wait-Task7OuterFollowerCount `
                    -Key $key -ExpectedCount 6
                $replacementStateBeforeRelease = Get-Task7OuterFlightState -Key $key
                $leaderResult = Receive-Task7BoundedJobs -Jobs @($leaderJob) -ExpectedCount 1
                $leaderResult | Should -Contain 'leader-cancelled'

                # The old leader's finally block has now run while the replacement
                # is still held open. Its exact-instance cleanup must not remove the
                # replacement registered under the same key.
                InModuleScope GraphKit -Parameters @{ K = $key } {
                    param($K)
                    $oldFlight = [System.AppDomain]::CurrentDomain.GetData('GraphKitTest.OldLeaderFlight')
                    [GraphTokenFlightRegistry]::Flights.ContainsKey($K) | Should -BeTrue
                    [object]::ReferenceEquals([GraphTokenFlightRegistry]::Flights[$K], $oldFlight) | Should -BeFalse
                }

                $releaseReplacement.Set()
                $waiterResults = Receive-Task7BoundedJobs -Jobs $waiterJobs -ExpectedCount 7
                $oldFollowersObserved | Should -BeTrue
                $oldStateBeforeCancel.WaiterCount | Should -Be 7
                $replacementFollowersObserved | Should -BeTrue
                $replacementStateBeforeRelease.WaiterCount | Should -Be 6
                $waiterResults.Count | Should -Be 7
                @($waiterResults | Where-Object { $_ -ne 'replacement-result' }).Count | Should -Be 0
                @($calls | Where-Object { $_ -eq 'leader' }).Count | Should -Be 1
                @($calls | Where-Object { $_ -eq 'replacement' }).Count | Should -Be 1
                Get-Task7ExactFlightWaiterCount -Flight $oldStateBeforeCancel.Flight | Should -Be 0
                Get-Task7ExactFlightWaiterCount -Flight $replacementStateBeforeRelease.Flight |
                    Should -Be 0
                InModuleScope GraphKit -Parameters @{ K = $key } {
                    param($K)
                    [GraphTokenFlightRegistry]::Flights.ContainsKey($K) | Should -BeFalse
                }
            }
            finally {
                $releaseReplacement.Set()
                $waitersGo.Set()
                $leaderCts.Cancel()
                [System.AppDomain]::CurrentDomain.SetData('GraphKitTest.LeaderCts', $null)
                [System.AppDomain]::CurrentDomain.SetData('GraphKitTest.LeaderStarted', $null)
                [System.AppDomain]::CurrentDomain.SetData('GraphKitTest.WaitersReady', $null)
                [System.AppDomain]::CurrentDomain.SetData('GraphKitTest.WaitersGo', $null)
                [System.AppDomain]::CurrentDomain.SetData('GraphKitTest.ReplacementStarted', $null)
                [System.AppDomain]::CurrentDomain.SetData('GraphKitTest.ReleaseReplacement', $null)
                [System.AppDomain]::CurrentDomain.SetData('GraphKitTest.CancelledLeaderCalls', $null)
                [System.AppDomain]::CurrentDomain.SetData('GraphKitTest.OldLeaderFlight', $null)
                if ($null -ne $leaderJob) {
                    $null = @($leaderJob | Wait-Job -Timeout 10)
                    $leaderJob | Remove-Job -Force -ErrorAction SilentlyContinue
                }
                if ($null -ne $waiterJobs) {
                    $null = @($waiterJobs | Wait-Job -Timeout 10)
                    $waiterJobs | Remove-Job -Force -ErrorAction SilentlyContinue
                }
                $leaderCts.Dispose()
                $leaderStarted.Dispose()
                $waitersReady.Dispose()
                $waitersGo.Dispose()
                $replacementStarted.Dispose()
                $releaseReplacement.Dispose()
            }
        }

        It 'collapses real sender acquisitions across contexts sharing one canonical tuple' {
            $key = 'production-sender-tuple-key'
            $calls = [System.Collections.Concurrent.ConcurrentQueue[string]]::new()
            $ready = [System.Threading.CountdownEvent]::new(8)
            $go = [System.Threading.ManualResetEventSlim]::new($false)
            $entered = [System.Threading.ManualResetEventSlim]::new($false)
            $release = [System.Threading.ManualResetEventSlim]::new($false)
            [System.AppDomain]::CurrentDomain.SetData('GraphKitTest.ProductionSingleFlightCalls', $calls)
            [System.AppDomain]::CurrentDomain.SetData('GraphKitTest.ProductionSingleFlightReady', $ready)
            [System.AppDomain]::CurrentDomain.SetData('GraphKitTest.ProductionSingleFlightGo', $go)
            [System.AppDomain]::CurrentDomain.SetData('GraphKitTest.ProductionSingleFlightEntered', $entered)
            [System.AppDomain]::CurrentDomain.SetData('GraphKitTest.ProductionSingleFlightRelease', $release)

            $jobs = $null
            try {
                $jobs = 1..8 | ForEach-Object {
                    Start-ThreadJob -ThrottleLimit 8 -ScriptBlock {
                        param($Key, $Manifest)
                        Import-Module $Manifest
                        $ready = [System.AppDomain]::CurrentDomain.GetData('GraphKitTest.ProductionSingleFlightReady')
                        $go = [System.AppDomain]::CurrentDomain.GetData('GraphKitTest.ProductionSingleFlightGo')
                        $null = $ready.Signal()
                        $null = $go.Wait()

                        & (Get-Module GraphKit) {
                            param($AcquisitionKey)
                            $provider = {
                                $queue = [System.AppDomain]::CurrentDomain.GetData('GraphKitTest.ProductionSingleFlightCalls')
                                $entered = [System.AppDomain]::CurrentDomain.GetData('GraphKitTest.ProductionSingleFlightEntered')
                                $release = [System.AppDomain]::CurrentDomain.GetData('GraphKitTest.ProductionSingleFlightRelease')
                                $queue.Enqueue('acquire')
                                $entered.Set()
                                $null = $release.Wait()
                                return @{
                                    Token        = 'runtime-single-flight-token'
                                    ExpiresOnUtc = [System.DateTimeOffset]::UtcNow.AddHours(1)
                                }
                            }
                            $source = [ProviderTokenSource]::new(
                                $provider, 'https://graph.microsoft.com', 'client-id', 'runtime-generation'
                            )
                            $prover = {
                                param($Context, $TokenResult, $CancellationToken)
                                throw "proof-sentinel:$($TokenResult.TokenFingerprint)"
                            }

                            try {
                                $null = Send-GraphHttpRequest `
                                    -Uri ([uri] 'https://graph.microsoft.com/v1.0/mutation') `
                                    -Method POST -Body @{} -CredentialPolicy GraphBearer `
                                    -ExpectedAuthority ([uri] 'https://graph.microsoft.com') `
                                    -TokenSource $source -TokenAcquisitionKey $AcquisitionKey `
                                    -TargetTenantId ([guid] '00000000-0000-0000-0000-000000000001') `
                                    -VerifyTenantBinding -TenantBindingProver $prover
                                return 'unexpected-success'
                            }
                            catch {
                                return $_.Exception.Message
                            }
                        } $Key
                    } -ArgumentList $key, $script:BuiltManifest
                }

                $ready.Wait(15000) | Should -BeTrue
                $go.Set()
                $entered.Wait(5000) | Should -BeTrue
                $flightKey = InModuleScope GraphKit -Parameters @{ K = $key } {
                    param($K)
                    Get-GraphTokenFlightKey -AcquisitionKey $K -ForceRefresh:$false
                }
                $followerObserved = Wait-Task7OuterFollowerCount `
                    -Key $flightKey -ExpectedCount 7
                $beforeRelease = Get-Task7OuterFlightState -Key $flightKey
                $release.Set()
                $followerObserved | Should -BeTrue
                $beforeRelease.WaiterCount | Should -Be 7
                $results = Receive-Task7BoundedJobs -Jobs $jobs -ExpectedCount 8

                $calls.Count | Should -Be 1
                $results.Count | Should -Be 8
                @($results | Where-Object { $_ -notlike 'proof-sentinel:*' }).Count | Should -Be 0
                @($results | Sort-Object -Unique).Count | Should -Be 1
                Get-Task7ExactFlightWaiterCount -Flight $beforeRelease.Flight | Should -Be 0
                InModuleScope GraphKit -Parameters @{ K = $key } {
                    param($K)
                    $flightKey = Get-GraphTokenFlightKey -AcquisitionKey $K -ForceRefresh:$false
                    [GraphTokenFlightRegistry]::Flights.ContainsKey($flightKey) | Should -BeFalse
                }
            }
            finally {
                $release.Set()
                $go.Set()
                if ($null -ne $jobs) {
                    $null = @($jobs | Wait-Job -Timeout 10)
                }
                [System.AppDomain]::CurrentDomain.SetData('GraphKitTest.ProductionSingleFlightCalls', $null)
                [System.AppDomain]::CurrentDomain.SetData('GraphKitTest.ProductionSingleFlightReady', $null)
                [System.AppDomain]::CurrentDomain.SetData('GraphKitTest.ProductionSingleFlightGo', $null)
                [System.AppDomain]::CurrentDomain.SetData('GraphKitTest.ProductionSingleFlightEntered', $null)
                [System.AppDomain]::CurrentDomain.SetData('GraphKitTest.ProductionSingleFlightRelease', $null)
                if ($null -ne $jobs) {
                    $jobs | Remove-Job -Force -ErrorAction SilentlyContinue
                }
                $ready.Dispose()
                $go.Dispose()
                $entered.Dispose()
                $release.Dispose()
            }
        }
    }

    Context 'Credential generation' {

        It 'is stable for identical PFX bytes and changes when the bytes at the same path change' {
            $pfxPath = Join-Path $TestDrive 'generation.pfx'
            [System.IO.File]::WriteAllBytes($pfxPath, [byte[]] @(1, 2, 3, 4))

            $first = InModuleScope GraphKit -Parameters @{ Path = $pfxPath } {
                param($Path)
                Get-GraphCredentialGeneration -TenantProfile @{
                    AuthMethod = 'Certificate'
                    Credential = @{
                        PfxPath = $Path
                        Password = @{ VaultName = 'vault'; SecretName = 'password'; Version = 'v1' }
                    }
                }
            }
            $same = InModuleScope GraphKit -Parameters @{ Path = $pfxPath } {
                param($Path)
                Get-GraphCredentialGeneration -TenantProfile @{
                    AuthMethod = 'Certificate'
                    Credential = @{
                        PfxPath = $Path
                        Password = @{ VaultName = 'vault'; SecretName = 'password'; Version = 'v1' }
                    }
                }
            }

            [System.IO.File]::WriteAllBytes($pfxPath, [byte[]] @(1, 2, 3, 5))
            $changed = InModuleScope GraphKit -Parameters @{ Path = $pfxPath } {
                param($Path)
                Get-GraphCredentialGeneration -TenantProfile @{
                    AuthMethod = 'Certificate'
                    Credential = @{
                        PfxPath = $Path
                        Password = @{ VaultName = 'vault'; SecretName = 'password'; Version = 'v1' }
                    }
                }
            }

            $same | Should -Be $first
            $changed | Should -Not -Be $first
            $first | Should -Match 'sha256:[0-9a-f]{64}'
            $first | Should -Not -Match ([regex]::Escape([Convert]::ToBase64String([byte[]] @(1, 2, 3, 4))))
        }

        It 'changes when only the PFX password secret version changes' {
            $pfxPath = Join-Path $TestDrive 'password-version.pfx'
            [System.IO.File]::WriteAllBytes($pfxPath, [byte[]] @(5, 6, 7, 8))

            $v1 = InModuleScope GraphKit -Parameters @{ Path = $pfxPath } {
                param($Path)
                Get-GraphCredentialGeneration -TenantProfile @{
                    AuthMethod = 'Certificate'
                    Credential = @{
                        PfxPath = $Path
                        Password = @{ VaultName = 'vault'; SecretName = 'password'; Version = 'v1' }
                    }
                }
            }
            $v2 = InModuleScope GraphKit -Parameters @{ Path = $pfxPath } {
                param($Path)
                Get-GraphCredentialGeneration -TenantProfile @{
                    AuthMethod = 'Certificate'
                    Credential = @{
                        PfxPath = $Path
                        Password = @{ VaultName = 'vault'; SecretName = 'password'; Version = 'v2' }
                    }
                }
            }

            $v2 | Should -Not -Be $v1
            $v1 | Should -Match '\|2:v1$'
            $v2 | Should -Match '\|2:v2$'
        }

        It 'zeroes the internal PFX snapshot after deriving its generation' {
            $script:GenerationSnapshotProbe = [byte[]] @(9, 8, 7, 6)
            Mock Get-GraphPfxSnapshot -ModuleName GraphKit {
                [pscustomobject] @{
                    Path = '/canonical/test.pfx'
                    Bytes = $script:GenerationSnapshotProbe
                    Sha256 = ('b' * 64)
                }
            }

            $generation = InModuleScope GraphKit {
                Get-GraphCredentialGeneration -TenantProfile @{
                    AuthMethod = 'Certificate'
                    Credential = @{
                        PfxPath = 'relative/test.pfx'
                        Password = @{ VaultName = 'vault'; SecretName = 'password'; Version = 'v1' }
                    }
                }
            }

            $generation | Should -Be (
                "g1|Certificate.PFX|19:/canonical/test.pfx|71:sha256:$('b' * 64)|5:vault|8:password|2:v1"
            )
            @($script:GenerationSnapshotProbe | Where-Object { $_ -ne 0 }).Count | Should -Be 0
        }

        It 'pins a relative PFX path into the legacy generation selected by a compatibility factory' {
            $original = Join-Path $TestDrive 'relative-pfx-origin'
            $elsewhere = Join-Path $TestDrive 'relative-pfx-elsewhere'
            $captureKey = 'GraphKitTest.CanonicalFactoryPfxPath'
            [System.AppDomain]::CurrentDomain.SetData($captureKey, $null)
            $null = New-Item -ItemType Directory -Path $original, $elsewhere -Force
            [System.IO.File]::WriteAllBytes((Join-Path $original 'credential.pfx'), [byte[]] @(1, 3, 3, 7))
            $source = InModuleScope GraphKit -Parameters @{ Origin = $original; CaptureKey = $captureKey } {
                param($Origin, $CaptureKey)
                Push-Location $Origin
                try {
                    New-GraphTokenSource -Profile @{
                            TenantId = '00000000-0000-0000-0000-000000000001'
                            ClientId = '00000000-0000-0000-0000-000000000002'
                            AuthMethod = 'Certificate'
                            Credential = @{
                                PfxPath = 'credential.pfx'
                                Password = @{ VaultName = 'vault'; SecretName = 'password'; Version = 'v1' }
                            }
                        } -Cloud @{
                            Resource = 'https://graph.microsoft.com'
                            Authority = 'https://login.microsoftonline.com'
                        } -MsalFactory {
                            param($FactoryProfile)
                            $capturedPath = if ($null -eq $FactoryProfile) {
                                '<null>'
                            }
                            else {
                                [string] $FactoryProfile.Credential.PfxPath
                            }
                            [System.AppDomain]::CurrentDomain.SetData($CaptureKey, $capturedPath)
                            [pscustomobject] @{ Kind = 'compatibility-factory-fixture' }
                        }.GetNewClosure()
                }
                finally {
                    Pop-Location
                }
            }

            Push-Location $elsewhere
            try {
                $null = $source.GetApplication()
                $source.CredentialGeneration | Should -Match '^g1\|Certificate\.PFX\|.+\|71:sha256:[0-9a-f]{64}\|5:vault\|8:password\|2:v1$'
                $canonicalPath = [System.IO.Path]::GetFullPath((Join-Path $original 'credential.pfx'))
                $source.CredentialGeneration | Should -Match ([regex]::Escape($canonicalPath))
                [System.AppDomain]::CurrentDomain.GetData($captureKey) | Should -BeExactly $canonicalPath
            }
            finally {
                Pop-Location
                [System.AppDomain]::CurrentDomain.SetData($captureKey, $null)
            }
        }

        It 'changes when a vault-certificate material or password version changes' {
            $baseProfile = @{
                AuthMethod = 'Certificate'
                Credential = @{
                    VaultName = 'vault'
                    CertificateName = 'certificate'
                    Version = 'cert-v1'
                    Password = @{ VaultName = 'vault'; SecretName = 'password'; Version = 'password-v1' }
                }
            }

            $base = InModuleScope GraphKit -Parameters @{ Profile = $baseProfile } {
                param($Profile)
                Get-GraphCredentialGeneration -TenantProfile $Profile
            }
            $passwordChanged = $baseProfile.Clone()
            $passwordChanged.Credential = $baseProfile.Credential.Clone()
            $passwordChanged.Credential.Password = $baseProfile.Credential.Password.Clone()
            $passwordChanged.Credential.Password.Version = 'password-v2'
            $passwordGeneration = InModuleScope GraphKit -Parameters @{ Profile = $passwordChanged } {
                param($Profile)
                Get-GraphCredentialGeneration -TenantProfile $Profile
            }
            $materialChanged = $baseProfile.Clone()
            $materialChanged.Credential = $baseProfile.Credential.Clone()
            $materialChanged.Credential.Version = 'cert-v2'
            $materialGeneration = InModuleScope GraphKit -Parameters @{ Profile = $materialChanged } {
                param($Profile)
                Get-GraphCredentialGeneration -TenantProfile $Profile
            }

            $passwordGeneration | Should -Not -Be $base
            $materialGeneration | Should -Not -Be $base
        }

        It 'fails actionably when a persisted PFX cannot be read for identity' {
            $missing = Join-Path $TestDrive 'missing.pfx'

            {
                InModuleScope GraphKit -Parameters @{ Path = $missing } {
                    param($Path)
                    Get-GraphCredentialGeneration -TenantProfile @{
                        AuthMethod = 'Certificate'
                        Credential = @{
                            PfxPath = $Path
                            Password = @{ VaultName = 'vault'; SecretName = 'password'; Version = 'v1' }
                        }
                    }
                }
            } | Should -Throw -ExpectedMessage '*PFX*read*'
        }

        It 'isolates mutable vault selectors per context while versioned references still coalesce' {
            $cloud = @{ Resource = 'https://graph.microsoft.com'; Authority = 'https://login.microsoftonline.com' }
            $unversioned = @{
                TenantId = '00000000-0000-0000-0000-000000000001'
                ClientId = '00000000-0000-0000-0000-000000000002'
                AuthMethod = 'ClientSecret'
                Credential = @{ VaultName = 'vault'; SecretName = 'secret' }
            }
            $versioned = $unversioned.Clone()
            $versioned.Credential = $unversioned.Credential.Clone()
            $versioned.Credential.Version = 'immutable-v1'

            $generations = InModuleScope GraphKit -Parameters @{
                Cloud = $cloud
                Unversioned = $unversioned
                Versioned = $versioned
            } {
                param($Cloud, $Unversioned, $Versioned)
                $factory = { throw 'generation-only test must not acquire' }
                [pscustomobject] @{
                    UnpinnedA = (New-GraphTokenSource -Profile $Unversioned -Cloud $Cloud -MsalFactory $factory).CredentialGeneration
                    UnpinnedB = (New-GraphTokenSource -Profile $Unversioned -Cloud $Cloud -MsalFactory $factory).CredentialGeneration
                    PinnedA = (New-GraphTokenSource -Profile $Versioned -Cloud $Cloud -MsalFactory $factory).CredentialGeneration
                    PinnedB = (New-GraphTokenSource -Profile $Versioned -Cloud $Cloud -MsalFactory $factory).CredentialGeneration
                }
            }

            $generations.UnpinnedA | Should -Not -Be $generations.UnpinnedB
            $generations.UnpinnedA | Should -Match '\|context:[0-9a-f]{32}$'
            $generations.PinnedA | Should -Be $generations.PinnedB
            $generations.PinnedA | Should -Be 'g1|ClientSecret|5:vault|6:secret|12:immutable-v1'
        }

        It 'does not collide when distinct versioned reference fields contain the old delimiter' {
            $generations = InModuleScope GraphKit {
                [pscustomobject] @{
                    First = Get-GraphCredentialGeneration -TenantProfile @{
                        AuthMethod = 'ClientSecret'
                        Credential = @{ VaultName = 'a|b'; SecretName = 'c'; Version = 'd' }
                    }
                    Second = Get-GraphCredentialGeneration -TenantProfile @{
                        AuthMethod = 'ClientSecret'
                        Credential = @{ VaultName = 'a'; SecretName = 'b'; Version = 'c|d' }
                    }
                }
            }

            $generations.First | Should -Not -Be $generations.Second
            $generations.First | Should -Be 'g1|ClientSecret|3:a|b|1:c|1:d'
            $generations.Second | Should -Be 'g1|ClientSecret|1:a|1:b|3:c|d'
        }

        It 'isolates unversioned bearer rotations so old and new tokens cannot share a flight key' {
            $script:BearerRotationValues = [System.Collections.Concurrent.ConcurrentQueue[string]]::new()
            $script:BearerRotationValues.Enqueue('old-bearer')
            $script:BearerRotationValues.Enqueue('new-bearer')
            Mock Get-GraphVaultCredential -ModuleName GraphKit {
                $resolved = $null
                if (-not $script:BearerRotationValues.TryDequeue([ref] $resolved)) {
                    throw 'bearer rotation test exhausted its values'
                }
                [pscustomobject] @{ Material = $resolved }
            }

            $result = InModuleScope GraphKit {
                $profile = @{
                    TenantId = '00000000-0000-0000-0000-000000000001'
                    ClientId = $null
                    AuthMethod = 'BearerToken'
                    Environment = 'Global'
                    Credential = @{ VaultName = 'vault'; SecretName = 'bearer' }
                }
                $cloud = @{
                    Name = 'Global'
                    Resource = 'https://graph.microsoft.com'
                    Authority = 'https://login.microsoftonline.com'
                }
                $old = New-GraphTokenSource -Profile $profile -Cloud $cloud
                $new = New-GraphTokenSource -Profile $profile -Cloud $cloud
                [pscustomobject] @{
                    OldGeneration = $old.CredentialGeneration
                    NewGeneration = $new.CredentialGeneration
                    OldToken = $old.Acquire($false, [System.Threading.CancellationToken]::None).AccessToken
                    NewToken = $new.Acquire($false, [System.Threading.CancellationToken]::None).AccessToken
                    OldKey = Get-GraphTokenAcquisitionKey -Environment $cloud.Name -TenantId $profile.TenantId `
                        -Authority $cloud.Authority -Resource $cloud.Resource -ClientId $profile.ClientId `
                        -AuthMode BearerToken -Generation $old.CredentialGeneration
                    NewKey = Get-GraphTokenAcquisitionKey -Environment $cloud.Name -TenantId $profile.TenantId `
                        -Authority $cloud.Authority -Resource $cloud.Resource -ClientId $profile.ClientId `
                        -AuthMode BearerToken -Generation $new.CredentialGeneration
                }
            }

            $result.OldToken | Should -Be 'old-bearer'
            $result.NewToken | Should -Be 'new-bearer'
            $result.OldGeneration | Should -Not -Be $result.NewGeneration
            $result.OldKey | Should -Not -Be $result.NewKey
        }

        It 'treats a subject-only store selector and unversioned vault certificate as mutable' {
            $pinned = InModuleScope GraphKit {
                [pscustomobject] @{
                    SubjectOnly = Test-GraphCredentialReferencePinned -TenantProfile @{
                        AuthMethod = 'Certificate'
                        Credential = @{ StoreLocation = 'CurrentUser'; StoreName = 'My'; Subject = 'CN=example' }
                    }
                    Thumbprint = Test-GraphCredentialReferencePinned -TenantProfile @{
                        AuthMethod = 'Certificate'
                        Credential = @{ StoreLocation = 'CurrentUser'; StoreName = 'My'; Thumbprint = 'ABC123' }
                    }
                    VaultUnversioned = Test-GraphCredentialReferencePinned -TenantProfile @{
                        AuthMethod = 'Certificate'
                        Credential = @{ VaultName = 'vault'; CertificateName = 'cert' }
                    }
                    VaultVersioned = Test-GraphCredentialReferencePinned -TenantProfile @{
                        AuthMethod = 'Certificate'
                        Credential = @{
                            VaultName = 'vault'
                            CertificateName = 'cert'
                            Version = 'cert-v1'
                            Password = @{ VaultName = 'vault'; SecretName = 'password'; Version = 'password-v1' }
                        }
                    }
                }
            }

            $pinned.SubjectOnly | Should -BeFalse
            $pinned.Thumbprint | Should -BeTrue
            $pinned.VaultUnversioned | Should -BeFalse
            $pinned.VaultVersioned | Should -BeTrue
        }
    }

    Context 'Canonical tuple normalization' {

        It 'yields the same key for GUID case, host case and scope order differences' {
            InModuleScope GraphKit {
                $k1 = Get-GraphTokenAcquisitionKey `
                    -Environment 'Global' `
                    -TenantId '3A4B5C6D-1111-2222-3333-444455556666' `
                    -Authority 'HTTPS://LOGIN.MICROSOFTONLINE.COM' `
                    -Resource 'https://graph.microsoft.com' `
                    -ClientId '7D6E5F44-9999-8888-7777-666655554444' `
                    -AuthMode 'Certificate' `
                    -IdentitySelector '' `
                    -Generation 'gen' `
                    -Scopes @('https://graph.microsoft.com/b', 'https://graph.microsoft.com/a')

                $k2 = Get-GraphTokenAcquisitionKey `
                    -Environment 'Global' `
                    -TenantId '3a4b5c6d-1111-2222-3333-444455556666' `
                    -Authority 'https://login.microsoftonline.com' `
                    -Resource 'https://graph.microsoft.com' `
                    -ClientId '7d6e5f44-9999-8888-7777-666655554444' `
                    -AuthMode 'Certificate' `
                    -IdentitySelector '' `
                    -Generation 'gen' `
                    -Scopes @('https://graph.microsoft.com/a', 'https://graph.microsoft.com/b')

                $k1 | Should -Be $k2
            }
        }

        It 'yields a different key when a tuple component changes' {
            InModuleScope GraphKit {
                $k1 = Get-GraphTokenAcquisitionKey -Environment 'Global' -TenantId '3a4b5c6d-1111-2222-3333-444455556666' -Authority 'https://login.microsoftonline.com' -Resource 'https://graph.microsoft.com' -ClientId '7d6e5f44-9999-8888-7777-666655554444' -AuthMode 'Certificate' -IdentitySelector '' -Generation 'gen'
                $k2 = Get-GraphTokenAcquisitionKey -Environment 'Global' -TenantId '3a4b5c6d-1111-2222-3333-444455556666' -Authority 'https://login.microsoftonline.com' -Resource 'https://graph.microsoft.com' -ClientId '7d6e5f44-9999-8888-7777-666655554444' -AuthMode 'ClientSecret' -IdentitySelector '' -Generation 'gen'
                $k1 | Should -Not -Be $k2
            }
        }

        It 'keeps ordinary and forced acquisitions in different in-flight groups' {
            InModuleScope GraphKit {
                $ordinary = Get-GraphTokenFlightKey -AcquisitionKey 'same-tuple' -ForceRefresh:$false
                $forced = Get-GraphTokenFlightKey -AcquisitionKey 'same-tuple' -ForceRefresh:$true

                $ordinary | Should -Not -Be $forced
                $ordinary | Should -Not -Match 'True|False'
                $forced | Should -Not -Match 'True|False'
            }
        }

        It 'collapses same-mode callers while ordinary and forced flights remain separate' {
            $key = 'mode-partition-key'
            $calls = [System.Collections.Concurrent.ConcurrentQueue[string]]::new()
            $entered = [System.Threading.CountdownEvent]::new(2)
            $release = [System.Threading.ManualResetEventSlim]::new($false)
            [System.AppDomain]::CurrentDomain.SetData('GraphKitTest.ModeCalls', $calls)
            [System.AppDomain]::CurrentDomain.SetData('GraphKitTest.ModeEntered', $entered)
            [System.AppDomain]::CurrentDomain.SetData('GraphKitTest.ModeRelease', $release)

            $workers = [System.Collections.Generic.List[object]]::new()
            try {
                # Start-ThreadJob shares one process-global throttle. An unrelated
                # running job can consume a slot and deadlock a participant-count
                # readiness barrier before GraphKit is reached. Prepare dedicated
                # runspaces synchronously so this test measures token-flight
                # concurrency rather than ambient job-scheduler capacity.
                0..5 | ForEach-Object {
                    $force = $_ -ge 3
                    $runspace = [runspacefactory]::CreateRunspace()
                    $runspace.ThreadOptions =
                        [System.Management.Automation.Runspaces.PSThreadOptions]::UseNewThread
                    $runspace.Open()

                    $initializer = [powershell]::Create()
                    $initializer.Runspace = $runspace
                    try {
                        $null = $initializer.AddCommand('Import-Module').
                            AddParameter('Name', $script:BuiltManifest).
                            AddParameter('ErrorAction', 'Stop').Invoke()
                    }
                    finally {
                        $initializer.Dispose()
                    }

                    $pipeline = [powershell]::Create()
                    $pipeline.Runspace = $runspace
                    $null = $pipeline.AddScript({
                        param($Key, $Force)
                        & (Get-Module GraphKit) {
                            param($AcquisitionKey, $ForceRefresh)
                            $mode = if ($ForceRefresh) { 'refresh' } else { 'ordinary' }
                            $flightKey = Get-GraphTokenFlightKey `
                                -AcquisitionKey $AcquisitionKey -ForceRefresh:$ForceRefresh
                            Invoke-GraphTokenSingleFlight -Key $flightKey -AcquireScript {
                                $queue = [System.AppDomain]::CurrentDomain.GetData('GraphKitTest.ModeCalls')
                                $entered = [System.AppDomain]::CurrentDomain.GetData('GraphKitTest.ModeEntered')
                                $release = [System.AppDomain]::CurrentDomain.GetData('GraphKitTest.ModeRelease')
                                $queue.Enqueue($mode)
                                $null = $entered.Signal()
                                $null = $release.Wait()
                                $mode
                            }.GetNewClosure()
                        } $Key $Force
                    }).AddArgument($key).AddArgument($force)

                    $workers.Add([pscustomobject] @{
                        PowerShell = $pipeline
                        Runspace = $runspace
                        Async = $null
                        Received = $false
                    })
                }

                foreach ($worker in $workers) {
                    $worker.Async = $worker.PowerShell.BeginInvoke()
                }

                $entered.Wait(5000) | Should -BeTrue
                $flightKeys = InModuleScope GraphKit -Parameters @{ K = $key } {
                    param($K)
                    [pscustomobject] @{
                        Ordinary = Get-GraphTokenFlightKey `
                            -AcquisitionKey $K -ForceRefresh:$false
                        Forced = Get-GraphTokenFlightKey `
                            -AcquisitionKey $K -ForceRefresh:$true
                    }
                }
                $ordinaryFollowersObserved = Wait-Task7OuterFollowerCount `
                    -Key $flightKeys.Ordinary -ExpectedCount 2
                $forcedFollowersObserved = Wait-Task7OuterFollowerCount `
                    -Key $flightKeys.Forced -ExpectedCount 2
                $ordinaryBeforeRelease = Get-Task7OuterFlightState -Key $flightKeys.Ordinary
                $forcedBeforeRelease = Get-Task7OuterFlightState -Key $flightKeys.Forced
                $release.Set()
                $ordinaryFollowersObserved | Should -BeTrue
                $forcedFollowersObserved | Should -BeTrue
                $ordinaryBeforeRelease.WaiterCount | Should -Be 2
                $forcedBeforeRelease.WaiterCount | Should -Be 2
                $ordinaryBeforeRelease.RegistryCount | Should -Be 2
                $forcedBeforeRelease.RegistryCount | Should -Be 2
                $results = @(
                    foreach ($worker in $workers) {
                        $worker.Async.AsyncWaitHandle.WaitOne(10000) |
                            Should -BeTrue -Because 'each dedicated runspace must complete'
                        $worker.Received = $true
                        $worker.PowerShell.EndInvoke($worker.Async)
                    }
                )

                @($calls | Where-Object { $_ -eq 'ordinary' }).Count | Should -Be 1
                @($calls | Where-Object { $_ -eq 'refresh' }).Count | Should -Be 1
                @($results | Where-Object { $_ -eq 'ordinary' }).Count | Should -Be 3
                @($results | Where-Object { $_ -eq 'refresh' }).Count | Should -Be 3
                Get-Task7ExactFlightWaiterCount -Flight $ordinaryBeforeRelease.Flight | Should -Be 0
                Get-Task7ExactFlightWaiterCount -Flight $forcedBeforeRelease.Flight | Should -Be 0
                (Get-Task7OuterFlightState -Key $flightKeys.Ordinary).Exists | Should -BeFalse
                (Get-Task7OuterFlightState -Key $flightKeys.Forced).Exists | Should -BeFalse
            }
            finally {
                $release.Set()
                foreach ($worker in $workers) {
                    if ($null -ne $worker.Async -and -not $worker.Received) {
                        if ($worker.Async.AsyncWaitHandle.WaitOne(10000)) {
                            try { $null = $worker.PowerShell.EndInvoke($worker.Async) } catch { }
                        }
                        else {
                            try { $worker.PowerShell.Stop() } catch { }
                        }
                    }
                    $worker.PowerShell.Dispose()
                    $worker.Runspace.Close()
                    $worker.Runspace.Dispose()
                }
                [System.AppDomain]::CurrentDomain.SetData('GraphKitTest.ModeCalls', $null)
                [System.AppDomain]::CurrentDomain.SetData('GraphKitTest.ModeEntered', $null)
                [System.AppDomain]::CurrentDomain.SetData('GraphKitTest.ModeRelease', $null)
                $entered.Dispose()
                $release.Dispose()
            }
        }
    }
}
