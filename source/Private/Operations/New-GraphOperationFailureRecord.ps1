<#
    Private: build the ErrorRecord for a non-Succeeded operation result.

    Extracted from Get-GraphObject so it can be tested directly. Testing it through
    Get-GraphObject requires standing up a context, a token source with a working Acquire, and
    a transport - and the dispatch happens through a scriptblock built before a Pester mock can
    apply, so a mock on the handler intercepts nothing and the "unit" test silently issues a
    real request. A test that reaches a live tenant is not a unit test, and one asserting
    against whatever that tenant returned is not testing the code it names.

    The record carries what a caller has to branch on:

      - an ErrorCategory mapped from the HTTP status, so `$_.CategoryInfo.Category` separates
        permission-denied from a generic failure
      - the status and Graph error code in the message
      - the whole result envelope as TargetObject, so telemetry survives onto the error

    Before this existed the throw was a bare string. The status was recorded in telemetry and
    unreachable from the error, so a consumer had to re-issue the entire request through
    -PassThruResult to read a number it had already been given - against a customer tenant.
#>

function New-GraphOperationFailureRecord {
    [CmdletBinding()]
    [OutputType([System.Management.Automation.ErrorRecord])]
    param(
        [Parameter(Mandatory)]
        [object] $Result,

        [Parameter(Mandatory)]
        [string] $Type,

        [Parameter(Mandatory)]
        [string] $Operation
    )

    $lastAttempt = @($Result.Telemetry) | Select-Object -Last 1
    $statusCode = if ($null -ne $lastAttempt) { [int] $lastAttempt.StatusCode } else { 0 }
    $graphErrorCode = if ($null -ne $lastAttempt -and -not [string]::IsNullOrWhiteSpace([string] $lastAttempt.GraphErrorCode)) {
        [string] $lastAttempt.GraphErrorCode
    }
    else { $null }

    $category = switch ($statusCode) {
        401 { [System.Management.Automation.ErrorCategory]::AuthenticationError }
        403 { [System.Management.Automation.ErrorCategory]::PermissionDenied }
        404 { [System.Management.Automation.ErrorCategory]::ObjectNotFound }
        408 { [System.Management.Automation.ErrorCategory]::OperationTimeout }
        429 { [System.Management.Automation.ErrorCategory]::LimitsExceeded }
        default {
            if ($statusCode -ge 500) { [System.Management.Automation.ErrorCategory]::ResourceUnavailable }
            else { [System.Management.Automation.ErrorCategory]::InvalidResult }
        }
    }

    $detail = "Get-GraphObject failed for '{0}/{1}': Outcome '{2}', Certainty '{3}'" -f $Type, $Operation, $Result.Outcome, $Result.Certainty
    if ($statusCode -gt 0) { $detail += ", HTTP $statusCode" }
    if ($null -ne $graphErrorCode) { $detail += ", Graph error '$graphErrorCode'" }
    $detail += '.'

    $record = [System.Management.Automation.ErrorRecord]::new(
        [System.InvalidOperationException]::new($detail),
        "GraphKit.OperationFailed.$statusCode",
        $category,
        $Result)
    $record.ErrorDetails = [System.Management.Automation.ErrorDetails]::new($detail)
    return $record
}
