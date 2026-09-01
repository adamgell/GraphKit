<#
    Normalized transport result record.

    This is the internal contract the retry engine consumes. The real sender
    (Send-GraphHttpRequest) and every injected test sender produce this exact
    shape, so policy logic never touches PowerShell exception internals or
    HttpClient-specific response objects.

    Field semantics:
      StatusCode         HTTP status when a response was received; 0 otherwise.
      Headers            Case-insensitive hashtable of response headers
                         (duplicate header values are comma-joined).
      Body               Normalized body: parsed hashtable for JSON, raw string
                         for other text, byte[] for binary, $null when empty.
      RequestId          The response `request-id` header, when present.
      TransportException The exception for transport-level failures
                         (timeout, reset, cancellation); $null on a clean response.
                         Caller/module cancellation carries the internal boolean
                         marker GraphKit.OperationCancellation in Exception.Data.
      ResponseReceived   $true when HTTP response headers were actually received.
      VerifiedTenantId   Tenant proven for the exact bearer placed on the request;
                         never populated from an unverified provider claim.
      TokenFingerprint   Non-secret fingerprint of the exact bearer placed on the
                         request. The bearer itself never enters this record.
      CredentialGeneration Non-secret credential generation for that bearer.
#>
class GraphTransportResult {
    [int]       $StatusCode
    [hashtable] $Headers
    [object]    $Body
    [string]    $RequestId
    [object]    $TransportException
    [bool]      $ResponseReceived
    [string]    $VerifiedTenantId
    [string]    $TokenFingerprint
    [string]    $CredentialGeneration
}
