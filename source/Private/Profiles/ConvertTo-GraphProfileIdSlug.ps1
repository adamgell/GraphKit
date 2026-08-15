<#
    Private: derive a canonical ProfileId from a legacy tenant display name.

    The canonical form is ^[a-z0-9][a-z0-9-]{0,63}$, enforced by Test-GraphProfileId. This
    helper only proposes a candidate; the caller still validates, because a name that cannot
    yield a legal id must be reported to the operator rather than silently mangled into one.
#>

function ConvertTo-GraphProfileIdSlug {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $Name
    )

    if ([string]::IsNullOrWhiteSpace($Name)) {
        return ''
    }

    $slug = $Name.ToLowerInvariant()

    # Anything outside the canonical alphabet collapses to a single separator, so
    # "Contoso Ltd. (Prod)" and "Contoso  Ltd  Prod" do not become different ids.
    $slug = [regex]::Replace($slug, '[^a-z0-9]+', '-')
    $slug = $slug.Trim('-')

    if ($slug.Length -gt 64) {
        $slug = $slug.Substring(0, 64).TrimEnd('-')
    }

    # A leading digit is legal; a leading hyphen is not, and the trim above already
    # guarantees that. An all-punctuation name yields an empty string, which the caller
    # reports as unmappable.
    return $slug
}
