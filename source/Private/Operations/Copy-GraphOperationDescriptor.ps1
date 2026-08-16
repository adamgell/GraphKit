<#
    Private: deep-copy an operation descriptor before it crosses the public boundary.

    Import-GraphOperationCatalog caches the catalog once per session and hands out the same
    hashtable instances every time. Returning those by reference means a caller who mutates a
    returned descriptor mutates the catalog for every subsequent operation in that runspace.

    Demonstrated, not theorised:

        $d = Get-GraphOperation -Type ManagedDevice -Operation List
        $d.CredentialPolicy = 'None'
        (Get-GraphOperation -Type ManagedDevice -Operation List).CredentialPolicy   # -> None

    The blast radius is bounded - the sender re-checks credential policy per hop and module
    state is per-runspace, so the realistic worst case is a self-inflicted downgrade in the
    caller's own session rather than a cross-tenant leak. It is still wrong: load-time
    validation is what makes a descriptor trustworthy, and an object that can be edited
    afterwards has quietly escaped it.

    Only the PUBLIC command copies. Internal callers resolve descriptors on every request and
    genuinely want the cached instance; copying there would add allocation to the hot path to
    protect code that already holds the original.

    A copy must be FAITHFUL, not merely isolated. The first version of this used a recursive
    scriptblock invoked with '&', and a single-element array returned that way is unrolled by
    the pipeline - so RequiredPermissions, which is an Object[] of one hashtable, came back as
    a bare hashtable and $descriptor.RequiredPermissions[0].Value became $null. Isolation tests
    still passed; only an assertion on the descriptor's own values caught it. Hence the
    explicit ,@() below and a test that reads a value back through an array index.
#>

function Copy-GraphOperationDescriptorValue {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        $Value
    )

    if ($null -eq $Value) { return $null }

    if ($Value -is [System.Collections.IDictionary]) {
        $nested = @{}
        foreach ($key in $Value.Keys) {
            $nested[$key] = Copy-GraphOperationDescriptorValue -Value $Value[$key]
        }
        return $nested
    }

    # Strings and value types are immutable, and a string is IEnumerable - so it must be
    # returned before the array branch or it would be copied character by character.
    if ($Value -is [string] -or $Value -is [ValueType]) { return $Value }

    if ($Value -is [System.Collections.IEnumerable]) {
        $items = @(foreach ($item in $Value) { Copy-GraphOperationDescriptorValue -Value $item })
        # The comma is load-bearing: without it a one-element array is unrolled on return and
        # the copy silently changes the descriptor's shape.
        return , $items
    }

    return $Value
}

function Copy-GraphOperationDescriptor {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [AllowNull()]
        $Descriptor
    )

    process {
        if ($null -eq $Descriptor) { return $null }
        return (Copy-GraphOperationDescriptorValue -Value $Descriptor)
    }
}
