<#
    Invoke-Build integration for the canonical tested-release proof.

    Capture runs before Pester and deletes stale proof/result material. Finalize runs only
    after Pester and coverage gates, rechecks the captured candidate and complete result,
    then writes tested-release-proof.json. The scripts hold the behavior so the exact same
    boundary is exercised by focused subprocess tests.
#>

task Capture_Tested_Release_Proof_Candidate {
    & (Join-Path $BuildRoot 'scripts/New-GraphKitTestedReleaseProof.ps1') `
        -Stage Capture `
        -RepositoryRoot $BuildRoot
}

task Record_Tested_Release_Proof {
    & (Join-Path $BuildRoot 'scripts/New-GraphKitTestedReleaseProof.ps1') `
        -Stage Finalize `
        -RepositoryRoot $BuildRoot
}
