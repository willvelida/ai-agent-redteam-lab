#!/usr/bin/env pwsh
# SPDX-License-Identifier: MIT
#Requires -Version 7.4

<#
.SYNOPSIS
    One-time, human-run bootstrap for the AI Agent Red-Team Lab deployment pipeline.
.DESCRIPTION
    Creates, per environment (vulnerable, hardened):
      - a resource group rg-ailab3-<env>
      - a user-assigned managed identity for GitHub Actions (OIDC, no secrets)
      - a federated credential bound to the repo's GitHub environment
      - a Contributor role assignment scoped to that resource group only
    Optionally creates the GitHub environments and sets the IDs as environment secrets.

    Run this yourself with Owner (or User Access Administrator + Contributor) on the subscription.
    The CI pipeline never gets these rights. That separation is the point.
.PARAMETER SubscriptionId
    Target subscription. Must be a subscription you own and are authorised to test (see ETHICS.md).
.PARAMETER GitHubRepo
    owner/repo that is allowed to request tokens.
.PARAMETER Location
    Azure region for the resource groups and identities.
.PARAMETER Environments
    Lab environments. Each gets its own resource group and identity.
.PARAMETER BootstrapResourceGroup
    Holds the deploy identities. Deliberately outside the rg-ailab3-* pattern so destroy.yml can never touch it.
.PARAMETER ConfigureGitHub
    Also create the GitHub environments and set AZURE_CLIENT_ID / AZURE_TENANT_ID / AZURE_SUBSCRIPTION_ID secrets via gh.
.PARAMETER BudgetAlertEmail
    If set, deploys the subscription budget (infra/modules/budget.bicep) with alerts to this address.
    Kept out of the pipeline so a compromised deploy identity can't silence its own cost alarm.
.PARAMETER BudgetAmount
    Monthly budget in the subscription billing currency.
.EXAMPLE
    ./infra/bootstrap/bootstrap.ps1 -SubscriptionId <id> -ConfigureGitHub
.NOTES
    Idempotent: safe to re-run.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$SubscriptionId,

    [Parameter(Mandatory = $false)]
    [string]$GitHubRepo = 'willvelida/ai-agent-redteam-lab',

    [Parameter(Mandatory = $false)]
    [string]$Location = 'australiaeast',

    [Parameter(Mandatory = $false)]
    [string[]]$Environments = @('vulnerable', 'hardened'),

    [Parameter(Mandatory = $false)]
    [string]$BootstrapResourceGroup = 'rg-redteamlab-bootstrap',

    [Parameter(Mandatory = $false)]
    [switch]$ConfigureGitHub,

    [Parameter(Mandatory = $false)]
    [string]$BudgetAlertEmail,

    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 100000)]
    [int]$BudgetAmount = 80
)

$ErrorActionPreference = 'Stop'

#region Functions
function Invoke-Az {
    param([Parameter(Mandatory)][string[]]$Arguments)
    $result = & az @Arguments --only-show-errors -o json
    if ($LASTEXITCODE -ne 0) { throw "az $($Arguments -join ' ') failed with exit code $LASTEXITCODE" }
    if ($result) { return ($result | Out-String | ConvertFrom-Json) }
}

function Invoke-Gh {
    param([Parameter(Mandatory)][string[]]$Arguments)
    & gh @Arguments
    if ($LASTEXITCODE -ne 0) { throw "gh $($Arguments[0..1] -join ' ') failed with exit code $LASTEXITCODE" }
}
#endregion Functions

#region Main Execution
if ($MyInvocation.InvocationName -ne '.') {

    # Show exactly what will change before changing anything. Scope errors are the main risk here.
    Invoke-Az @('account', 'set', '--subscription', $SubscriptionId) | Out-Null
    $account = Invoke-Az @('account', 'show')
    Write-Host "Subscription : $($account.name)"
    Write-Host "Tenant       : $($account.tenantId)"
    Write-Host "Repo         : $GitHubRepo"
    Write-Host "Environments : $($Environments -join ', ')"
    $answer = Read-Host 'Is this a subscription you own and are authorised to use for the lab? (yes/no)'
    if ($answer -ne 'yes') { throw 'Aborted by user.' }

    $tags = @('purpose=ai-redteam-lab', "repo=$GitHubRepo")

    Invoke-Az (@('group', 'create', '--name', $BootstrapResourceGroup, '--location', $Location, '--tags') + $tags) | Out-Null

    # Ask GitHub for the exact sub prefix it will send. Repos may use immutable subjects
    # (owner@<id>/repo@<id>), which a hand-built "repo:owner/name" string would never match.
    $subPrefix = "repo:$GitHubRepo"
    $oidcSub = & gh api "repos/$GitHubRepo/actions/oidc/customization/sub" 2>$null | ConvertFrom-Json
    if ($LASTEXITCODE -eq 0 -and $oidcSub.sub_claim_prefix) { $subPrefix = $oidcSub.sub_claim_prefix }
    Write-Host "OIDC sub prefix: $subPrefix"

    foreach ($envName in $Environments) {
        $rgName = "rg-ailab3-$envName"
        $identityName = "id-ailab3-gh-$envName"

        $rg = Invoke-Az (@('group', 'create', '--name', $rgName, '--location', $Location, '--tags') + $tags + @("env=$envName"))

        $identity = Invoke-Az @('identity', 'create', '--name', $identityName, '--resource-group', $BootstrapResourceGroup, '--location', $Location)

        $subject = "${subPrefix}:environment:$envName"

        Invoke-Az @(
            'identity', 'federated-credential', 'create',
            '--name', "github-$envName",
            '--identity-name', $identityName,
            '--resource-group', $BootstrapResourceGroup,
            '--issuer', 'https://token.actions.githubusercontent.com',
            '--subject', $subject,
            '--audiences', 'api://AzureADTokenExchange'
        ) | Out-Null

        $roleScope = $rg.id

        Invoke-Az @(
            'role', 'assignment', 'create',
            '--assignee-object-id', $identity.principalId,
            '--assignee-principal-type', 'ServicePrincipal',
            '--role', 'Contributor',
            '--scope', $roleScope
        ) | Out-Null

        # Same identity and scope, separate trust path: <env>-destroy has no reviewer so the nightly schedule can run.
        $destroyEnv = "$envName-destroy"
        Invoke-Az @(
            'identity', 'federated-credential', 'create',
            '--name', "github-$destroyEnv",
            '--identity-name', $identityName,
            '--resource-group', $BootstrapResourceGroup,
            '--issuer', 'https://token.actions.githubusercontent.com',
            '--subject', "${subPrefix}:environment:$destroyEnv",
            '--audiences', 'api://AzureADTokenExchange'
        ) | Out-Null

        Write-Host "[$envName] rg=$rgName identity=$identityName clientId=$($identity.clientId)"

        if ($ConfigureGitHub) {
            foreach ($ghEnv in @($envName, $destroyEnv)) {
                # Create only if missing, so re-runs never reset reviewers or branch policies.
                & gh api "repos/$GitHubRepo/environments/$ghEnv" --silent 2>$null
                if ($LASTEXITCODE -ne 0) {
                    Invoke-Gh @('api', '--method', 'PUT', "repos/$GitHubRepo/environments/$ghEnv", '--silent')
                }
                Invoke-Gh @('secret', 'set', 'AZURE_CLIENT_ID', '--repo', $GitHubRepo, '--env', $ghEnv, '--body', $identity.clientId)
                Invoke-Gh @('secret', 'set', 'AZURE_TENANT_ID', '--repo', $GitHubRepo, '--env', $ghEnv, '--body', $account.tenantId)
                Invoke-Gh @('secret', 'set', 'AZURE_SUBSCRIPTION_ID', '--repo', $GitHubRepo, '--env', $ghEnv, '--body', $SubscriptionId)
            }
        }
    }

    if ($BudgetAlertEmail) {
        $budgetTemplate = Join-Path $PSScriptRoot '..' 'modules' 'budget.bicep'
        Invoke-Az @(
            'deployment', 'sub', 'create',
            '--name', 'ailab3-budget',
            '--location', $Location,
            '--template-file', $budgetTemplate,
            '--parameters', "amount=$BudgetAmount", "alertEmail=$BudgetAlertEmail"
        ) | Out-Null
        Write-Host "Budget deployed: $BudgetAmount/month (subscription billing currency)."
    }

    Write-Host 'Bootstrap complete. Next: protect the GitHub environments and branch-protect main.'
}
#endregion Main Execution
