<#
.SYNOPSIS
  Imports existing Azure resources into Terraform state (state only - Azure is not changed).

.DESCRIPTION
  Run from the Terraform folder after `terraform init`, logged in with `az login`.
  Resources already in state are skipped, so the script is safe to re-run.
  Works with Windows PowerShell 5.1 and PowerShell 7+.

.EXAMPLE
  .\import-existing.ps1 -SubscriptionId "0000..." -ResourceGroupName "rg-web-prod" -Name "web-prod" `
      -KeyVaultName "kv-shared-certs" -KeyVaultResourceGroupName "rg-shared-security"
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string]   $SubscriptionId,
    [Parameter(Mandatory)] [string]   $ResourceGroupName,
    [Parameter(Mandatory)] [string]   $Name,                       # same as var.name
    [Parameter(Mandatory)] [string]   $KeyVaultName,
    [Parameter(Mandatory)] [string]   $KeyVaultResourceGroupName,
    [ValidateSet('rbac', 'access_policy')]
                           [string]   $KeyVaultAuthMode = 'rbac',
                           [bool]     $IsWaf = $true,              # true if sku_name = WAF_v2
                           [string[]] $AdditionalSubnets = @('snet-backend')
)

$ErrorActionPreference = 'Stop'

# ---- Prerequisites ----------------------------------------------------------
foreach ($tool in 'terraform', 'az') {
    if (-not (Get-Command $tool -ErrorAction SilentlyContinue)) {
        throw "'$tool' was not found in PATH."
    }
}
if (-not (Test-Path '.terraform')) {
    throw "No .terraform folder found. Run 'terraform init' in this folder first."
}

# ---- Resource IDs (must match the naming in main.tf) ------------------------
$Gw     = "agw-$Name"
$RgId   = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName"
$Net    = "$RgId/providers/Microsoft.Network"
$Vnet   = "$Net/virtualNetworks/vnet-$Name"
$KvId   = "/subscriptions/$SubscriptionId/resourceGroups/$KeyVaultResourceGroupName/providers/Microsoft.KeyVault/vaults/$KeyVaultName"
$UaiId  = "$RgId/providers/Microsoft.ManagedIdentity/userAssignedIdentities/id-$Gw"

# ---- Helpers ----------------------------------------------------------------
# Windows PowerShell 5.1 (and 7.0-7.2) drop embedded double quotes when calling
# native programs, which breaks addresses like azurerm_subnet.additional["x"].
function ConvertTo-NativeArg([string] $Value) {
    $legacy = ($PSVersionTable.PSVersion -lt [version]'7.3') -or
              ((Get-Variable PSNativeCommandArgumentPassing -ValueOnly -ErrorAction SilentlyContinue) -eq 'Legacy')
    if ($legacy) { return $Value -replace '"', '\"' }
    return $Value
}

function Invoke-Native([scriptblock] $Command) {
    # Native tools write progress to stderr; don't let that abort the script.
    $prev = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try   { & $Command }
    finally { $ErrorActionPreference = $prev }
}

function Test-InState([string] $Address) {
    $arg = ConvertTo-NativeArg $Address
    Invoke-Native { terraform state show -no-color $arg *> $null }
    return ($LASTEXITCODE -eq 0)
}

$script:Results = [System.Collections.Generic.List[object]]::new()

function Import-TfResource([string] $Address, [string] $Id) {
    if (Test-InState $Address) {
        Write-Host "SKIP    $Address (already in state)" -ForegroundColor DarkGray
        $script:Results.Add([pscustomobject]@{ Address = $Address; Status = 'Skipped' })
        return
    }

    Write-Host "IMPORT  $Address" -ForegroundColor Cyan
    $arg = ConvertTo-NativeArg $Address
    Invoke-Native { terraform import -input=false -no-color $arg $Id }

    if ($LASTEXITCODE -eq 0) {
        $script:Results.Add([pscustomobject]@{ Address = $Address; Status = 'Imported' })
    } else {
        Write-Warning "Import failed for $Address (ID: $Id)"
        $script:Results.Add([pscustomobject]@{ Address = $Address; Status = 'FAILED' })
    }
}

# ---- Azure login ------------------------------------------------------------
Invoke-Native { az account set --subscription $SubscriptionId }
if ($LASTEXITCODE -ne 0) { throw "Could not select subscription $SubscriptionId. Run 'az login' first." }

# ---- Imports ----------------------------------------------------------------
Import-TfResource 'azurerm_resource_group.this'                             $RgId
Import-TfResource 'azurerm_virtual_network.this'                            $Vnet
Import-TfResource 'azurerm_subnet.appgw'                                    "$Vnet/subnets/snet-appgw"
Import-TfResource 'azurerm_network_security_group.appgw'                    "$Net/networkSecurityGroups/nsg-appgw-$Name"
Import-TfResource 'azurerm_subnet_network_security_group_association.appgw' "$Vnet/subnets/snet-appgw"
Import-TfResource 'azurerm_public_ip.appgw'                                 "$Net/publicIPAddresses/pip-$Gw"
Import-TfResource 'azurerm_user_assigned_identity.appgw'                    $UaiId

foreach ($subnet in $AdditionalSubnets) {
    Import-TfResource "azurerm_subnet.additional[""$subnet""]" "$Vnet/subnets/$subnet"
}

if ($IsWaf) {
    Import-TfResource 'azurerm_web_application_firewall_policy.this[0]' `
        "$Net/ApplicationGatewayWebApplicationFirewallPolicies/wafp-$Name"
}

# ---- Key Vault permission for the gateway identity --------------------------
$principalId = Invoke-Native { az identity show --ids $UaiId --query principalId -o tsv }
if ($LASTEXITCODE -ne 0 -or -not $principalId) {
    Write-Warning "Managed identity id-$Gw not found - skipping Key Vault permission import."
}
elseif ($KeyVaultAuthMode -eq 'rbac') {
    $json = Invoke-Native { az role assignment list --assignee $principalId --scope $KvId --role 'Key Vault Secrets User' -o json }
    $assignment = ($json | Out-String | ConvertFrom-Json) | Select-Object -First 1
    if ($assignment) {
        Import-TfResource 'azurerm_role_assignment.kv_secrets_user[0]' $assignment.id
    } else {
        Write-Host "NOTE    No existing role assignment found - Terraform will create it." -ForegroundColor Yellow
    }
}
else {
    $json = Invoke-Native { az keyvault show --name $KeyVaultName --resource-group $KeyVaultResourceGroupName -o json }
    $kv = $json | Out-String | ConvertFrom-Json
    $policy = $kv.properties.accessPolicies | Where-Object { $_.objectId -eq $principalId }
    if ($policy) {
        Import-TfResource 'azurerm_key_vault_access_policy.appgw[0]' "$KvId/objectId/$principalId"
    } else {
        Write-Host "NOTE    No existing access policy found - Terraform will create it." -ForegroundColor Yellow
    }
}

Import-TfResource 'azurerm_application_gateway.this' "$Net/applicationGateways/$Gw"

# ---- Summary ----------------------------------------------------------------
Write-Host ''
$script:Results | Format-Table -AutoSize

$failed = @($script:Results | Where-Object Status -eq 'FAILED')
if ($failed.Count -gt 0) {
    Write-Warning "$($failed.Count) import(s) failed. Check the resource names (see main.tf naming), fix, and re-run."
    exit 1
}
Write-Host "Done. Now run: terraform plan" -ForegroundColor Green
