#!/usr/bin/env bash
# Imports existing Azure resources into Terraform state (state only - Azure is not changed).
# Run from the Terraform folder after `terraform init`, logged in with `az login`.
# Resources already in state are skipped, so the script is safe to re-run.
set -euo pipefail

# ---- Set these to match terraform.tfvars ------------------------------------
SUB="00000000-0000-0000-0000-000000000000"
RG="rg-web-prod"
NAME="web-prod"
KV_NAME="kv-shared-certs"
KV_RG="rg-shared-security"
KV_AUTH_MODE="rbac"              # rbac | access_policy
IS_WAF="true"                    # true if sku_name = WAF_v2
ADDITIONAL_SUBNETS=("snet-backend")
# -----------------------------------------------------------------------------

GW="agw-${NAME}"
RG_ID="/subscriptions/${SUB}/resourceGroups/${RG}"
NET="${RG_ID}/providers/Microsoft.Network"
VNET="${NET}/virtualNetworks/vnet-${NAME}"
KV_ID="/subscriptions/${SUB}/resourceGroups/${KV_RG}/providers/Microsoft.KeyVault/vaults/${KV_NAME}"
UAI_ID="${RG_ID}/providers/Microsoft.ManagedIdentity/userAssignedIdentities/id-${GW}"

az account set --subscription "$SUB"

imp() {
  local addr="$1" id="$2"
  if terraform state show "$addr" >/dev/null 2>&1; then
    echo "SKIP  $addr (already in state)"
  else
    echo "IMPORT $addr"
    terraform import -input=false "$addr" "$id"
  fi
}

imp azurerm_resource_group.this                              "$RG_ID"
imp azurerm_virtual_network.this                             "$VNET"
imp azurerm_subnet.appgw                                     "${VNET}/subnets/snet-appgw"
imp azurerm_network_security_group.appgw                     "${NET}/networkSecurityGroups/nsg-appgw-${NAME}"
imp azurerm_subnet_network_security_group_association.appgw  "${VNET}/subnets/snet-appgw"
imp azurerm_public_ip.appgw                                  "${NET}/publicIPAddresses/pip-${GW}"
imp azurerm_user_assigned_identity.appgw                     "$UAI_ID"

for s in "${ADDITIONAL_SUBNETS[@]}"; do
  imp "azurerm_subnet.additional[\"${s}\"]" "${VNET}/subnets/${s}"
done

if [[ "$IS_WAF" == "true" ]]; then
  imp 'azurerm_web_application_firewall_policy.this[0]' \
      "${NET}/ApplicationGatewayWebApplicationFirewallPolicies/wafp-${NAME}"
fi

# Key Vault permission for the gateway identity (looked up, imported if it exists)
PRINCIPAL_ID=$(az identity show --ids "$UAI_ID" --query principalId -o tsv)

if [[ "$KV_AUTH_MODE" == "rbac" ]]; then
  RA_ID=$(az role assignment list --assignee "$PRINCIPAL_ID" --scope "$KV_ID" \
          --role "Key Vault Secrets User" --query "[0].id" -o tsv)
  if [[ -n "$RA_ID" ]]; then
    imp 'azurerm_role_assignment.kv_secrets_user[0]' "$RA_ID"
  else
    echo "NOTE  no existing role assignment found - Terraform will create it"
  fi
else
  HAS_POLICY=$(az keyvault show --name "$KV_NAME" --resource-group "$KV_RG" \
               --query "length(properties.accessPolicies[?objectId=='${PRINCIPAL_ID}'])" -o tsv)
  if [[ "$HAS_POLICY" != "0" ]]; then
    imp 'azurerm_key_vault_access_policy.appgw[0]' "${KV_ID}/objectId/${PRINCIPAL_ID}"
  else
    echo "NOTE  no existing access policy found - Terraform will create it"
  fi
fi

imp azurerm_application_gateway.this "${NET}/applicationGateways/${GW}"

echo
echo "Done. Now run: terraform plan"
