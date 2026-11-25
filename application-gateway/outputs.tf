output "application_gateway_id" {
  value = azurerm_application_gateway.this.id
}

output "public_ip_address" {
  value = azurerm_public_ip.appgw.ip_address
}

output "public_fqdn" {
  value = azurerm_public_ip.appgw.fqdn
}

output "vnet_id" {
  value = azurerm_virtual_network.this.id
}

output "subnet_ids" {
  value = merge(
    { "snet-appgw" = azurerm_subnet.appgw.id },
    { for k, s in azurerm_subnet.additional : k => s.id }
  )
}

output "appgw_identity_principal_id" {
  value = azurerm_user_assigned_identity.appgw.principal_id
}

output "listeners" {
  description = "Frontend key => listener details."
  value = {
    for k, f in var.frontends : k => {
      listener   = "lst-${k}"
      port       = f.port
      protocol   = f.protocol
      host_names = f.host_names
      backend    = f.backend
    }
  }
}

output "backend_pools" {
  value = { for k, b in var.backends : k => "pool-${k}" }
}
