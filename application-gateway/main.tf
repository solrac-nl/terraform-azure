###############################################################################
# Locals
###############################################################################
locals {
  gateway_name           = "agw-${var.name}"
  gateway_ip_config_name = "gwip-config"
  public_feip_name       = "feip-public"
  private_feip_name      = "feip-private"

  is_waf = var.sku_name == "WAF_v2"

  https_frontends    = { for k, f in var.frontends : k => f if f.protocol == "Https" }
  redirect_frontends = { for k, f in local.https_frontends : k => f if f.redirect_http_to_https }

  # Every distinct listener port, plus 80 if any redirect listener is needed
  frontend_ports = toset(concat(
    [for f in values(var.frontends) : f.port],
    length(local.redirect_frontends) > 0 ? [80] : []
  ))

  # Distinct Key Vault certificate names referenced by HTTPS frontends
  certificate_names = toset([
    for f in values(local.https_frontends) : f.certificate_name if f.certificate_name != null
  ])

  # Probes inherit the host name from HTTP settings when the backend defines one
  probe_pick_host = {
    for k, b in var.backends :
    k => b.probe.host == null && (b.pick_host_name_from_backend_address || b.host_name != null)
  }
}

###############################################################################
# Resource group
###############################################################################
resource "azurerm_resource_group" "this" {
  name     = var.resource_group_name
  location = var.location
  tags     = var.tags
}

###############################################################################
# Networking
###############################################################################
resource "azurerm_virtual_network" "this" {
  name                = "vnet-${var.name}"
  location            = azurerm_resource_group.this.location
  resource_group_name = azurerm_resource_group.this.name
  address_space       = var.vnet_address_space
  tags                = var.tags
}

resource "azurerm_subnet" "appgw" {
  name                 = "snet-appgw"
  resource_group_name  = azurerm_resource_group.this.name
  virtual_network_name = azurerm_virtual_network.this.name
  address_prefixes     = [var.appgw_subnet_prefix]
  service_endpoints    = ["Microsoft.KeyVault"]
}

resource "azurerm_subnet" "additional" {
  for_each             = var.additional_subnets
  name                 = each.key
  resource_group_name  = azurerm_resource_group.this.name
  virtual_network_name = azurerm_virtual_network.this.name
  address_prefixes     = [each.value]
}

resource "azurerm_network_security_group" "appgw" {
  name                = "nsg-appgw-${var.name}"
  location            = azurerm_resource_group.this.location
  resource_group_name = azurerm_resource_group.this.name
  tags                = var.tags

  # Required for App Gateway v2 infrastructure
  security_rule {
    name                       = "AllowGatewayManager"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "65200-65535"
    source_address_prefix      = "GatewayManager"
    destination_address_prefix = "*"
  }

  security_rule {
    name                       = "AllowAzureLoadBalancer"
    priority                   = 110
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "*"
    source_port_range          = "*"
    destination_port_range     = "*"
    source_address_prefix      = "AzureLoadBalancer"
    destination_address_prefix = "*"
  }

  security_rule {
    name                       = "AllowListenerPorts"
    priority                   = 120
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_ranges    = [for p in local.frontend_ports : tostring(p)]
    source_address_prefix      = var.allowed_source_address_prefix
    destination_address_prefix = "*"
  }
}

resource "azurerm_subnet_network_security_group_association" "appgw" {
  subnet_id                 = azurerm_subnet.appgw.id
  network_security_group_id = azurerm_network_security_group.appgw.id
}

resource "azurerm_public_ip" "appgw" {
  name                = "pip-${local.gateway_name}"
  location            = azurerm_resource_group.this.location
  resource_group_name = azurerm_resource_group.this.name
  allocation_method   = "Static"
  sku                 = "Standard"
  zones               = var.zones
  domain_name_label   = lower(replace(local.gateway_name, "_", "-"))
  tags                = var.tags
}

###############################################################################
# Identity + Key Vault access
###############################################################################
data "azurerm_key_vault" "this" {
  name                = var.key_vault_name
  resource_group_name = var.key_vault_resource_group_name
}

resource "azurerm_user_assigned_identity" "appgw" {
  name                = "id-${local.gateway_name}"
  location            = azurerm_resource_group.this.location
  resource_group_name = azurerm_resource_group.this.name
  tags                = var.tags
}

resource "azurerm_role_assignment" "kv_secrets_user" {
  count                = var.key_vault_auth_mode == "rbac" ? 1 : 0
  scope                = data.azurerm_key_vault.this.id
  role_definition_name = "Key Vault Secrets User"
  principal_id         = azurerm_user_assigned_identity.appgw.principal_id
  principal_type       = "ServicePrincipal"
}

resource "azurerm_key_vault_access_policy" "appgw" {
  count                   = var.key_vault_auth_mode == "access_policy" ? 1 : 0
  key_vault_id            = data.azurerm_key_vault.this.id
  tenant_id               = data.azurerm_key_vault.this.tenant_id
  object_id               = azurerm_user_assigned_identity.appgw.principal_id
  secret_permissions      = ["Get"]
  certificate_permissions = ["Get"]
}

# Give the new permission time to propagate before the gateway reads the vault
resource "time_sleep" "wait_for_kv_permissions" {
  create_duration = "60s"

  depends_on = [
    azurerm_role_assignment.kv_secrets_user,
    azurerm_key_vault_access_policy.appgw,
  ]
}

###############################################################################
# WAF policy (only for WAF_v2)
###############################################################################
resource "azurerm_web_application_firewall_policy" "this" {
  count               = local.is_waf ? 1 : 0
  name                = "wafp-${var.name}"
  location            = azurerm_resource_group.this.location
  resource_group_name = azurerm_resource_group.this.name
  tags                = var.tags

  policy_settings {
    enabled            = true
    mode               = var.waf_mode
    request_body_check = true
  }

  managed_rules {
    managed_rule_set {
      type    = "OWASP"
      version = "3.2"
    }
  }
}

###############################################################################
# Application Gateway
###############################################################################
resource "azurerm_application_gateway" "this" {
  name                = local.gateway_name
  location            = azurerm_resource_group.this.location
  resource_group_name = azurerm_resource_group.this.name
  zones               = var.zones
  http2_enabled       = true
  tags                = var.tags

  firewall_policy_id                = local.is_waf ? azurerm_web_application_firewall_policy.this[0].id : null
  force_firewall_policy_association = local.is_waf

  sku {
    name = var.sku_name
    tier = var.sku_name
  }

  autoscale_configuration {
    min_capacity = var.autoscale_min_capacity
    max_capacity = var.autoscale_max_capacity
  }

  identity {
    type         = "UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.appgw.id]
  }

  gateway_ip_configuration {
    name      = local.gateway_ip_config_name
    subnet_id = azurerm_subnet.appgw.id
  }

  ssl_policy {
    policy_type = "Predefined"
    policy_name = var.ssl_policy_name
  }

  # ---------------------------------------------------------------- Frontend IPs
  frontend_ip_configuration {
    name                 = local.public_feip_name
    public_ip_address_id = azurerm_public_ip.appgw.id
  }

  dynamic "frontend_ip_configuration" {
    for_each = var.private_frontend_ip != null ? [var.private_frontend_ip] : []
    content {
      name                          = local.private_feip_name
      subnet_id                     = azurerm_subnet.appgw.id
      private_ip_address            = frontend_ip_configuration.value
      private_ip_address_allocation = "Static"
    }
  }

  # ---------------------------------------------------------------- Ports
  dynamic "frontend_port" {
    for_each = local.frontend_ports
    content {
      name = "port-${frontend_port.value}"
      port = frontend_port.value
    }
  }

  # ---------------------------------------------------------------- Certificates (Key Vault)
  # Versionless secret URI so the gateway picks up renewed certificates automatically.
  dynamic "ssl_certificate" {
    for_each = local.certificate_names
    content {
      name                = ssl_certificate.value
      key_vault_secret_id = "${data.azurerm_key_vault.this.vault_uri}secrets/${ssl_certificate.value}"
    }
  }

  # ---------------------------------------------------------------- Backends
  dynamic "backend_address_pool" {
    for_each = var.backends
    iterator = be
    content {
      name         = "pool-${be.key}"
      fqdns        = be.value.fqdns
      ip_addresses = be.value.ip_addresses
    }
  }

  dynamic "probe" {
    for_each = var.backends
    iterator = be
    content {
      name                                      = "probe-${be.key}"
      protocol                                  = be.value.protocol
      path                                      = be.value.probe.path
      interval                                  = be.value.probe.interval
      timeout                                   = be.value.probe.timeout
      unhealthy_threshold                       = be.value.probe.unhealthy_threshold
      pick_host_name_from_backend_http_settings = local.probe_pick_host[be.key]
      host                                      = local.probe_pick_host[be.key] ? null : coalesce(be.value.probe.host, "127.0.0.1")

      match {
        status_code = be.value.probe.match_status_codes
      }
    }
  }

  dynamic "backend_http_settings" {
    for_each = var.backends
    iterator = be
    content {
      name                                = "bhs-${be.key}"
      port                                = be.value.port
      protocol                            = be.value.protocol
      path                                = be.value.path
      request_timeout                     = be.value.request_timeout
      cookie_based_affinity               = be.value.cookie_based_affinity
      host_name                           = be.value.host_name
      pick_host_name_from_backend_address = be.value.pick_host_name_from_backend_address
      probe_name                          = "probe-${be.key}"
    }
  }

  # ---------------------------------------------------------------- Listeners
  dynamic "http_listener" {
    for_each = var.frontends
    iterator = fe
    content {
      name                           = "lst-${fe.key}"
      frontend_ip_configuration_name = fe.value.frontend_ip == "private" ? local.private_feip_name : local.public_feip_name
      frontend_port_name             = "port-${fe.value.port}"
      protocol                       = fe.value.protocol
      ssl_certificate_name           = fe.value.protocol == "Https" ? fe.value.certificate_name : null
      host_names                     = length(fe.value.host_names) > 0 ? fe.value.host_names : null
    }
  }

  # HTTP listeners on port 80 that only redirect to the HTTPS listener
  dynamic "http_listener" {
    for_each = local.redirect_frontends
    iterator = fe
    content {
      name                           = "lst-${fe.key}-http"
      frontend_ip_configuration_name = fe.value.frontend_ip == "private" ? local.private_feip_name : local.public_feip_name
      frontend_port_name             = "port-80"
      protocol                       = "Http"
      host_names                     = length(fe.value.host_names) > 0 ? fe.value.host_names : null
    }
  }

  dynamic "redirect_configuration" {
    for_each = local.redirect_frontends
    iterator = fe
    content {
      name                 = "redir-${fe.key}"
      redirect_type        = "Permanent"
      target_listener_name = "lst-${fe.key}"
      include_path         = true
      include_query_string = true
    }
  }

  # ---------------------------------------------------------------- Routing rules
  dynamic "request_routing_rule" {
    for_each = var.frontends
    iterator = fe
    content {
      name                       = "rule-${fe.key}"
      rule_type                  = "Basic"
      priority                   = fe.value.priority
      http_listener_name         = "lst-${fe.key}"
      backend_address_pool_name  = "pool-${fe.value.backend}"
      backend_http_settings_name = "bhs-${fe.value.backend}"
    }
  }

  dynamic "request_routing_rule" {
    for_each = local.redirect_frontends
    iterator = fe
    content {
      name                        = "rule-${fe.key}-redirect"
      rule_type                   = "Basic"
      priority                    = fe.value.priority + 10000
      http_listener_name          = "lst-${fe.key}-http"
      redirect_configuration_name = "redir-${fe.key}"
    }
  }

  lifecycle {
    precondition {
      condition     = alltrue([for f in values(var.frontends) : contains(keys(var.backends), f.backend)])
      error_message = "Every frontend.backend must match a key in var.backends."
    }
    precondition {
      condition     = alltrue([for f in values(local.https_frontends) : f.certificate_name != null])
      error_message = "Every HTTPS frontend must set certificate_name (the certificate's name in Key Vault)."
    }
    precondition {
      condition     = var.private_frontend_ip != null || alltrue([for f in values(var.frontends) : f.frontend_ip == "public"])
      error_message = "A frontend uses frontend_ip = \"private\" but private_frontend_ip is not set."
    }
    precondition {
      condition     = length(distinct([for f in values(var.frontends) : f.priority])) == length(var.frontends)
      error_message = "Frontend priorities must be unique."
    }
  }

  depends_on = [
    time_sleep.wait_for_kv_permissions,
    azurerm_subnet_network_security_group_association.appgw,
  ]
}
