###############################################################################
# General
###############################################################################
variable "subscription_id" {
  description = "Azure subscription ID to deploy into."
  type        = string
}

variable "name" {
  description = "Base name used to build resource names (e.g. 'web-prod')."
  type        = string
}

variable "location" {
  description = "Azure region."
  type        = string
}

variable "resource_group_name" {
  description = "Name of the resource group to create."
  type        = string
}

variable "tags" {
  description = "Tags applied to all resources."
  type        = map(string)
  default     = {}
}

###############################################################################
# Networking
###############################################################################
variable "vnet_address_space" {
  description = "Address space for the virtual network."
  type        = list(string)
  default     = ["10.10.0.0/16"]
}

variable "appgw_subnet_prefix" {
  description = "CIDR for the dedicated Application Gateway subnet (/24 recommended for v2)."
  type        = string
  default     = "10.10.0.0/24"
}

variable "additional_subnets" {
  description = "Extra subnets to create in the VNet (e.g. for backend workloads). Map of name => CIDR."
  type        = map(string)
  default = {
    "snet-backend" = "10.10.1.0/24"
  }
}

variable "allowed_source_address_prefix" {
  description = "Source allowed to reach the listener ports through the NSG ('Internet', a service tag, or a CIDR)."
  type        = string
  default     = "Internet"
}

variable "private_frontend_ip" {
  description = "Optional static private IP (inside the App Gateway subnet) for a private frontend. Null disables it."
  type        = string
  default     = null
}

variable "zones" {
  description = "Availability zones for the gateway and public IP. Use [] in regions without zones."
  type        = list(string)
  default     = ["1", "2", "3"]
}

###############################################################################
# Application Gateway
###############################################################################
variable "sku_name" {
  description = "Application Gateway SKU: Standard_v2 or WAF_v2."
  type        = string
  default     = "WAF_v2"

  validation {
    condition     = contains(["Standard_v2", "WAF_v2"], var.sku_name)
    error_message = "sku_name must be Standard_v2 or WAF_v2."
  }
}

variable "autoscale_min_capacity" {
  type    = number
  default = 1
}

variable "autoscale_max_capacity" {
  type    = number
  default = 5
}

variable "ssl_policy_name" {
  description = "Predefined TLS policy for HTTPS listeners."
  type        = string
  default     = "AppGwSslPolicy20220101"
}

variable "waf_mode" {
  description = "WAF mode when sku_name is WAF_v2: Detection or Prevention."
  type        = string
  default     = "Prevention"
}

###############################################################################
# Key Vault (existing)
###############################################################################
variable "key_vault_name" {
  description = "Name of the existing Key Vault holding the TLS certificates."
  type        = string
}

variable "key_vault_resource_group_name" {
  description = "Resource group of the existing Key Vault."
  type        = string
}

variable "key_vault_auth_mode" {
  description = "How the Key Vault authorizes access: 'rbac' or 'access_policy'."
  type        = string
  default     = "rbac"

  validation {
    condition     = contains(["rbac", "access_policy"], var.key_vault_auth_mode)
    error_message = "key_vault_auth_mode must be 'rbac' or 'access_policy'."
  }
}

###############################################################################
# Backends - one pool + HTTP settings + health probe is created per entry
###############################################################################
variable "backends" {
  description = "Map of backends. Key is used in resource names and referenced by frontends."
  type = map(object({
    fqdns                               = optional(list(string), [])
    ip_addresses                        = optional(list(string), [])
    port                                = optional(number, 443)
    protocol                            = optional(string, "Https")
    host_name                           = optional(string)
    pick_host_name_from_backend_address = optional(bool, false)
    path                                = optional(string)
    request_timeout                     = optional(number, 30)
    cookie_based_affinity               = optional(string, "Disabled")
    probe = optional(object({
      path                = optional(string, "/")
      host                = optional(string)
      interval            = optional(number, 30)
      timeout             = optional(number, 30)
      unhealthy_threshold = optional(number, 3)
      match_status_codes  = optional(list(string), ["200-399"])
    }), {})
  }))

  validation {
    condition     = alltrue([for b in values(var.backends) : contains(["Http", "Https"], b.protocol)])
    error_message = "Backend protocol must be 'Http' or 'Https'."
  }

  validation {
    condition     = alltrue([for b in values(var.backends) : !(b.host_name != null && b.pick_host_name_from_backend_address)])
    error_message = "A backend cannot set both host_name and pick_host_name_from_backend_address."
  }
}

###############################################################################
# Frontends - one listener + routing rule (+ optional HTTP->HTTPS redirect) per entry
###############################################################################
variable "frontends" {
  description = "Map of frontends (listeners). Each routes to a backend by key."
  type = map(object({
    backend                = string
    priority               = number
    host_names             = optional(list(string), [])
    frontend_ip            = optional(string, "public")
    port                   = optional(number, 443)
    protocol               = optional(string, "Https")
    certificate_name       = optional(string)
    redirect_http_to_https = optional(bool, true)
  }))

  validation {
    condition     = alltrue([for f in values(var.frontends) : contains(["Http", "Https"], f.protocol)])
    error_message = "Frontend protocol must be 'Http' or 'Https'."
  }

  validation {
    condition     = alltrue([for f in values(var.frontends) : contains(["public", "private"], f.frontend_ip)])
    error_message = "frontend_ip must be 'public' or 'private'."
  }

  validation {
    condition     = alltrue([for f in values(var.frontends) : f.priority >= 1 && f.priority <= 9999])
    error_message = "Frontend priority must be between 1 and 9999 (10000+ is reserved for generated redirect rules)."
  }
}
