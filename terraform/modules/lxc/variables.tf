variable "node_name" {
  type        = string
  description = "Proxmox node name."
}

variable "template_file_id" {
  type        = string
  description = "Template file ID for the container OS."
}

variable "vm_id" {
  type        = number
  description = "Optional fixed VM ID."
  default     = null
  validation {
    condition     = var.vm_id == null ? true : var.vm_id >= 100 && var.vm_id <= 999999999 && floor(var.vm_id) == var.vm_id
    error_message = "vm_id must be an integer from 100 through 999999999."
  }
}

variable "start_on_boot" {
  type        = bool
  description = "Start container on host boot."
  default     = true
}

variable "started" {
  type        = bool
  description = "Ensure container is started after apply."
  default     = true
}

variable "unprivileged" {
  type        = bool
  description = "Run container as unprivileged."
  default     = true
}

variable "description" {
  type        = string
  description = "Container description."
  default     = ""
}

variable "hostname" {
  type        = string
  description = "Container hostname."
}

variable "cpu_cores" {
  type        = number
  description = "CPU cores."
  default     = 2
  validation {
    condition     = var.cpu_cores >= 1 && floor(var.cpu_cores) == var.cpu_cores
    error_message = "cpu_cores must be a positive integer."
  }
}

variable "cpu_units" {
  type        = number
  description = "CPU units."
  default     = 1024
}

variable "memory_dedicated" {
  type        = number
  description = "Dedicated memory in MiB."
  default     = 2048
  validation {
    condition     = var.memory_dedicated >= 64 && floor(var.memory_dedicated) == var.memory_dedicated
    error_message = "memory_dedicated must be an integer of at least 64 MiB."
  }
}

variable "memory_swap" {
  type        = number
  description = "Swap memory in MiB."
  default     = 512
  validation {
    condition     = var.memory_swap >= 0 && floor(var.memory_swap) == var.memory_swap
    error_message = "memory_swap must be a nonnegative integer."
  }
}

variable "disk_datastore_id" {
  type        = string
  description = "Datastore for root disk."
  validation {
    condition     = can(regex("^[A-Za-z0-9][A-Za-z0-9_.-]*$", var.disk_datastore_id))
    error_message = "disk_datastore_id must be an explicit Proxmox datastore identifier."
  }
}

variable "disk_size_gb" {
  type        = number
  description = "Root disk size in GiB."
  default     = 16
  validation {
    condition     = var.disk_size_gb > 0 && floor(var.disk_size_gb) == var.disk_size_gb
    error_message = "disk_size_gb must be a positive integer."
  }
}

variable "network_bridge" {
  type        = string
  description = "Bridge for network interface."
  validation {
    condition     = can(regex("^[A-Za-z0-9][A-Za-z0-9_.-]*$", var.network_bridge))
    error_message = "network_bridge must be an explicit bridge identifier."
  }
}

variable "mac_address" {
  type        = string
  description = "Optional fixed MAC address for the primary network interface."
  default     = null
}

variable "network_vlan_id" {
  type        = number
  description = "Optional VLAN ID."
  default     = null
  validation {
    condition     = var.network_vlan_id == null ? true : var.network_vlan_id >= 1 && var.network_vlan_id <= 4094 && floor(var.network_vlan_id) == var.network_vlan_id
    error_message = "network_vlan_id must be null or an integer from 1 through 4094."
  }
}

variable "ipv4_address" {
  type        = string
  description = "IPv4 address/CIDR or dhcp."
  default     = "dhcp"
}

variable "ipv4_gateway" {
  type        = string
  description = "IPv4 gateway."
  default     = null
}

variable "dns_domain" {
  type        = string
  description = "DNS search domain."
  default     = ""
}

variable "dns_servers" {
  type        = list(string)
  description = "DNS servers."
  default     = []
}

variable "tags" {
  type        = list(string)
  description = "Resource tags."
  default     = []
}

variable "ssh_authorized_keys" {
  type        = list(string)
  description = "SSH authorized keys injected at initialization time."
  default     = []
}

variable "device_passthroughs" {
  type = list(object({
    path       = string
    uid        = optional(number)
    gid        = optional(number)
    mode       = optional(string)
    deny_write = optional(bool)
  }))
  description = "Optional host devices passed through into the container."
  default     = []
  validation {
    condition     = alltrue([for device in var.device_passthroughs : can(regex("^/dev/[A-Za-z0-9_./-]+$", device.path))])
    error_message = "Explicit passthrough paths must be under /dev."
  }
}

variable "nesting" {
  type        = bool
  description = "Enable container nesting only when explicitly required."
  default     = false
}
