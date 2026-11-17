locals {
  operating_system_type = can(regex("ubuntu", lower(var.template_file_id))) ? "ubuntu" : can(regex("debian", lower(var.template_file_id))) ? "debian" : "unmanaged"
}

resource "proxmox_virtual_environment_container" "this" {
  node_name     = var.node_name
  vm_id         = var.vm_id
  description   = var.description
  tags          = var.tags
  start_on_boot = var.start_on_boot
  started       = var.started
  unprivileged  = var.unprivileged

  cpu {
    cores = var.cpu_cores
    units = var.cpu_units
  }

  memory {
    dedicated = var.memory_dedicated
    swap      = var.memory_swap
  }

  disk {
    datastore_id = var.disk_datastore_id
    size         = var.disk_size_gb
  }

  operating_system {
    template_file_id = var.template_file_id
    type             = local.operating_system_type
  }

  features {
    nesting = var.nesting
  }

  dynamic "device_passthrough" {
    for_each = var.device_passthroughs
    content {
      path       = device_passthrough.value.path
      uid        = try(device_passthrough.value.uid, null)
      gid        = try(device_passthrough.value.gid, null)
      mode       = try(device_passthrough.value.mode, null)
      deny_write = try(device_passthrough.value.deny_write, null)
    }
  }

  network_interface {
    name        = "eth0"
    bridge      = var.network_bridge
    mac_address = var.mac_address
    vlan_id     = var.network_vlan_id
  }

  initialization {
    hostname = var.hostname

    dynamic "user_account" {
      for_each = length(var.ssh_authorized_keys) > 0 ? [1] : []
      content {
        keys = var.ssh_authorized_keys
      }
    }

    dns {
      domain  = var.dns_domain
      servers = var.dns_servers
    }

    ip_config {
      ipv4 {
        address = var.ipv4_address
        gateway = var.ipv4_gateway
      }
    }
  }
}
