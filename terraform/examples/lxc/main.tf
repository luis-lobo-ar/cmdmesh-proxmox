terraform {
  required_version = ">= 1.6, < 2.0"
  required_providers {
    proxmox = {
      source  = "bpg/proxmox"
      version = "0.97.0"
    }
  }
}

# Supply PROXMOX_VE_API_TOKEN through the environment. Never commit it.
provider "proxmox" {
  endpoint = "https://pve.example.invalid:8006/"
  insecure = false
}

module "demo" {
  source            = "../../modules/lxc"
  node_name         = "node-a"
  vm_id             = 101
  hostname          = "demo"
  template_file_id  = "templates:vztmpl/debian-demo.tar.zst"
  disk_datastore_id = "containers"
  network_bridge    = "vmbr0"
  started           = false
  nesting           = false
  ipv4_address      = "192.0.2.10/24"
  ipv4_gateway      = "192.0.2.1"
  dns_domain        = "example.invalid"
  dns_servers       = ["192.0.2.53"]
}
