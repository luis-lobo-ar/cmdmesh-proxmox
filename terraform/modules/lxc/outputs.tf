output "id" {
  description = "Terraform resource ID."
  value       = proxmox_virtual_environment_container.this.id
}

output "vm_id" {
  description = "Proxmox VM ID."
  value       = proxmox_virtual_environment_container.this.vm_id
}
