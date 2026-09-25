packer {
  required_plugins {
    amazon = { source = "github.com/hashicorp/amazon", version = ">= 1.3.9" }
  }
}
variable "aws_region" { type = string }
variable "release_id" { type = string }
variable "binary_directory" { type = string }
variable "parent_sha256" { type = string }
variable "source_runtime_ami" { type = string }
variable "eif_sha256" { type = string }
source "amazon-ebs" "parent_only" {
  region               = var.aws_region
  source_ami           = var.source_runtime_ami
  instance_type        = "m6i.xlarge"
  ssh_username         = "ec2-user"
  ssh_interface        = "session_manager"
  iam_instance_profile = "layrs-opening-epoch-packer-ssm"
  ami_name             = "layrs-opening-epoch-${var.release_id}"
  ami_description      = "Layrs bounded immutable archive reader; unchanged measured enclave"
  ena_support          = true
  imds_support         = "v2.0"
  launch_block_device_mappings {
    device_name           = "/dev/xvda"
    encrypted             = true
    delete_on_termination = true
  }
  tags = { Name = "layrs-opening-epoch-${var.release_id}", Project = "Layrs", Environment = "opening-epoch", ProductionAccess = "denied", WriterEnabled = "false", ManagedBy = "Packer" }
}
build {
  sources = ["source.amazon-ebs.parent_only"]
  provisioner "file" {
    source      = "${var.binary_directory}/layrs-direct-parent"
    destination = "/tmp/layrs-direct-parent"
  }
  provisioner "file" {
    source      = "${path.root}/layrs-opening-parent.service"
    destination = "/tmp/layrs-opening-parent.service"
  }
  provisioner "shell" {
    inline = [
      "set -eu",
      "sudo systemctl stop layrs-opening-parent.service layrs-opening-enclave.service",
      "sudo test ! -f /etc/layrs-opening/direct-runtime.env",
      "test \"$(sudo find /var/lib/layrs-opening-artifacts -type f | wc -l)\" = 0",
      "test \"$(sudo sha256sum /opt/layrs-opening/layrs-direct-execution.eif | cut -d ' ' -f1)\" = '${var.eif_sha256}'",
      "test \"$(sha256sum /tmp/layrs-direct-parent | cut -d ' ' -f1)\" = '${var.parent_sha256}'",
      "sudo install -m 0755 /tmp/layrs-direct-parent /opt/layrs-opening/layrs-direct-parent",
      "test \"$(sha256sum /opt/layrs-opening/layrs-direct-parent | cut -d ' ' -f1)\" = '${var.parent_sha256}'",
      "unit_path=$(systemctl show -p FragmentPath --value layrs-opening-parent.service)",
      "test -n \"$unit_path\"",
      "sudo install -m 0644 /tmp/layrs-opening-parent.service \"$unit_path\"",
      "sudo systemctl daemon-reload",
      "systemctl cat layrs-opening-parent.service | grep -q 'ExecStopPost=+/bin/sh'",
      "echo PARENT_ONLY_IMAGE_PRESERVES_EXACT_MEASURED_EIF_WITHOUT_RUNTIME_SECRETS"
    ]
  }
}
