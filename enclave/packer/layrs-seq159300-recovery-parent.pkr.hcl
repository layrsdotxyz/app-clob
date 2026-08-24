packer {
  required_plugins {
    amazon = { source = "github.com/hashicorp/amazon", version = "= 1.3.9" }
  }
}

// This template is intentionally not a standalone entrypoint. The recovery
// wrapper verifies the on-disk parent/EIF/PCR0 bytes and the reviewed Phase2
// template before invoking Packer.
variable "aws_region" {
  type = string
  validation {
    condition     = var.aws_region == "us-east-1"
    error_message = "The recovery AMI is bound to us-east-1."
  }
}
variable "source_ami_id" {
  type = string
  validation {
    condition     = can(regex("^ami-[0-9a-f]{8,17}$", var.source_ami_id))
    error_message = "An exact pinned source AMI ID is required."
  }
}
variable "source_ami_owner" {
  type = string
  validation {
    condition     = var.source_ami_owner == "137112412989"
    error_message = "The source AMI owner must be the official AL2023 owner."
  }
}
variable "build_subnet_id" {
  type = string
  validation {
    condition     = can(regex("^subnet-[0-9a-f]{8,17}$", var.build_subnet_id))
    error_message = "An exact recovery build subnet is required."
  }
}
variable "build_security_group_id" {
  type = string
  validation {
    condition     = can(regex("^sg-[0-9a-f]{8,17}$", var.build_security_group_id))
    error_message = "An exact recovery build security group is required."
  }
}
variable "build_instance_profile" {
  type = string
  validation {
    condition     = can(regex("^layrs-seq159300-recovery-[A-Za-z0-9+=,.@_-]+$", var.build_instance_profile))
    error_message = "The build instance profile must be recovery-specific."
  }
}
variable "parent_sha384" {
  type = string
  validation {
    condition     = var.parent_sha384 == "d9506bf11627b04bd5d220e18e78584cd5e649952fe380309346d9c6bbecd511eb318cdcdee6a1d0db989d581a742db1"
    error_message = "The parent binary must match the independently preserved f282 bytes."
  }
}
variable "phase2_template_sha384" {
  type = string
  validation {
    condition     = can(regex("^[0-9a-f]{96}$", var.phase2_template_sha384))
    error_message = "The reviewed Phase2 template SHA384 is required."
  }
}
variable "implementation_commit" {
  type = string
  validation {
    condition     = can(regex("^[0-9a-f]{40}$", var.implementation_commit))
    error_message = "The final integrated recovery implementation commit is required."
  }
}
variable "manifest_output" {
  type = string
  validation {
    condition     = length(trimspace(var.manifest_output)) > 0
    error_message = "A Packer manifest output path is required."
  }
}

locals {
  recovery_source_commit = "f282583cae7a5c873a26aa8d0c1bec10c490eb8e"
  recovery_eif_sha384    = "958e084e0a66d0aca6773193a74d40659cd258fcffa116b0117fed1fab8361046ffea6411379b72fc72c97b86f611290"
  recovery_pcr0_sha384   = "57fc48ad4d755edda38665bc8f0a16e7fd9dc485e3b57a2bce9070f60bd3b9724711ff973175340d5ebbfed4d63b7fac"
  recovery_purpose       = "layrs-seq159300-recovery"
  ami_name               = "layrs-seq159300-recovery-parent-f282583cae7a"
}

source "amazon-ebs" "seq159300_recovery_parent" {
  region        = var.aws_region
  instance_type = "m6i.xlarge"
  ssh_username  = "ec2-user"
  ssh_interface = "session_manager"

  ami_name        = local.ami_name
  ami_description = "Isolated Layrs sequence-159300 recovery-only Nitro parent from f282583cae7a"
  encrypt_boot    = true
  kms_key_id      = "alias/aws/ebs"
  ena_support     = true
  imds_support    = "v2.0"

  associate_public_ip_address = false
  subnet_id                   = var.build_subnet_id
  security_group_id           = var.build_security_group_id
  iam_instance_profile        = var.build_instance_profile
  ssh_clear_authorized_keys   = true

  deregistration_protection {
    enabled       = true
    with_cooldown = true
  }

  source_ami_filter {
    filters = {
      image-id            = var.source_ami_id
      root-device-type    = "ebs"
      virtualization-type = "hvm"
    }
    owners      = [var.source_ami_owner]
    most_recent = false
  }

  tags = {
    Name                     = local.ami_name
    Project                  = "Layrs"
    Purpose                  = local.recovery_purpose
    Environment              = "recovery-only"
    ManagedBy                = "Packer"
    RecoverySourceCommit     = local.recovery_source_commit
    RecoveryParentSha384     = var.parent_sha384
    RecoveryEifSha384        = local.recovery_eif_sha384
    RecoveryPcr0Sha384       = local.recovery_pcr0_sha384
    Phase2TemplateSha384     = var.phase2_template_sha384
    GateImplementationCommit = var.implementation_commit
    ProductionRouteAttached  = "false"
    Visibility               = "private"
  }

  run_tags = {
    Name        = "layrs-seq159300-recovery-parent-build"
    Project     = "Layrs"
    Purpose     = local.recovery_purpose
    Environment = "recovery-only"
    ManagedBy   = "Packer"
  }

  run_volume_tags = {
    Name        = "layrs-seq159300-recovery-parent-build"
    Project     = "Layrs"
    Purpose     = local.recovery_purpose
    Environment = "recovery-only"
    ManagedBy   = "Packer"
  }
}

build {
  sources = ["source.amazon-ebs.seq159300_recovery_parent"]

  provisioner "file" {
    source      = "build/layrs-enclave-parent"
    destination = "/tmp/layrs-enclave-parent"
  }
  provisioner "file" {
    source      = "build/layrsv2-clob.eif"
    destination = "/tmp/layrsv2-clob.eif"
  }
  provisioner "file" {
    source      = "enclave/systemd/layrsv2-enclave.service"
    destination = "/tmp/layrsv2-enclave.service"
  }
  provisioner "file" {
    source      = "enclave/systemd/layrsv2-enclave-parent.service"
    destination = "/tmp/layrsv2-enclave-parent.service"
  }
  provisioner "file" {
    source      = "enclave/systemd/layrsv2-enclave-watchdog.service"
    destination = "/tmp/layrsv2-enclave-watchdog.service"
  }
  provisioner "file" {
    source      = "enclave/systemd/layrsv2-enclave-watchdog.timer"
    destination = "/tmp/layrsv2-enclave-watchdog.timer"
  }
  provisioner "file" {
    source      = "enclave/systemd/layrsv2-enclave-watchdog"
    destination = "/tmp/layrsv2-enclave-watchdog"
  }
  provisioner "file" {
    source      = "enclave/allocator.yaml"
    destination = "/tmp/allocator.yaml"
  }

  provisioner "shell" {
    inline = [
      "printf '%s  %s\\n' 'd9506bf11627b04bd5d220e18e78584cd5e649952fe380309346d9c6bbecd511eb318cdcdee6a1d0db989d581a742db1' '/tmp/layrs-enclave-parent' | sha384sum -c -",
      "printf '%s  %s\\n' '958e084e0a66d0aca6773193a74d40659cd258fcffa116b0117fed1fab8361046ffea6411379b72fc72c97b86f611290' '/tmp/layrsv2-clob.eif' | sha384sum -c -",
      "sudo dnf install -y aws-nitro-enclaves-cli aws-nitro-enclaves-cli-devel",
      "sudo useradd --system --home-dir /nonexistent --shell /sbin/nologin layrsv2 || true",
      "sudo usermod -aG ne ec2-user",
      "sudo install -d -o root -g root -m 0755 /opt/layrsv2",
      "sudo install -o root -g root -m 0755 /tmp/layrs-enclave-parent /opt/layrsv2/layrs-enclave-parent",
      "sudo install -o root -g root -m 0600 /tmp/layrsv2-clob.eif /opt/layrsv2/layrsv2-clob.eif",
      "sudo install -o root -g root -m 0644 /tmp/layrsv2-enclave.service /etc/systemd/system/layrsv2-enclave.service",
      "sudo install -o root -g root -m 0644 /tmp/layrsv2-enclave-parent.service /etc/systemd/system/layrsv2-enclave-parent.service",
      "sudo install -o root -g root -m 0644 /tmp/layrsv2-enclave-watchdog.service /etc/systemd/system/layrsv2-enclave-watchdog.service",
      "sudo install -o root -g root -m 0644 /tmp/layrsv2-enclave-watchdog.timer /etc/systemd/system/layrsv2-enclave-watchdog.timer",
      "sudo install -o root -g root -m 0755 /tmp/layrsv2-enclave-watchdog /opt/layrsv2/layrsv2-enclave-watchdog",
      "sudo install -o root -g root -m 0644 /tmp/allocator.yaml /etc/nitro_enclaves/allocator.yaml",
      "sudo systemctl enable nitro-enclaves-allocator.service layrsv2-enclave.service layrsv2-enclave-parent.service layrsv2-enclave-watchdog.timer",
      "sudo dnf clean all"
    ]
  }

  post-processor "manifest" {
    output     = var.manifest_output
    strip_path = true
    custom_data = {
      purpose                   = local.recovery_purpose
      sourceCommit              = local.recovery_source_commit
      sourceAmiId               = var.source_ami_id
      sourceAmiOwner            = var.source_ami_owner
      parentSha384              = var.parent_sha384
      eifSha384                 = local.recovery_eif_sha384
      pcr0Sha384                = local.recovery_pcr0_sha384
      phase2TemplateSha384      = var.phase2_template_sha384
      implementationCommit      = var.implementation_commit
      productionRouteAttached   = "false"
      recoveryServicesUnchanged = "true"
    }
  }
}
