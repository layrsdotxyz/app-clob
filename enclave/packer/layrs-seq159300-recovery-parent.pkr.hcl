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
    condition     = var.source_ami_id == "ami-0332d564d76dbd8d6"
    error_message = "The exact reviewed AL2023 source AMI ID is required."
  }
}
variable "source_ami_owner" {
  type = string
  validation {
    condition     = var.source_ami_owner == "137112412989"
    error_message = "The source AMI owner must be the official AL2023 owner."
  }
}
variable "source_ami_provenance_sha384" {
  type = string
  validation {
    condition     = can(regex("^[0-9a-f]{96}$", var.source_ami_provenance_sha384))
    error_message = "The canonical source AMI provenance SHA384 is required."
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
    condition     = can(regex("^layrs-production-recovery-seq159300-[A-Za-z0-9+=,.@_-]+$", var.build_instance_profile))
    error_message = "The build instance profile must be recovery-specific."
  }
}
variable "build_subnet_inventory_sha384" {
  type = string
  validation {
    condition     = can(regex("^[0-9a-f]{96}$", var.build_subnet_inventory_sha384))
    error_message = "The canonical build subnet inventory SHA384 is required."
  }
}
variable "build_security_group_inventory_sha384" {
  type = string
  validation {
    condition     = can(regex("^[0-9a-f]{96}$", var.build_security_group_inventory_sha384))
    error_message = "The canonical build security-group inventory SHA384 is required."
  }
}
variable "build_instance_profile_inventory_sha384" {
  type = string
  validation {
    condition     = can(regex("^[0-9a-f]{96}$", var.build_instance_profile_inventory_sha384))
    error_message = "The canonical build instance-profile inventory SHA384 is required."
  }
}
variable "parent_package_commit" {
  type = string
  validation {
    condition     = can(regex("^[0-9a-f]{40}$", var.parent_package_commit))
    error_message = "The exact reviewed recovery-parent package commit is required."
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
variable "phase2_template_commit" {
  type = string
  validation {
    condition     = can(regex("^[0-9a-f]{40}$", var.phase2_template_commit))
    error_message = "The exact reviewed Phase2 template commit is required."
  }
}
variable "implementation_commit" {
  type = string
  validation {
    condition     = can(regex("^[0-9a-f]{40}$", var.implementation_commit))
    error_message = "The final integrated recovery implementation commit is required."
  }
}
variable "packer_template_sha384" {
  type = string
  validation {
    condition     = can(regex("^[0-9a-f]{96}$", var.packer_template_sha384))
    error_message = "The exact Packer template SHA384 is required."
  }
}
variable "nitro_cli_nevra" {
  type = string
  validation {
    condition     = can(regex("^aws-nitro-enclaves-cli-[0-9]+:?[A-Za-z0-9._+~]+-[A-Za-z0-9._+~]+\\.x86_64$", var.nitro_cli_nevra))
    error_message = "One exact reviewed x86_64 Nitro CLI NEVRA is required."
  }
}
variable "nitro_cli_rpm_sha384" {
  type = string
  validation {
    condition     = can(regex("^[0-9a-f]{96}$", var.nitro_cli_rpm_sha384))
    error_message = "The exact reviewed Nitro CLI RPM SHA384 is required."
  }
}
variable "nitro_package_inventory_sha384" {
  type = string
  validation {
    condition     = can(regex("^[0-9a-f]{96}$", var.nitro_package_inventory_sha384))
    error_message = "The expected installed-package inventory SHA384 is required."
  }
}
variable "nitro_package_set_sha384" {
  type = string
  validation {
    condition     = can(regex("^[0-9a-f]{96}$", var.nitro_package_set_sha384))
    error_message = "The exact immutable Nitro dependency-closure manifest SHA384 is required."
  }
}
variable "nitro_package_closure_sha384" {
  type = string
  validation {
    condition     = can(regex("^[0-9a-f]{96}$", var.nitro_package_closure_sha384))
    error_message = "The independently reviewed Nitro package name and NEVRA closure SHA384 is required."
  }
}
variable "recovery_evidence_index_sha384" {
  type = string
  validation {
    condition     = can(regex("^[0-9a-f]{96}$", var.recovery_evidence_index_sha384))
    error_message = "The exact recovery evidence-index SHA384 is required."
  }
}
variable "build_control_plane_role_inventory_sha384" {
  type = string
  validation {
    condition     = can(regex("^[0-9a-f]{96}$", var.build_control_plane_role_inventory_sha384))
    error_message = "The exact Packer control-role inventory SHA384 is required."
  }
}
variable "builder_template_sha384" {
  type = string
  validation {
    condition     = can(regex("^[0-9a-f]{96}$", var.builder_template_sha384))
    error_message = "The exact recovery-builder CloudFormation template SHA384 is required."
  }
}
variable "packer_invoker_role_inventory_sha384" {
  type = string
  validation {
    condition     = can(regex("^[0-9a-f]{96}$", var.packer_invoker_role_inventory_sha384))
    error_message = "The exact Packer invoker-role inventory SHA384 is required."
  }
}
variable "package_install_plan" {
  type = string
  validation {
    condition     = length(trimspace(var.package_install_plan)) > 0
    error_message = "A locally verified package-install plan is required."
  }
}
variable "package_inventory_output" {
  type = string
  validation {
    condition     = length(trimspace(var.package_inventory_output)) > 0
    error_message = "A local installed-package inventory output path is required."
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
  recovery_source_commit    = "f282583cae7a5c873a26aa8d0c1bec10c490eb8e"
  recovery_eif_sha384       = "958e084e0a66d0aca6773193a74d40659cd258fcffa116b0117fed1fab8361046ffea6411379b72fc72c97b86f611290"
  recovery_pcr0_sha384      = "57fc48ad4d755edda38665bc8f0a16e7fd9dc485e3b57a2bce9070f60bd3b9724711ff973175340d5ebbfed4d63b7fac"
  recovery_purpose          = "layrs-seq159300-recovery"
  ami_name                  = "layrs-seq159300-recovery-parent-f282583cae7a"
  packer_cli_version        = "1.16.0"
  packer_cli_archive_sha256 = "5edcd14ab59b535040c512dbecd6ec9ef976a000b073c19d93e4c431c948581e"
  packer_cli_sha384         = "acdd742a9f7a9e32715e81e72c8d0622ac1a700779e2b1480d89544bec89761655fa07a1fc75edaf35d337fcd318d126"
  packer_amazon_version     = "1.3.9"
  packer_amazon_sha384      = "72d1f95616192ce9b5f7f4011b43e2fee43c48c464fd03b99b5d1bd23b49940a9b41a2151a2240a670d063b9aa53e973"
  packer_evidence_sha256    = "9f116d64eba294c61582335d74a4812b287d9a9c601787ea7454cb030ebebb33"
  packer_manifest_sha256    = "6a6d597535481836605a4cc9762755038e56e524af621356e5f5f65519c6858e"
}

source "amazon-ebs" "seq159300_recovery_parent" {
  region              = var.aws_region
  instance_type       = "m6i.xlarge"
  ssh_username        = "ec2-user"
  ssh_interface       = "session_manager"
  allowed_account_ids = ["082223548516"]

  ami_name        = local.ami_name
  ami_description = "Isolated Layrs sequence-159300 recovery-only Nitro parent from f282583cae7a"
  imds_support    = "v2.0"

  associate_public_ip_address = false
  subnet_id                   = var.build_subnet_id
  security_group_id           = var.build_security_group_id
  iam_instance_profile        = var.build_instance_profile
  ssh_clear_authorized_keys   = true
  temporary_key_pair_name     = "layrs-seq159300-recovery-${substr(uuidv4(), 0, 16)}"

  launch_block_device_mappings {
    delete_on_termination = true
    device_name           = "/dev/xvda"
    encrypted             = true
    volume_size           = 8
    volume_type           = "gp3"
  }

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
    Name                          = local.ami_name
    Project                       = "Layrs"
    Purpose                       = local.recovery_purpose
    Environment                   = "recovery-only"
    ManagedBy                     = "Packer"
    RecoverySourceCommit          = local.recovery_source_commit
    RecoveryParentPackageCommit   = var.parent_package_commit
    SourceAmiProvenanceSha384     = var.source_ami_provenance_sha384
    BuildSubnetInventorySha384    = var.build_subnet_inventory_sha384
    BuildSecurityGroupSha384      = var.build_security_group_inventory_sha384
    BuildInstanceProfileSha384    = var.build_instance_profile_inventory_sha384
    BuildControlPlaneRoleSha384   = var.build_control_plane_role_inventory_sha384
    PackerInvokerRoleSha384       = var.packer_invoker_role_inventory_sha384
    RecoveryBuilderTemplateSha384 = var.builder_template_sha384
    RecoveryPackageSetSha384      = var.nitro_package_set_sha384
    RecoveryEvidenceIndexSha384   = var.recovery_evidence_index_sha384
    RecoveryParentSha384          = var.parent_sha384
    RecoveryEifSha384             = local.recovery_eif_sha384
    RecoveryPcr0Sha384            = local.recovery_pcr0_sha384
    Phase2TemplateSha384          = var.phase2_template_sha384
    Phase2TemplateCommit          = var.phase2_template_commit
    GateImplementationCommit      = var.implementation_commit
    PackerTemplateSha384          = var.packer_template_sha384
    NitroCliNevra                 = var.nitro_cli_nevra
    NitroCliRpmSha384             = var.nitro_cli_rpm_sha384
    NitroPackageInventorySha384   = var.nitro_package_inventory_sha384
    NitroPackageSetSha384         = var.nitro_package_set_sha384
    NitroPackageClosureSha384     = var.nitro_package_closure_sha384
    ProductionRouteAttached       = "false"
    Visibility                    = "private"
  }

  snapshot_tags = {
    Project                       = "Layrs"
    Purpose                       = local.recovery_purpose
    Environment                   = "recovery-only"
    ManagedBy                     = "Packer"
    RecoveryBuilderTemplateSha384 = var.builder_template_sha384
    RecoveryPackageSetSha384      = var.nitro_package_set_sha384
    RecoveryEvidenceIndexSha384   = var.recovery_evidence_index_sha384
    Phase2TemplateSha384          = var.phase2_template_sha384
  }

  run_tags = {
    Name                          = "layrs-seq159300-recovery-parent-build"
    Project                       = "Layrs"
    Purpose                       = local.recovery_purpose
    Environment                   = "recovery-only"
    ManagedBy                     = "Packer"
    RecoveryBuilderTemplateSha384 = var.builder_template_sha384
    RecoveryPackageSetSha384      = var.nitro_package_set_sha384
    RecoveryEvidenceIndexSha384   = var.recovery_evidence_index_sha384
    Phase2TemplateSha384          = var.phase2_template_sha384
  }

  run_volume_tags = {
    Name                          = "layrs-seq159300-recovery-parent-build"
    Project                       = "Layrs"
    Purpose                       = local.recovery_purpose
    Environment                   = "recovery-only"
    ManagedBy                     = "Packer"
    RecoveryBuilderTemplateSha384 = var.builder_template_sha384
    RecoveryPackageSetSha384      = var.nitro_package_set_sha384
    RecoveryEvidenceIndexSha384   = var.recovery_evidence_index_sha384
    Phase2TemplateSha384          = var.phase2_template_sha384
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
  provisioner "file" {
    source      = "build/seq159300-nitro-packages"
    destination = "/tmp/seq159300-nitro-packages"
  }
  provisioner "file" {
    source      = var.package_install_plan
    destination = "/tmp/seq159300-package-install-plan.tsv"
  }

  provisioner "shell" {
    inline = [
      "printf '%s  %s\\n' 'd9506bf11627b04bd5d220e18e78584cd5e649952fe380309346d9c6bbecd511eb318cdcdee6a1d0db989d581a742db1' '/tmp/layrs-enclave-parent' | sha384sum -c -",
      "printf '%s  %s\\n' '958e084e0a66d0aca6773193a74d40659cd258fcffa116b0117fed1fab8361046ffea6411379b72fc72c97b86f611290' '/tmp/layrsv2-clob.eif' | sha384sum -c -",
      "test \"$(find /tmp/seq159300-nitro-packages -mindepth 1 -maxdepth 1 -type f -name '*.rpm' | wc -l)\" = \"$(wc -l < /tmp/seq159300-package-install-plan.tsv)\"",
      "test \"$(sha256sum /etc/pki/rpm-gpg/RPM-GPG-KEY-amazon-linux-2023 | awk '{print $1}')\" = '664b632018bd84f9b249be7bd26937c560edb2f2bfc0cbc01ec5a7b4e06aad56'",
      "rpm -q gpg-pubkey-d832c631-6515c85e",
      "while IFS='\t' read -r file sha nevra name; do test -f \"/tmp/seq159300-nitro-packages/$file\"; printf '%s  %s\\n' \"$sha\" \"/tmp/seq159300-nitro-packages/$file\" | sha384sum -c -; rpmkeys --checksig --verbose \"/tmp/seq159300-nitro-packages/$file\" | grep -iF 'key ID D832C631' | grep -F ': OK'; test \"$(rpm -qp --qf '%%{NAME}' \"/tmp/seq159300-nitro-packages/$file\")\" = \"$name\"; test \"$(rpm -qp --qf '%%{NAME}-%%{EPOCHNUM}:%%{VERSION}-%%{RELEASE}.%%{ARCH}' \"/tmp/seq159300-nitro-packages/$file\")\" = \"$nevra\"; done < /tmp/seq159300-package-install-plan.tsv",
      "sudo dnf install -y --disablerepo='*' $(awk -F '\t' '{printf \"/tmp/seq159300-nitro-packages/%%s \", $1}' /tmp/seq159300-package-install-plan.tsv)",
      "while IFS='\t' read -r file sha nevra name; do test \"$(rpm -q --qf '%%{NAME}-%%{EPOCHNUM}:%%{VERSION}-%%{RELEASE}.%%{ARCH}' \"$name\")\" = \"$nevra\"; printf '%s\t%s\\n' \"$nevra\" \"$sha\"; done < /tmp/seq159300-package-install-plan.tsv > /tmp/layrs-seq159300-installed-package-inventory.txt",
      "test \"$(rpm -q --qf '%%{NAME}-%%{EPOCHNUM}:%%{VERSION}-%%{RELEASE}.%%{ARCH}' aws-nitro-enclaves-cli)\" = '${var.nitro_cli_nevra}'",
      "printf '%s  %s\\n' '${var.nitro_package_inventory_sha384}' '/tmp/layrs-seq159300-installed-package-inventory.txt' | sha384sum -c -",
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

  provisioner "file" {
    direction   = "download"
    source      = "/tmp/layrs-seq159300-installed-package-inventory.txt"
    destination = var.package_inventory_output
  }

  post-processor "manifest" {
    output     = var.manifest_output
    strip_path = true
    custom_data = {
      purpose                              = local.recovery_purpose
      sourceCommit                         = local.recovery_source_commit
      parentPackageCommit                  = var.parent_package_commit
      sourceAmiId                          = var.source_ami_id
      sourceAmiOwner                       = var.source_ami_owner
      sourceAmiProvenanceSha384            = var.source_ami_provenance_sha384
      buildSubnetInventorySha384           = var.build_subnet_inventory_sha384
      buildSecurityGroupInventorySha384    = var.build_security_group_inventory_sha384
      buildInstanceProfileInventorySha384  = var.build_instance_profile_inventory_sha384
      buildControlPlaneRoleInventorySha384 = var.build_control_plane_role_inventory_sha384
      builderEvidenceIndexSha384           = var.recovery_evidence_index_sha384
      builderTemplateSha384                = var.builder_template_sha384
      parentSha384                         = var.parent_sha384
      eifSha384                            = local.recovery_eif_sha384
      pcr0Sha384                           = local.recovery_pcr0_sha384
      phase2TemplateSha384                 = var.phase2_template_sha384
      phase2TemplateCommit                 = var.phase2_template_commit
      implementationCommit                 = var.implementation_commit
      packerTemplateSha384                 = var.packer_template_sha384
      packerInvokerRoleInventorySha384     = var.packer_invoker_role_inventory_sha384
      packerCliVersion                     = local.packer_cli_version
      packerCliArchiveSha256               = local.packer_cli_archive_sha256
      packerCliSha384                      = local.packer_cli_sha384
      packerAmazonPluginVersion            = local.packer_amazon_version
      packerAmazonPluginSha384             = local.packer_amazon_sha384
      packerToolchainProvenanceSha256      = local.packer_evidence_sha256
      packerToolchainManifestSha256        = local.packer_manifest_sha256
      nitroCliNevra                        = var.nitro_cli_nevra
      nitroCliRpmSha384                    = var.nitro_cli_rpm_sha384
      nitroPackageInventorySha384          = var.nitro_package_inventory_sha384
      nitroPackageSetSha384                = var.nitro_package_set_sha384
      nitroPackageClosureSha384            = var.nitro_package_closure_sha384
      productionRouteAttached              = "false"
      recoveryServicesUnchanged            = "true"
    }
  }
}
