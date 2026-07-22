packer {
  required_plugins {
    amazon = { source = "github.com/hashicorp/amazon", version = ">= 1.3.9" }
  }
}

variable "aws_region" {
  type = string
}
variable "source_ami_owner" {
  type    = string
  default = "137112412989"
}
variable "release_id" {
  type = string
}

source "amazon-ebs" "layrsv2_enclave_parent" {
  region        = var.aws_region
  instance_type = "m6i.xlarge"
  ssh_username  = "ec2-user"
  ami_name      = "layrsv2-enclave-parent-${var.release_id}"
  ena_support   = true
  imds_support  = "v2.0"
  source_ami_filter {
    filters = {
      name                = "al2023-ami-2023.*-x86_64"
      root-device-type    = "ebs"
      virtualization-type = "hvm"
    }
    owners      = [var.source_ami_owner]
    most_recent = true
  }
  tags = {
    Name       = "layrsv2-enclave-parent-${var.release_id}"
    Project    = "Layrs"
    Generation = "layrsv2"
    ManagedBy  = "Packer"
  }
}

build {
  sources = ["source.amazon-ebs.layrsv2_enclave_parent"]
  provisioner "file" { source = "build/layrs-enclave-parent", destination = "/tmp/layrs-enclave-parent" }
  provisioner "file" { source = "build/layrsv2-clob.eif", destination = "/tmp/layrsv2-clob.eif" }
  provisioner "file" { source = "enclave/systemd/layrsv2-enclave.service", destination = "/tmp/layrsv2-enclave.service" }
  provisioner "file" { source = "enclave/systemd/layrsv2-enclave-parent.service", destination = "/tmp/layrsv2-enclave-parent.service" }
  provisioner "file" { source = "enclave/allocator.yaml", destination = "/tmp/allocator.yaml" }
  provisioner "shell" {
    inline = [
      "sudo dnf install -y aws-nitro-enclaves-cli aws-nitro-enclaves-cli-devel",
      "sudo useradd --system --home-dir /nonexistent --shell /sbin/nologin layrsv2 || true",
      "sudo usermod -aG ne ec2-user",
      "sudo install -d -o root -g root -m 0755 /opt/layrsv2",
      "sudo install -o root -g root -m 0755 /tmp/layrs-enclave-parent /opt/layrsv2/layrs-enclave-parent",
      "sudo install -o root -g root -m 0600 /tmp/layrsv2-clob.eif /opt/layrsv2/layrsv2-clob.eif",
      "sudo install -o root -g root -m 0644 /tmp/layrsv2-enclave.service /etc/systemd/system/layrsv2-enclave.service",
      "sudo install -o root -g root -m 0644 /tmp/layrsv2-enclave-parent.service /etc/systemd/system/layrsv2-enclave-parent.service",
      "sudo install -o root -g root -m 0644 /tmp/allocator.yaml /etc/nitro_enclaves/allocator.yaml",
      "sudo systemctl enable nitro-enclaves-allocator.service layrsv2-enclave.service layrsv2-enclave-parent.service",
      "sudo dnf clean all"
    ]
  }
}
