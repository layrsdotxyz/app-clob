packer {
  required_plugins {
    amazon = { source = "github.com/hashicorp/amazon", version = ">= 1.3.9" }
  }
}
variable "aws_region" { type = string }
variable "release_id" { type = string }
source "amazon-ebs" "opening_epoch" {
  region               = var.aws_region
  instance_type        = "m6i.xlarge"
  ssh_username         = "ec2-user"
  ssh_interface        = "session_manager"
  iam_instance_profile = "layrs-opening-epoch-packer-ssm"
  ami_name             = "layrs-opening-epoch-${var.release_id}"
  ami_description      = "Isolated dormant Layrs opening epoch direct-execution Nitro runtime"
  encrypt_boot         = true
  ena_support          = true
  imds_support         = "v2.0"
  source_ami_filter {
    filters     = { name = "al2023-ami-2023.*-x86_64", root-device-type = "ebs", virtualization-type = "hvm" }
    owners      = ["137112412989"]
    most_recent = true
  }
  tags = { Name = "layrs-opening-epoch-${var.release_id}", Project = "Layrs", Environment = "opening-epoch", ProductionAccess = "denied", WriterEnabled = "false", ManagedBy = "Packer" }
}
build {
  sources = ["source.amazon-ebs.opening_epoch"]
  provisioner "file" {
    source      = "${path.root}/../target/release/layrs-direct-enclave"
    destination = "/tmp/layrs-direct-enclave"
  }
  provisioner "file" {
    source      = "${path.root}/../target/release/layrs-direct-parent"
    destination = "/tmp/layrs-direct-parent"
  }
  provisioner "file" {
    source      = "${path.root}/Dockerfile"
    destination = "/tmp/Dockerfile"
  }
  provisioner "file" {
    source      = "${path.root}/layrs-opening-enclave.service"
    destination = "/tmp/layrs-opening-enclave.service"
  }
  provisioner "file" {
    source      = "${path.root}/layrs-opening-parent.service"
    destination = "/tmp/layrs-opening-parent.service"
  }
  provisioner "file" {
    source      = "${path.root}/../../../../../.codex-review-bundles/unified-direct-execution-20260905/new-epoch-20260911/OPENING_EPOCH_STATE_20260911.json"
    destination = "/tmp/OPENING_EPOCH_STATE_20260911.json"
  }
  provisioner "file" {
    source      = "${path.root}/../../../../../.codex-review-bundles/unified-direct-execution-20260905/new-epoch-20260911/OPENING_EPOCH_EVIDENCE_MANIFEST_20260911.json"
    destination = "/tmp/OPENING_EPOCH_EVIDENCE_MANIFEST_20260911.json"
  }
  provisioner "shell" {
    inline = [
      "sudo dnf install -y aws-nitro-enclaves-cli docker",
      "sudo systemctl enable docker && sudo systemctl start docker",
      "sudo install -d -m 0755 /opt/layrs-opening /tmp/opening-image",
      "sudo install -m 0755 /tmp/layrs-direct-enclave /tmp/opening-image/layrs-direct-enclave",
      "sudo install -m 0755 /tmp/layrs-direct-parent /opt/layrs-opening/layrs-direct-parent",
      "sudo install -m 0600 /tmp/OPENING_EPOCH_STATE_20260911.json /tmp/opening-image/OPENING_EPOCH_STATE_20260911.json",
      "sudo install -m 0600 /tmp/OPENING_EPOCH_EVIDENCE_MANIFEST_20260911.json /tmp/opening-image/OPENING_EPOCH_EVIDENCE_MANIFEST_20260911.json",
      "sudo install -m 0644 /tmp/Dockerfile /tmp/opening-image/Dockerfile",
      "sudo docker build -t layrs-opening-epoch:local /tmp/opening-image",
      "sudo NITRO_CLI_BLOBS=/usr/share/nitro_enclaves/blobs nitro-cli build-enclave --docker-uri layrs-opening-epoch:local --output-file /tmp/layrs-direct-execution.eif",
      "sudo install -m 0600 /tmp/layrs-direct-execution.eif /opt/layrs-opening/layrs-direct-execution.eif",
      "sudo install -m 0600 /tmp/OPENING_EPOCH_STATE_20260911.json /opt/layrs-opening/OPENING_EPOCH_STATE_20260911.json",
      "sudo install -m 0600 /tmp/OPENING_EPOCH_EVIDENCE_MANIFEST_20260911.json /opt/layrs-opening/OPENING_EPOCH_EVIDENCE_MANIFEST_20260911.json",
      "sudo useradd --system --home-dir /nonexistent --shell /sbin/nologin layrsopening || true",
      "sudo install -m 0644 /tmp/layrs-opening-enclave.service /etc/systemd/system/layrs-opening-enclave.service",
      "sudo install -m 0644 /tmp/layrs-opening-parent.service /etc/systemd/system/layrs-opening-parent.service",
      "sudo install -d -m 0755 /etc/nitro_enclaves",
      "printf 'memory_mib: 1024\\ncpu_count: 2\\n' | sudo tee /etc/nitro_enclaves/allocator.yaml >/dev/null",
      "sudo systemctl enable nitro-enclaves-allocator.service layrs-opening-enclave.service layrs-opening-parent.service",
      "sudo dnf clean all"
    ]
  }
}
