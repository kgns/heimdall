# The cloud end of the measurements: one small instance in eu-central-1 with
# an Elastic IP, running
#   - heimdall-reflector: STAMP (UDP 862), TCP 443 accept-and-close, and the
#     authoritative server of the whoami zone w.<subdomain>.<zone> (53)
#   - heimdall-probe as device "aws-euc1", measuring the catalog from AWS
# Binaries and configuration come from the artifacts bucket at boot; any
# change to them replaces the instance, which keeps its Elastic IP.

locals {
  reflector_domain = "reflector.${local.base_domain}"
  whoami_zone      = "w.${local.base_domain}"
  whoami_ns        = "ns.${local.base_domain}"
  cloud_device     = "aws-euc1"
  repo_root        = "${path.module}/.."

  reflector_artifacts = merge(
    {
      "reflector/bin/heimdall-reflector" = "${local.repo_root}/bin/linux-arm64/heimdall-reflector"
      "reflector/bin/heimdall-probe"     = "${local.repo_root}/bin/linux-arm64/heimdall-probe"
      "reflector/probe.yaml"             = "${local.repo_root}/configs/aws.yaml"
    },
    { for f in fileset("${local.repo_root}/catalog", "**/*.yaml") : "reflector/catalog/${f}" => "${local.repo_root}/catalog/${f}" },
  )
  reflector_artifacts_hash = substr(sha256(join("\n", [
    for k in sort(keys(local.reflector_artifacts)) : "${k}:${filemd5(local.reflector_artifacts[k])}"
  ])), 0, 16)
}

resource "aws_s3_object" "reflector" {
  for_each = local.reflector_artifacts
  bucket   = aws_s3_bucket.artifacts.id
  key      = each.key
  source   = each.value
  etag     = filemd5(each.value)
}

# Upload token of the cloud probe. The instance reads the token; the ingest
# Lambda checks its digest, like for any other device.
ephemeral "random_password" "cloud_device_token" {
  length  = 40
  special = false
}

resource "aws_ssm_parameter" "cloud_device_token" {
  name             = "/heimdall/devices/${local.cloud_device}/token"
  description      = "Upload token of ${local.cloud_device}, read by the reflector instance"
  type             = "SecureString"
  value_wo         = ephemeral.random_password.cloud_device_token.result
  value_wo_version = 1
}

resource "aws_ssm_parameter" "cloud_device_token_sha256" {
  name             = "/heimdall/devices/${local.cloud_device}/token_sha256"
  description      = "SHA-256 of the upload token of ${local.cloud_device}"
  type             = "SecureString"
  value_wo         = sha256(ephemeral.random_password.cloud_device_token.result)
  value_wo_version = 1
}

data "aws_ssm_parameter" "al2023_arm64" {
  name = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-arm64"
}

resource "aws_cloudwatch_log_group" "reflector" {
  name              = "/heimdall/reflector"
  retention_in_days = var.log_retention_days
}

data "aws_iam_policy_document" "ec2_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "reflector" {
  name               = "heimdall-reflector"
  assume_role_policy = data.aws_iam_policy_document.ec2_assume.json
}

data "aws_iam_policy_document" "reflector" {
  statement {
    sid       = "Artifacts"
    actions   = ["s3:GetObject"]
    resources = ["${aws_s3_bucket.artifacts.arn}/reflector/*"]
  }
  statement {
    sid       = "ListArtifacts"
    actions   = ["s3:ListBucket"]
    resources = [aws_s3_bucket.artifacts.arn]
    condition {
      test     = "StringLike"
      variable = "s3:prefix"
      values   = ["reflector/*"]
    }
  }
  statement {
    sid       = "UploadToken"
    actions   = ["ssm:GetParameter"]
    resources = [aws_ssm_parameter.cloud_device_token.arn]
  }
  statement {
    sid       = "DecryptToken"
    actions   = ["kms:Decrypt"]
    resources = ["arn:aws:kms:${var.aws_region}:${var.aws_account_id}:key/*"]
    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["ssm.${var.aws_region}.amazonaws.com"]
    }
  }
  statement {
    sid       = "Logs"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents", "logs:DescribeLogStreams"]
    resources = [aws_cloudwatch_log_group.reflector.arn, "${aws_cloudwatch_log_group.reflector.arn}:*"]
  }
  statement {
    sid       = "DescribeLogGroups"
    actions   = ["logs:DescribeLogGroups"]
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "reflector" {
  name   = "reflector"
  role   = aws_iam_role.reflector.id
  policy = data.aws_iam_policy_document.reflector.json
}

# Session Manager access for debugging; there is no SSH.
resource "aws_iam_role_policy_attachment" "reflector_ssm" {
  role       = aws_iam_role.reflector.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_instance_profile" "reflector" {
  name = "heimdall-reflector"
  role = aws_iam_role.reflector.name
}

resource "aws_security_group" "reflector" {
  name        = "heimdall-reflector"
  description = "heimdall reflector: STAMP, TCP 443, whoami DNS, ICMP echo"
  vpc_id      = data.aws_vpc.default.id
}

resource "aws_vpc_security_group_ingress_rule" "reflector" {
  for_each = {
    stamp   = { proto = "udp", from = 862, to = 862 }
    tcp443  = { proto = "tcp", from = 443, to = 443 }
    dns_udp = { proto = "udp", from = 53, to = 53 }
    dns_tcp = { proto = "tcp", from = 53, to = 53 }
    # ICMP: from_port is the type (8, echo request), to_port the code.
    echo = { proto = "icmp", from = 8, to = 0 }
  }
  security_group_id = aws_security_group.reflector.id
  description       = each.key
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = each.value.proto
  from_port         = each.value.from
  to_port           = each.value.to
}

# The probe measures arbitrary services over ICMP, TCP, UDP (DNS, NTP) and
# HTTPS, so egress is open.
resource "aws_vpc_security_group_egress_rule" "reflector" {
  security_group_id = aws_security_group.reflector.id
  description       = "measurements and AWS APIs"
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "-1"
}

resource "aws_instance" "reflector" {
  ami                         = data.aws_ssm_parameter.al2023_arm64.insecure_value
  instance_type               = "t4g.micro"
  subnet_id                   = sort(data.aws_subnets.default.ids)[0]
  vpc_security_group_ids      = [aws_security_group.reflector.id]
  iam_instance_profile        = aws_iam_instance_profile.reflector.name
  associate_public_ip_address = true
  user_data_replace_on_change = true
  user_data = templatefile("${path.module}/templates/reflector-user-data.sh.tftpl", {
    artifacts_hash  = local.reflector_artifacts_hash
    region          = var.aws_region
    bucket          = aws_s3_bucket.artifacts.id
    token_parameter = aws_ssm_parameter.cloud_device_token.name
    zone            = local.whoami_zone
    ns              = local.whoami_ns
    hostmaster      = "hostmaster.${var.zone}"
    log_group       = aws_cloudwatch_log_group.reflector.name
  })

  credit_specification {
    cpu_credits = "standard"
  }

  metadata_options {
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }

  root_block_device {
    volume_type = "gp3"
    volume_size = 8
    encrypted   = true
  }

  tags = {
    Name = "heimdall-reflector"
  }

  lifecycle {
    # A newer AMI is picked up when the instance is replaced for other
    # reasons, not by itself.
    ignore_changes = [ami]
  }

  depends_on = [aws_s3_object.reflector, aws_iam_role_policy.reflector, aws_ssm_parameter.cloud_device_token]
}

resource "aws_eip" "reflector" {
  domain = "vpc"
  tags = {
    Name = "heimdall-reflector"
  }
}

resource "aws_eip_association" "reflector" {
  allocation_id = aws_eip.reflector.id
  instance_id   = aws_instance.reflector.id
}

# DNS only: the probe measures the path to AWS, not to Cloudflare.
resource "cloudflare_dns_record" "reflector" {
  for_each = {
    reflector = local.reflector_domain
    ns        = local.whoami_ns
  }
  zone_id = data.cloudflare_zone.this[0].id
  name    = each.value
  type    = "A"
  content = aws_eip.reflector.public_ip
  ttl     = 300
  proxied = false
  comment = "heimdall: reflector instance"
}

resource "cloudflare_dns_record" "whoami_delegation" {
  zone_id = data.cloudflare_zone.this[0].id
  name    = local.whoami_zone
  type    = "NS"
  content = local.whoami_ns
  ttl     = 300
  comment = "heimdall: whoami zone served by heimdall-reflector"
}
