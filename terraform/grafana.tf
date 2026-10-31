# Grafana on ECS Fargate with a public IP, reachable only through Cloudflare.
#
# Browsers connect to Cloudflare at heimdall.<zone>; Cloudflare connects to
# the task on 443 with full (strict) TLS against a Cloudflare origin
# certificate. The security group admits only Cloudflare's address ranges.
# The task's public IP changes whenever it is replaced, so the record's
# content is kept current by the dnssync Lambda (dnssync.tf), not by
# Terraform.

locals {
  # A first-level name: the zone's Universal SSL certificate covers only
  # <zone> and *.<zone>, so a proxied name under <subdomain>.<zone> would
  # have no edge certificate.
  grafana_domain = "heimdall.${var.zone}"
  grafana_dir    = "${path.module}/../grafana"
  grafana_files  = sort([for f in fileset(local.grafana_dir, "**") : f if !strcontains(f, "__pycache__")])
  # Content hash of the image sources; a change rebuilds and redeploys.
  grafana_image_tag = substr(sha256(join("\n", [
    for f in local.grafana_files : "${f}:${filesha256("${local.grafana_dir}/${f}")}"
  ])), 0, 16)
  grafana_service = "heimdall-grafana"
}

data "aws_vpc" "default" {
  default = true
}

data "aws_subnets" "default" {
  filter {
    name   = "vpc-id"
    values = [data.aws_vpc.default.id]
  }
  filter {
    name   = "default-for-az"
    values = ["true"]
  }
}

data "cloudflare_ip_ranges" "this" {}

# Image

resource "aws_ecr_repository" "grafana" {
  name                 = "heimdall-grafana"
  image_tag_mutability = "IMMUTABLE"

  image_scanning_configuration {
    scan_on_push = true
  }
}

resource "aws_ecr_lifecycle_policy" "grafana" {
  repository = aws_ecr_repository.grafana.name
  policy = jsonencode({
    rules = [{
      rulePriority = 1
      description  = "keep the last 5 images"
      selection    = { tagStatus = "any", countType = "imageCountMoreThan", countNumber = 5 }
      action       = { type = "expire" }
    }]
  })
}

resource "terraform_data" "grafana_image" {
  triggers_replace = [aws_ecr_repository.grafana.repository_url, local.grafana_image_tag]

  provisioner "local-exec" {
    command = "${path.module}/../scripts/push-image ${aws_ecr_repository.grafana.repository_url} ${local.grafana_image_tag} ${local.grafana_dir}"
  }
}

# Secrets

ephemeral "random_password" "grafana_admin" {
  length  = 32
  special = false
}

resource "aws_ssm_parameter" "grafana_admin_password" {
  name             = "/heimdall/grafana/admin_password"
  description      = "Grafana admin password (user admin)"
  type             = "SecureString"
  value_wo         = ephemeral.random_password.grafana_admin.result
  value_wo_version = 1
}

resource "tls_private_key" "grafana" {
  algorithm   = "ECDSA"
  ecdsa_curve = "P256"
}

resource "tls_cert_request" "grafana" {
  private_key_pem = tls_private_key.grafana.private_key_pem
  dns_names       = [local.grafana_domain]

  subject {
    common_name = local.grafana_domain
  }
}

resource "cloudflare_origin_ca_certificate" "grafana" {
  csr                = tls_cert_request.grafana.cert_request_pem
  hostnames          = [local.grafana_domain]
  request_type       = "origin-ecc"
  requested_validity = 5475
}

resource "aws_ssm_parameter" "grafana_tls_cert" {
  name        = "/heimdall/grafana/tls_cert"
  description = "Cloudflare origin certificate for ${local.grafana_domain}"
  type        = "String"
  tier        = "Standard"
  value       = cloudflare_origin_ca_certificate.grafana.certificate
}

resource "aws_ssm_parameter" "grafana_tls_key" {
  name        = "/heimdall/grafana/tls_key"
  description = "Private key of the origin certificate for ${local.grafana_domain}"
  type        = "SecureString"
  value       = tls_private_key.grafana.private_key_pem
}

# DNS

resource "cloudflare_dns_record" "grafana" {
  zone_id = data.cloudflare_zone.this[0].id
  name    = local.grafana_domain
  type    = "A"
  # Placeholder until dnssync writes the task's address.
  content = "192.0.2.1"
  ttl     = 1
  proxied = true
  comment = "heimdall: grafana, content managed by heimdall-dnssync"

  lifecycle {
    ignore_changes = [content]
  }
}

# Network

resource "aws_security_group" "grafana" {
  name        = local.grafana_service
  description = "Grafana task: HTTPS from Cloudflare only"
  vpc_id      = data.aws_vpc.default.id
}

resource "aws_vpc_security_group_ingress_rule" "grafana_cloudflare" {
  for_each          = toset(data.cloudflare_ip_ranges.this.ipv4_cidrs)
  security_group_id = aws_security_group.grafana.id
  description       = "Cloudflare"
  cidr_ipv4         = each.value
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
}

# ECR, CloudWatch Logs, SSM, Athena and S3 are all HTTPS. DNS and time
# sync go to the VPC's link-local services, which security groups do not
# filter.
resource "aws_vpc_security_group_egress_rule" "grafana_https" {
  security_group_id = aws_security_group.grafana.id
  description       = "AWS APIs"
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
}

# IAM

data "aws_iam_policy_document" "ecs_tasks_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ecs-tasks.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [var.aws_account_id]
    }
  }
}

resource "aws_iam_role" "grafana_execution" {
  name               = "heimdall-grafana-execution"
  assume_role_policy = data.aws_iam_policy_document.ecs_tasks_assume.json
}

data "aws_iam_policy_document" "grafana_execution" {
  statement {
    sid       = "PullImage"
    actions   = ["ecr:BatchGetImage", "ecr:GetDownloadUrlForLayer", "ecr:BatchCheckLayerAvailability"]
    resources = [aws_ecr_repository.grafana.arn]
  }
  statement {
    sid       = "EcrAuth"
    actions   = ["ecr:GetAuthorizationToken"]
    resources = ["*"]
  }
  statement {
    sid       = "Logs"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.grafana.arn}:*"]
  }
  statement {
    sid     = "Secrets"
    actions = ["ssm:GetParameters"]
    resources = [
      aws_ssm_parameter.grafana_admin_password.arn,
      aws_ssm_parameter.grafana_tls_cert.arn,
      aws_ssm_parameter.grafana_tls_key.arn,
    ]
  }
  statement {
    sid       = "DecryptSecrets"
    actions   = ["kms:Decrypt"]
    resources = ["arn:aws:kms:${var.aws_region}:${var.aws_account_id}:key/*"]
    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["ssm.${var.aws_region}.amazonaws.com"]
    }
  }
}

resource "aws_iam_role_policy" "grafana_execution" {
  name   = "execution"
  role   = aws_iam_role.grafana_execution.id
  policy = data.aws_iam_policy_document.grafana_execution.json
}

resource "aws_iam_role" "grafana_task" {
  name               = "heimdall-grafana-task"
  assume_role_policy = data.aws_iam_policy_document.ecs_tasks_assume.json
}

# Read-only access to the samples through the heimdall workgroup.
data "aws_iam_policy_document" "grafana_task" {
  statement {
    sid = "AthenaQueries"
    actions = [
      "athena:StartQueryExecution", "athena:StopQueryExecution", "athena:GetQueryExecution",
      "athena:GetQueryResults", "athena:BatchGetQueryExecution", "athena:GetWorkGroup",
    ]
    resources = [aws_athena_workgroup.this.arn]
  }
  statement {
    sid       = "AthenaCatalog"
    actions   = ["athena:GetDataCatalog", "athena:ListDatabases", "athena:GetDatabase", "athena:ListTableMetadata", "athena:GetTableMetadata"]
    resources = ["arn:aws:athena:${var.aws_region}:${var.aws_account_id}:datacatalog/AwsDataCatalog"]
  }
  statement {
    sid       = "AthenaList"
    actions   = ["athena:ListWorkGroups", "athena:ListDataCatalogs"]
    resources = ["*"]
  }
  statement {
    sid     = "Glue"
    actions = ["glue:GetDatabase", "glue:GetDatabases", "glue:GetTable", "glue:GetTables", "glue:GetPartition", "glue:GetPartitions", "glue:BatchGetPartition"]
    resources = [
      "arn:aws:glue:${var.aws_region}:${var.aws_account_id}:catalog",
      aws_glue_catalog_database.this.arn,
      "arn:aws:glue:${var.aws_region}:${var.aws_account_id}:table/${aws_glue_catalog_database.this.name}/*",
    ]
  }
  statement {
    sid       = "ReadSamples"
    actions   = ["s3:GetObject"]
    resources = ["${aws_s3_bucket.raw.arn}/raw/*", "${aws_s3_bucket.raw.arn}/derived/*"]
  }
  statement {
    sid       = "QueryResults"
    actions   = ["s3:GetObject", "s3:PutObject", "s3:AbortMultipartUpload", "s3:ListMultipartUploadParts"]
    resources = ["${aws_s3_bucket.athena.arn}/results/*"]
  }
  statement {
    sid       = "Buckets"
    actions   = ["s3:ListBucket", "s3:GetBucketLocation", "s3:ListBucketMultipartUploads"]
    resources = [aws_s3_bucket.raw.arn, aws_s3_bucket.athena.arn]
  }
}

resource "aws_iam_role_policy" "grafana_task" {
  name   = "athena-read"
  role   = aws_iam_role.grafana_task.id
  policy = data.aws_iam_policy_document.grafana_task.json
}

# ECS

resource "aws_cloudwatch_log_group" "grafana" {
  name              = "/ecs/${local.grafana_service}"
  retention_in_days = var.log_retention_days
}

resource "aws_ecs_cluster" "this" {
  name = local.name

  setting {
    name  = "containerInsights"
    value = "disabled"
  }
}

resource "aws_ecs_task_definition" "grafana" {
  family                   = local.grafana_service
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = 512
  memory                   = 1024
  execution_role_arn       = aws_iam_role.grafana_execution.arn
  task_role_arn            = aws_iam_role.grafana_task.arn

  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = "ARM64"
  }

  container_definitions = jsonencode([{
    name      = "grafana"
    image     = "${aws_ecr_repository.grafana.repository_url}:${local.grafana_image_tag}"
    essential = true
    portMappings = [{
      containerPort = 443
      protocol      = "tcp"
    }]
    # Grafana runs as uid 472; this lets it bind 443 without root.
    systemControls = [{
      namespace = "net.ipv4.ip_unprivileged_port_start"
      value     = "443"
    }]
    environment = [for k, v in {
      GF_SERVER_PROTOCOL                    = "https"
      GF_SERVER_HTTP_PORT                   = "443"
      GF_SERVER_DOMAIN                      = local.grafana_domain
      GF_SERVER_ROOT_URL                    = "https://${local.grafana_domain}/"
      GF_SERVER_CERT_FILE                   = "/tmp/tls/cert.pem"
      GF_SERVER_CERT_KEY                    = "/tmp/tls/key.pem"
      GF_SECURITY_ADMIN_USER                = "admin"
      GF_SECURITY_COOKIE_SECURE             = "true"
      GF_SECURITY_COOKIE_SAMESITE           = "strict"
      GF_SECURITY_DISABLE_GRAVATAR          = "true"
      GF_SECURITY_STRICT_TRANSPORT_SECURITY = "true"
      GF_USERS_ALLOW_SIGN_UP                = "false"
      GF_AUTH_ANONYMOUS_ENABLED             = tostring(var.grafana_anonymous)
      GF_AUTH_ANONYMOUS_ORG_ROLE            = "Viewer"
      GF_AUTH_ANONYMOUS_HIDE_VERSION        = "true"
      GF_USERS_VIEWERS_CAN_EDIT             = "false"
      # Each refresh runs every panel's Athena query again.
      GF_DASHBOARDS_MIN_REFRESH_INTERVAL        = "1m"
      GF_ANALYTICS_REPORTING_ENABLED            = "false"
      GF_ANALYTICS_CHECK_FOR_UPDATES            = "false"
      GF_ANALYTICS_CHECK_FOR_PLUGIN_UPDATES     = "false"
      GF_NEWS_NEWS_FEED_ENABLED                 = "false"
      GF_PLUGINS_PREINSTALL_DISABLED            = "true"
      GF_AWS_ALLOWED_AUTH_PROVIDERS             = "default"
      GF_AWS_ASSUME_ROLE_ENABLED                = "false"
      GF_DASHBOARDS_DEFAULT_HOME_DASHBOARD_PATH = "/etc/grafana/dashboards/topology.json"
      GF_LOG_MODE                               = "console"
    } : { name = k, value = v }]
    secrets = [
      { name = "GF_SECURITY_ADMIN_PASSWORD", valueFrom = aws_ssm_parameter.grafana_admin_password.arn },
      { name = "TLS_CERT", valueFrom = aws_ssm_parameter.grafana_tls_cert.arn },
      { name = "TLS_KEY", valueFrom = aws_ssm_parameter.grafana_tls_key.arn },
    ]
    healthCheck = {
      command     = ["CMD-SHELL", "curl -fsk -o /dev/null https://localhost/api/health || exit 1"]
      interval    = 30
      timeout     = 5
      retries     = 3
      startPeriod = 90
    }
    logConfiguration = {
      logDriver = "awslogs"
      options = {
        awslogs-group         = aws_cloudwatch_log_group.grafana.name
        awslogs-region        = var.aws_region
        awslogs-stream-prefix = "grafana"
      }
    }
  }])

  depends_on = [terraform_data.grafana_image]
}

resource "aws_ecs_service" "grafana" {
  name                    = local.grafana_service
  cluster                 = aws_ecs_cluster.this.id
  task_definition         = aws_ecs_task_definition.grafana.arn
  desired_count           = 1
  launch_type             = "FARGATE"
  platform_version        = "LATEST"
  enable_ecs_managed_tags = true
  propagate_tags          = "SERVICE"
  # The old task keeps serving until the new one is healthy; dnssync then
  # moves the record.
  deployment_minimum_healthy_percent = 100
  deployment_maximum_percent         = 200

  deployment_circuit_breaker {
    enable   = true
    rollback = true
  }

  network_configuration {
    subnets          = data.aws_subnets.default.ids
    security_groups  = [aws_security_group.grafana.id]
    assign_public_ip = true
  }

  depends_on = [aws_iam_role_policy.grafana_execution, aws_iam_role_policy.grafana_task]
}
