# Daily written report (cloud/src/heimdall_cloud/report.py). A language
# model reads the day's analysis summary and writes a short report, stored
# at derived/report/dt=<day>/<device>.md and posted to Slack. The analytics
# Lambda starts it after each run.
#
# The default writer is Kiro CLI in headless mode, authenticated with the
# API key in SSM /heimdall/kiro/api_key. The Lambda is a container image
# because it carries the Kiro CLI binaries. With report_writer = "bedrock" a
# Bedrock model or inference profile is called instead.

variable "report_writer" {
  description = "kiro (Kiro CLI headless) or bedrock."
  type        = string
  default     = "kiro"
  validation {
    condition     = contains(["kiro", "bedrock"], var.report_writer)
    error_message = "report_writer must be kiro or bedrock."
  }
}

variable "report_model" {
  description = "Kiro model name (kiro-cli chat --list-models) or Bedrock model / inference profile ID."
  type        = string
  default     = "claude-sonnet-5.5"
}

locals {
  kiro_key_parameter = "/heimdall/kiro/api_key"
  report_sources = concat(
    ["${path.module}/../cloud/report.Dockerfile"],
    [for f in sort(fileset("${path.module}/../cloud/src/heimdall_cloud", "*.py")) : "${path.module}/../cloud/src/heimdall_cloud/${f}"],
  )
  report_image_tag = substr(sha256(join("\n", [for f in local.report_sources : "${f}:${filesha256(f)}"])), 0, 16)
}

resource "aws_ecr_repository" "report" {
  name                 = "heimdall-report"
  image_tag_mutability = "IMMUTABLE"

  image_scanning_configuration {
    scan_on_push = true
  }
}

resource "aws_ecr_lifecycle_policy" "report" {
  repository = aws_ecr_repository.report.name
  policy = jsonencode({
    rules = [{
      rulePriority = 1
      description  = "keep the last 3 images"
      selection    = { tagStatus = "any", countType = "imageCountMoreThan", countNumber = 3 }
      action       = { type = "expire" }
    }]
  })
}

resource "terraform_data" "report_image" {
  triggers_replace = [aws_ecr_repository.report.repository_url, local.report_image_tag]

  provisioner "local-exec" {
    command = "${path.module}/../scripts/push-image ${aws_ecr_repository.report.repository_url} ${local.report_image_tag} ${path.module}/../cloud ${path.module}/../cloud/report.Dockerfile"
  }
}

resource "aws_cloudwatch_log_group" "report" {
  name              = "/aws/lambda/heimdall-report"
  retention_in_days = var.log_retention_days
}

resource "aws_iam_role" "report" {
  name               = "heimdall-report"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json
}

data "aws_iam_policy_document" "report" {
  statement {
    sid       = "Logs"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.report.arn}:*"]
  }
  dynamic "statement" {
    for_each = var.report_writer == "bedrock" ? [1] : []
    content {
      sid     = "Model"
      actions = ["bedrock:InvokeModel"]
      resources = [
        "arn:aws:bedrock:${var.aws_region}:${var.aws_account_id}:inference-profile/${var.report_model}",
        "arn:aws:bedrock:*::foundation-model/${replace(var.report_model, "/^(eu|global)\\./", "")}",
      ]
    }
  }
  statement {
    sid       = "ReadSummaries"
    actions   = ["s3:GetObject"]
    resources = ["${aws_s3_bucket.raw.arn}/derived/summary/*"]
  }
  statement {
    sid       = "ListDerived"
    actions   = ["s3:ListBucket"]
    resources = [aws_s3_bucket.raw.arn]
    condition {
      test     = "StringLike"
      variable = "s3:prefix"
      values   = ["derived/summary/*"]
    }
  }
  statement {
    sid       = "WriteReports"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.raw.arn}/derived/report/*"]
  }
  statement {
    sid     = "Secrets"
    actions = ["ssm:GetParameter"]
    resources = [
      "arn:aws:ssm:${var.aws_region}:${var.aws_account_id}:parameter${local.slack_webhook_parameter}",
      "arn:aws:ssm:${var.aws_region}:${var.aws_account_id}:parameter${local.kiro_key_parameter}",
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

resource "aws_iam_role_policy" "report" {
  name   = "report"
  role   = aws_iam_role.report.id
  policy = data.aws_iam_policy_document.report.json
}

resource "aws_lambda_function" "report" {
  function_name = "heimdall-report"
  role          = aws_iam_role.report.arn
  package_type  = "Image"
  image_uri     = "${aws_ecr_repository.report.repository_url}:${local.report_image_tag}"
  architectures = ["arm64"]
  # Kiro CLI is a large binary; it needs the memory and room in /tmp.
  memory_size = 1024
  timeout     = 300

  ephemeral_storage {
    size = 1024
  }

  environment {
    variables = {
      BUCKET             = aws_s3_bucket.raw.bucket
      WRITER             = var.report_writer
      MODEL_ID           = var.report_model
      KIRO_KEY_PARAMETER = local.kiro_key_parameter
      WEBHOOK_PARAMETER  = local.slack_webhook_parameter
    }
  }

  logging_config {
    log_format = "Text"
    log_group  = aws_cloudwatch_log_group.report.name
  }

  depends_on = [aws_iam_role_policy.report, terraform_data.report_image]
}

resource "aws_lambda_function_event_invoke_config" "report" {
  function_name          = aws_lambda_function.report.function_name
  maximum_retry_attempts = 1
}
