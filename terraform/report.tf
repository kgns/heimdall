# Daily written report (cloud/src/heimdall_cloud/report.py): Claude on
# Amazon Bedrock reads the day's analysis summary and writes a short
# report, stored at derived/report/dt=<day>/<device>.md and posted to
# Slack. The analytics Lambda starts it after each run.

variable "report_model" {
  description = "Bedrock model or inference profile ID for the daily report."
  type        = string
  default     = "eu.anthropic.claude-sonnet-5-5"
}

locals {
  # The EU inference profile routes to the model in any EU region.
  report_foundation_model = trimprefix(var.report_model, "eu.")
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
  statement {
    sid     = "Model"
    actions = ["bedrock:InvokeModel"]
    resources = [
      "arn:aws:bedrock:${var.aws_region}:${var.aws_account_id}:inference-profile/${var.report_model}",
      "arn:aws:bedrock:*::foundation-model/${local.report_foundation_model}",
    ]
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
    sid       = "Webhook"
    actions   = ["ssm:GetParameter"]
    resources = ["arn:aws:ssm:${var.aws_region}:${var.aws_account_id}:parameter${local.slack_webhook_parameter}"]
  }
  statement {
    sid       = "DecryptWebhook"
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
  function_name    = "heimdall-report"
  role             = aws_iam_role.report.arn
  runtime          = "python3.13"
  architectures    = ["arm64"]
  handler          = "heimdall_cloud.report.lambda_handler"
  filename         = data.archive_file.ingest.output_path
  source_code_hash = data.archive_file.ingest.output_base64sha256
  memory_size      = 256
  timeout          = 180

  environment {
    variables = {
      BUCKET            = aws_s3_bucket.raw.bucket
      MODEL_ID          = var.report_model
      WEBHOOK_PARAMETER = local.slack_webhook_parameter
    }
  }

  logging_config {
    log_format = "Text"
    log_group  = aws_cloudwatch_log_group.report.name
  }

  depends_on = [aws_iam_role_policy.report]
}

resource "aws_lambda_function_event_invoke_config" "report" {
  function_name          = aws_lambda_function.report.function_name
  maximum_retry_attempts = 1
}
