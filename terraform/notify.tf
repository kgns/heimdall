# Incident notifications. Probes detect incidents and send incident_*
# events with their samples; the ingest Lambda hands those to the notifier,
# which keeps open incidents per device in DynamoDB, compares a CPE's
# incident with the cloud control probe's, and posts to Slack when the
# webhook URL parameter exists.

locals {
  slack_webhook_parameter = "/heimdall/slack/webhook_url"
  # Probes on mesh extenders and the CPE whose home network they are part
  # of; their incidents are posted under the CPE's name.
  extender_sites = { "wx5600-ap-17479" = "ex7501-home" }
}

resource "aws_dynamodb_table" "incidents" {
  name         = "heimdall-incidents"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "device"
  range_key    = "incident_id"

  attribute {
    name = "device"
    type = "S"
  }
  attribute {
    name = "incident_id"
    type = "S"
  }

  ttl {
    attribute_name = "ttl"
    enabled        = true
  }

  server_side_encryption {
    enabled = true
  }
}

resource "aws_cloudwatch_log_group" "notifier" {
  name              = "/aws/lambda/heimdall-notifier"
  retention_in_days = var.log_retention_days
}

resource "aws_iam_role" "notifier" {
  name               = "heimdall-notifier"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json
}

data "aws_iam_policy_document" "notifier" {
  statement {
    sid       = "Logs"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.notifier.arn}:*"]
  }
  statement {
    sid       = "Incidents"
    actions   = ["dynamodb:PutItem", "dynamodb:UpdateItem", "dynamodb:GetItem", "dynamodb:Query"]
    resources = [aws_dynamodb_table.incidents.arn]
  }
  statement {
    sid     = "Secrets"
    actions = ["ssm:GetParameter"]
    resources = [
      "arn:aws:ssm:${var.aws_region}:${var.aws_account_id}:parameter${local.slack_webhook_parameter}",
      aws_ssm_parameter.link_secret.arn,
    ]
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

resource "aws_iam_role_policy" "notifier" {
  name   = "notifier"
  role   = aws_iam_role.notifier.id
  policy = data.aws_iam_policy_document.notifier.json
}

resource "aws_lambda_function" "notifier" {
  function_name    = "heimdall-notifier"
  role             = aws_iam_role.notifier.arn
  runtime          = "python3.13"
  architectures    = ["arm64"]
  handler          = "heimdall_cloud.notify.lambda_handler"
  filename         = data.archive_file.ingest.output_path
  source_code_hash = data.archive_file.ingest.output_base64sha256
  # More memory brings more CPU: a cold start at 128 MB took about 7 s
  # before the first Slack post.
  memory_size = 512
  timeout     = 30

  environment {
    variables = {
      TABLE             = aws_dynamodb_table.incidents.name
      WEBHOOK_PARAMETER = local.slack_webhook_parameter
      CONTROL_DEVICE    = local.cloud_device
      GRAFANA_URL       = "https://${local.grafana_domain}/"
      DEVICE_ASN        = jsonencode({ for d, a in local.home_asn : d => a if d != local.cloud_device })
      EXTENDER_SITES    = jsonencode(local.extender_sites)
      # Status page links in the posts.
      STATUS_URL            = local.status_url
      LINK_SECRET_PARAMETER = aws_ssm_parameter.link_secret.name
    }
  }

  logging_config {
    log_format = "Text"
    log_group  = aws_cloudwatch_log_group.notifier.name
  }

  depends_on = [aws_iam_role_policy.notifier]
}

resource "aws_lambda_function_event_invoke_config" "notifier" {
  function_name                = aws_lambda_function.notifier.function_name
  maximum_retry_attempts       = 1
  maximum_event_age_in_seconds = 3600
}
