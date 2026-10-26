# Points the proxied Grafana record at the public IP of the running task.
# Runs on ECS task state changes of the Grafana service and every 10 minutes.

locals {
  cloudflare_token_parameter = "/heimdall/cloudflare/api_token"
}

resource "aws_cloudwatch_log_group" "dnssync" {
  name              = "/aws/lambda/heimdall-dnssync"
  retention_in_days = var.log_retention_days
}

resource "aws_iam_role" "dnssync" {
  name               = "heimdall-dnssync"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json
}

data "aws_iam_policy_document" "dnssync" {
  statement {
    sid       = "Logs"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.dnssync.arn}:*"]
  }
  statement {
    sid       = "ListTasks"
    actions   = ["ecs:ListTasks"]
    resources = ["*"]
    condition {
      test     = "ArnEquals"
      variable = "ecs:cluster"
      values   = [aws_ecs_cluster.this.arn]
    }
  }
  statement {
    sid       = "DescribeTasks"
    actions   = ["ecs:DescribeTasks"]
    resources = ["arn:aws:ecs:${var.aws_region}:${var.aws_account_id}:task/${aws_ecs_cluster.this.name}/*"]
  }
  statement {
    sid       = "TaskAddress"
    actions   = ["ec2:DescribeNetworkInterfaces"]
    resources = ["*"]
  }
  statement {
    sid       = "CloudflareToken"
    actions   = ["ssm:GetParameter"]
    resources = ["arn:aws:ssm:${var.aws_region}:${var.aws_account_id}:parameter${local.cloudflare_token_parameter}"]
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
}

resource "aws_iam_role_policy" "dnssync" {
  name   = "dnssync"
  role   = aws_iam_role.dnssync.id
  policy = data.aws_iam_policy_document.dnssync.json
}

resource "aws_lambda_function" "dnssync" {
  function_name    = "heimdall-dnssync"
  role             = aws_iam_role.dnssync.arn
  runtime          = "python3.13"
  architectures    = ["arm64"]
  handler          = "heimdall_cloud.dnssync.lambda_handler"
  filename         = data.archive_file.ingest.output_path
  source_code_hash = data.archive_file.ingest.output_base64sha256
  memory_size      = 128
  timeout          = 30

  environment {
    variables = {
      CLUSTER         = aws_ecs_cluster.this.name
      SERVICE         = aws_ecs_service.grafana.name
      ZONE_ID         = data.cloudflare_zone.this[0].id
      RECORD_ID       = cloudflare_dns_record.grafana.id
      RECORD_NAME     = local.grafana_domain
      ALLOWED_SUFFIX  = local.grafana_domain
      TOKEN_PARAMETER = local.cloudflare_token_parameter
    }
  }

  logging_config {
    log_format = "Text"
    log_group  = aws_cloudwatch_log_group.dnssync.name
  }

  depends_on = [aws_iam_role_policy.dnssync]
}

resource "aws_cloudwatch_event_rule" "grafana_tasks" {
  name        = "heimdall-grafana-tasks"
  description = "Grafana task started or stopped"
  event_pattern = jsonencode({
    source        = ["aws.ecs"]
    "detail-type" = ["ECS Task State Change"]
    detail = {
      clusterArn = [aws_ecs_cluster.this.arn]
      group      = ["service:${local.grafana_service}"]
      lastStatus = ["RUNNING", "STOPPED"]
    }
  })
}

resource "aws_cloudwatch_event_rule" "dnssync_schedule" {
  name                = "heimdall-dnssync-schedule"
  description         = "Periodic Grafana record check"
  schedule_expression = "rate(10 minutes)"
}

resource "aws_cloudwatch_event_target" "dnssync" {
  for_each = {
    tasks    = aws_cloudwatch_event_rule.grafana_tasks.name
    schedule = aws_cloudwatch_event_rule.dnssync_schedule.name
  }
  rule = each.value
  arn  = aws_lambda_function.dnssync.arn
}

resource "aws_lambda_permission" "dnssync" {
  for_each = {
    tasks    = aws_cloudwatch_event_rule.grafana_tasks.arn
    schedule = aws_cloudwatch_event_rule.dnssync_schedule.arn
  }
  statement_id  = "AllowEventBridge-${each.key}"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.dnssync.function_name
  principal     = "events.amazonaws.com"
  source_arn    = each.value
}
