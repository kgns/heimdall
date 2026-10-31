# Status pages for the ISP and its customers: one page per incident, reached
# through a signed share link that the notifier puts in its Slack posts,
# and a weekly report per home (scripts/status-link prints its link).
# A Lambda behind an HTTP API serves the page and the incident's report,
# read from the incidents table, at status.<subdomain>.<zone>. The links
# are the only access control: whoever has one sees that incident.

locals {
  status_domain         = "status.${local.base_domain}"
  link_secret_parameter = "/heimdall/status/link_secret"
  status_url            = var.custom_domain ? "https://${local.status_domain}/" : "${aws_apigatewayv2_api.status.api_endpoint}/"
}

ephemeral "random_password" "link_secret" {
  length  = 48
  special = false
}

resource "aws_ssm_parameter" "link_secret" {
  name             = local.link_secret_parameter
  description      = "Signs the share links of the status pages; rotating it invalidates every link"
  type             = "SecureString"
  value_wo         = ephemeral.random_password.link_secret.result
  value_wo_version = 1
}

resource "aws_cloudwatch_log_group" "status" {
  name              = "/aws/lambda/heimdall-status"
  retention_in_days = var.log_retention_days
}

resource "aws_iam_role" "status" {
  name               = "heimdall-status"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json
}

data "aws_iam_policy_document" "status" {
  statement {
    sid       = "Logs"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.status.arn}:*"]
  }
  statement {
    sid       = "ReadIncidents"
    actions   = ["dynamodb:GetItem", "dynamodb:Query"]
    resources = [aws_dynamodb_table.incidents.arn]
  }
  statement {
    sid       = "LinkSecret"
    actions   = ["ssm:GetParameter"]
    resources = [aws_ssm_parameter.link_secret.arn]
  }
  # The daily analysis's summaries, for the home reports.
  statement {
    sid       = "DailySummaries"
    actions   = ["s3:GetObject"]
    resources = ["${aws_s3_bucket.raw.arn}/derived/summary/*"]
  }
  statement {
    sid       = "ListSummaries"
    actions   = ["s3:ListBucket"]
    resources = [aws_s3_bucket.raw.arn]
    condition {
      test     = "StringLike"
      variable = "s3:prefix"
      values   = ["derived/summary/*"]
    }
  }
  statement {
    sid       = "DecryptLinkSecret"
    actions   = ["kms:Decrypt"]
    resources = ["arn:aws:kms:${var.aws_region}:${var.aws_account_id}:key/*"]
    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["ssm.${var.aws_region}.amazonaws.com"]
    }
  }
}

resource "aws_iam_role_policy" "status" {
  name   = "status"
  role   = aws_iam_role.status.id
  policy = data.aws_iam_policy_document.status.json
}

resource "aws_lambda_function" "status" {
  function_name    = "heimdall-status"
  role             = aws_iam_role.status.arn
  runtime          = "python3.13"
  architectures    = ["arm64"]
  handler          = "heimdall_cloud.status.lambda_handler"
  filename         = data.archive_file.ingest.output_path
  source_code_hash = data.archive_file.ingest.output_base64sha256
  memory_size      = 512
  timeout          = 10

  environment {
    variables = {
      TABLE                 = aws_dynamodb_table.incidents.name
      LINK_SECRET_PARAMETER = aws_ssm_parameter.link_secret.name
      EXTENDER_SITES        = jsonencode(local.extender_sites)
      CONTROL_DEVICE        = local.cloud_device
      BUCKET                = aws_s3_bucket.raw.bucket
    }
  }

  logging_config {
    log_format = "Text"
    log_group  = aws_cloudwatch_log_group.status.name
  }

  depends_on = [aws_iam_role_policy.status]
}

resource "aws_apigatewayv2_api" "status" {
  name                         = "heimdall-status"
  protocol_type                = "HTTP"
  disable_execute_api_endpoint = var.custom_domain
}

resource "aws_apigatewayv2_integration" "status" {
  api_id                 = aws_apigatewayv2_api.status.id
  integration_type       = "AWS_PROXY"
  integration_uri        = aws_lambda_function.status.invoke_arn
  payload_format_version = "2.0"
  timeout_milliseconds   = 10000
}

resource "aws_apigatewayv2_route" "status" {
  for_each  = toset(["GET /i/{token}", "GET /api/i/{token}", "GET /h/{token}", "GET /api/h/{token}", "GET /assets/{file}"])
  api_id    = aws_apigatewayv2_api.status.id
  route_key = each.value
  target    = "integrations/${aws_apigatewayv2_integration.status.id}"
}

resource "aws_cloudwatch_log_group" "status_api" {
  name              = "/aws/apigateway/heimdall-status"
  retention_in_days = var.log_retention_days
}

resource "aws_apigatewayv2_stage" "status" {
  api_id      = aws_apigatewayv2_api.status.id
  name        = "$default"
  auto_deploy = true

  # A page refreshes every 3 s while its incident is open.
  default_route_settings {
    throttling_rate_limit  = 20
    throttling_burst_limit = 40
  }

  # The path carries the share link, so it is left out of the access log.
  access_log_settings {
    destination_arn = aws_cloudwatch_log_group.status_api.arn
    format = jsonencode({
      requestId = "$context.requestId", ip = "$context.identity.sourceIp", route = "$context.routeKey",
      status    = "$context.status", latency = "$context.responseLatency", bytes = "$context.responseLength"
    })
  }
}

resource "aws_lambda_permission" "status_api" {
  statement_id  = "AllowApiGateway"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.status.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_apigatewayv2_api.status.execution_arn}/*/*"
}

# The custom domain, as for the ingest API: an ACM certificate validated
# through Cloudflare and a DNS-only record.

resource "aws_acm_certificate" "status" {
  count             = var.custom_domain ? 1 : 0
  domain_name       = local.status_domain
  validation_method = "DNS"

  lifecycle {
    create_before_destroy = true
  }
}

resource "cloudflare_dns_record" "status_validation" {
  for_each = var.custom_domain ? {
    for o in aws_acm_certificate.status[0].domain_validation_options : o.domain_name => o
  } : {}

  zone_id = data.cloudflare_zone.this[0].id
  name    = trimsuffix(each.value.resource_record_name, ".")
  type    = each.value.resource_record_type
  content = trimsuffix(each.value.resource_record_value, ".")
  ttl     = 300
  proxied = false
  comment = "heimdall: ACM validation for ${each.key}"

  lifecycle {
    precondition {
      condition     = endswith(trimsuffix(each.value.resource_record_name, "."), ".${local.base_domain}")
      error_message = "Validation record must stay under ${local.base_domain}."
    }
  }
}

resource "aws_acm_certificate_validation" "status" {
  count                   = var.custom_domain ? 1 : 0
  certificate_arn         = aws_acm_certificate.status[0].arn
  validation_record_fqdns = [for r in cloudflare_dns_record.status_validation : r.name]
}

resource "aws_apigatewayv2_domain_name" "status" {
  count       = var.custom_domain ? 1 : 0
  domain_name = local.status_domain

  domain_name_configuration {
    certificate_arn = aws_acm_certificate_validation.status[0].certificate_arn
    endpoint_type   = "REGIONAL"
    security_policy = "TLS_1_2"
  }
}

resource "aws_apigatewayv2_api_mapping" "status" {
  count       = var.custom_domain ? 1 : 0
  api_id      = aws_apigatewayv2_api.status.id
  domain_name = aws_apigatewayv2_domain_name.status[0].id
  stage       = aws_apigatewayv2_stage.status.id
}

resource "cloudflare_dns_record" "status" {
  count   = var.custom_domain ? 1 : 0
  zone_id = data.cloudflare_zone.this[0].id
  name    = local.status_domain
  type    = "CNAME"
  content = aws_apigatewayv2_domain_name.status[0].domain_name_configuration[0].target_domain_name
  ttl     = 300
  proxied = false
  comment = "heimdall: status pages"
}
