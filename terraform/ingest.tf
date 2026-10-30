data "archive_file" "ingest" {
  type        = "zip"
  source_dir  = "${path.module}/../cloud/src"
  output_path = "${path.module}/build/ingest.zip"
  excludes    = ["**/__pycache__/**", "**/*.pyc", "heimdall_cloud/py.typed"]
}

resource "aws_cloudwatch_log_group" "ingest" {
  name              = "/aws/lambda/heimdall-ingest"
  retention_in_days = var.log_retention_days
}

data "aws_iam_policy_document" "lambda_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "ingest" {
  name               = "heimdall-ingest"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json
}

data "aws_iam_policy_document" "ingest" {
  statement {
    sid       = "Logs"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.ingest.arn}:*"]
  }
  statement {
    sid       = "Firehose"
    actions   = ["firehose:PutRecordBatch"]
    resources = [aws_kinesis_firehose_delivery_stream.samples.arn]
  }
  statement {
    sid       = "Notify"
    actions   = ["lambda:InvokeFunction"]
    resources = [aws_lambda_function.notifier.arn]
  }
  # The client names the CPEs report, for the notifier (one item per
  # client in the incidents table).
  statement {
    sid       = "ClientNames"
    actions   = ["dynamodb:PutItem"]
    resources = [aws_dynamodb_table.incidents.arn]
  }
  statement {
    sid       = "DeviceTokens"
    actions   = ["ssm:GetParameter"]
    resources = ["arn:aws:ssm:${var.aws_region}:${var.aws_account_id}:parameter/heimdall/devices/*"]
  }
  statement {
    sid       = "DecryptDeviceTokens"
    actions   = ["kms:Decrypt"]
    resources = ["arn:aws:kms:${var.aws_region}:${var.aws_account_id}:key/*"]
    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["ssm.${var.aws_region}.amazonaws.com"]
    }
  }
}

resource "aws_iam_role_policy" "ingest" {
  name   = "ingest"
  role   = aws_iam_role.ingest.id
  policy = data.aws_iam_policy_document.ingest.json
}

resource "aws_lambda_function" "ingest" {
  function_name    = "heimdall-ingest"
  role             = aws_iam_role.ingest.arn
  runtime          = "python3.13"
  architectures    = ["arm64"]
  handler          = "heimdall_cloud.ingest.lambda_handler"
  filename         = data.archive_file.ingest.output_path
  source_code_hash = data.archive_file.ingest.output_base64sha256
  memory_size      = 256
  timeout          = 15

  environment {
    variables = {
      FIREHOSE_STREAM   = aws_kinesis_firehose_delivery_stream.samples.name
      TOKEN_PREFIX      = "/heimdall/devices"
      NOTIFIER_FUNCTION = aws_lambda_function.notifier.function_name
      NAMES_TABLE       = aws_dynamodb_table.incidents.name
    }
  }

  logging_config {
    log_format = "Text"
    log_group  = aws_cloudwatch_log_group.ingest.name
  }

  depends_on = [aws_iam_role_policy.ingest]
}

resource "aws_apigatewayv2_api" "ingest" {
  name          = "heimdall-ingest"
  protocol_type = "HTTP"
  # With the custom domain in place the default endpoint is switched off,
  # so there is a single public entry point.
  disable_execute_api_endpoint = var.custom_domain
}

resource "aws_apigatewayv2_integration" "ingest" {
  api_id                 = aws_apigatewayv2_api.ingest.id
  integration_type       = "AWS_PROXY"
  integration_uri        = aws_lambda_function.ingest.invoke_arn
  payload_format_version = "2.0"
  timeout_milliseconds   = 15000
}

resource "aws_apigatewayv2_route" "batch" {
  api_id    = aws_apigatewayv2_api.ingest.id
  route_key = "POST /v1/batch"
  target    = "integrations/${aws_apigatewayv2_integration.ingest.id}"
}

resource "aws_cloudwatch_log_group" "api" {
  name              = "/aws/apigateway/heimdall-ingest"
  retention_in_days = var.log_retention_days
}

resource "aws_apigatewayv2_stage" "default" {
  api_id      = aws_apigatewayv2_api.ingest.id
  name        = "$default"
  auto_deploy = true

  default_route_settings {
    throttling_rate_limit  = var.ingest_rate_limit
    throttling_burst_limit = var.ingest_burst_limit
  }

  access_log_settings {
    destination_arn = aws_cloudwatch_log_group.api.arn
    format = jsonencode({
      requestId = "$context.requestId", ip = "$context.identity.sourceIp", route = "$context.routeKey",
      status    = "$context.status", latency = "$context.responseLatency", bytes = "$context.responseLength"
      error     = "$context.integrationErrorMessage"
    })
  }
}

resource "aws_lambda_permission" "api" {
  statement_id  = "AllowApiGateway"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.ingest.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_apigatewayv2_api.ingest.execution_arn}/*/*/v1/batch"
}
