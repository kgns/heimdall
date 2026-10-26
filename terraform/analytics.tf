# Daily analysis (cloud/src/heimdall_cloud/analytics.py). A scheduled Lambda
# runs Athena queries over the previous UTC day and writes gzip JSON lines
# to derived/<table>/dt=<day>/ in the raw bucket, read through the tables
# below.

locals {
  derived_tables = {
    daily_service = {
      description = "Per device, service and kind: percentiles, loss, jitter and busy-hour inflation for one day"
      columns = [
        ["device", "string"], ["category", "string"], ["service", "string"], ["kind", "string"],
        ["samples", "bigint"], ["targets", "bigint"], ["p50", "double"], ["p95", "double"], ["p99", "double"],
        ["loss_pct", "double"], ["busy_p50", "double"], ["night_p50", "double"], ["busy_loss_pct", "double"],
        ["jitter_ms", "double"], ["busy_inflation", "double"],
      ]
    }
    daily_compare = {
      description = "Per CPE service and UTC hour: CPE and AWS control medians relative to their best hour, and the attribution"
      columns = [
        ["device", "string"], ["service", "string"], ["hour", "int"], ["cpe_p50", "double"], ["cpe_ratio", "double"],
        ["control_p50", "double"], ["control_ratio", "double"], ["attribution", "string"],
      ]
    }
    ip_asn = {
      description = "Origin AS of router addresses seen in traceroutes (RIPEstat)"
      columns     = [["ip", "string"], ["asn", "bigint"], ["prefix", "string"], ["as_name", "string"]]
    }
    atlas_ping = {
      description = "RIPE Atlas built-in root server pings from other probes in each CPE's ISP, per probe and UTC hour"
      columns = [
        ["probe_id", "bigint"], ["asn", "bigint"], ["target", "string"], ["msm_id", "bigint"], ["hour", "int"],
        ["p50", "double"], ["min", "double"], ["results", "bigint"], ["loss_pct", "double"],
      ]
    }
    external_events = {
      description = "Outage events from public sources (IODA) for each CPE's ISP and country"
      columns = [
        ["source", "string"], ["entity", "string"], ["start_s", "bigint"], ["end_s", "bigint"],
        ["datasource", "string"], ["method", "string"], ["score", "double"],
      ]
    }
    path_borders = {
      description = "Per device and target: where the day's most frequent path leaves the device's own network"
      columns = [
        ["device", "string"], ["service", "string"], ["target_id", "string"], ["dst_ip", "string"],
        ["traces", "bigint"], ["paths", "bigint"], ["main_path_share", "double"], ["hop_count", "bigint"],
        ["as_path", "array<bigint>"], ["border_ttl", "bigint"], ["border_ip", "string"], ["next_asn", "bigint"],
        ["border_rtt_ms", "double"], ["last_home_ip", "string"], ["last_home_rtt_ms", "double"],
        ["border_jump_ms", "double"],
      ]
    }
  }
  # Each device's own network, for finding where paths leave it.
  home_asn = { "ex7501-home" = 34984, (local.cloud_device) = 16509 }
}

resource "aws_glue_catalog_table" "derived" {
  for_each      = local.derived_tables
  name          = each.key
  database_name = aws_glue_catalog_database.this.name
  table_type    = "EXTERNAL_TABLE"
  description   = each.value.description

  parameters = {
    "classification"              = "json"
    "EXTERNAL"                    = "TRUE"
    "projection.enabled"          = "true"
    "projection.dt.type"          = "date"
    "projection.dt.format"        = "yyyy-MM-dd"
    "projection.dt.range"         = "2026-10-01,NOW"
    "projection.dt.interval"      = "1"
    "projection.dt.interval.unit" = "DAYS"
    "storage.location.template"   = "s3://${aws_s3_bucket.raw.bucket}/derived/${each.key}/dt=$${dt}/"
  }

  partition_keys {
    name = "dt"
    type = "string"
  }

  storage_descriptor {
    location      = "s3://${aws_s3_bucket.raw.bucket}/derived/${each.key}/"
    input_format  = "org.apache.hadoop.mapred.TextInputFormat"
    output_format = "org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat"

    ser_de_info {
      serialization_library = "org.openx.data.jsonserde.JsonSerDe"
    }

    dynamic "columns" {
      for_each = each.value.columns
      content {
        name = columns.value[0]
        type = columns.value[1]
      }
    }
  }
}

resource "aws_cloudwatch_log_group" "analytics" {
  name              = "/aws/lambda/heimdall-analytics"
  retention_in_days = var.log_retention_days
}

resource "aws_iam_role" "analytics" {
  name               = "heimdall-analytics"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json
}

data "aws_iam_policy_document" "analytics" {
  statement {
    sid       = "Logs"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.analytics.arn}:*"]
  }
  statement {
    sid       = "Athena"
    actions   = ["athena:StartQueryExecution", "athena:GetQueryExecution", "athena:GetQueryResults", "athena:StopQueryExecution", "athena:GetWorkGroup"]
    resources = [aws_athena_workgroup.this.arn]
  }
  statement {
    sid     = "Glue"
    actions = ["glue:GetDatabase", "glue:GetTable", "glue:GetTables", "glue:GetPartition", "glue:GetPartitions", "glue:BatchGetPartition"]
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
    sid       = "WriteDerived"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.raw.arn}/derived/*"]
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

resource "aws_iam_role_policy" "analytics" {
  name   = "analytics"
  role   = aws_iam_role.analytics.id
  policy = data.aws_iam_policy_document.analytics.json
}

resource "aws_lambda_function" "analytics" {
  function_name    = "heimdall-analytics"
  role             = aws_iam_role.analytics.arn
  runtime          = "python3.13"
  architectures    = ["arm64"]
  handler          = "heimdall_cloud.analytics.lambda_handler"
  filename         = data.archive_file.ingest.output_path
  source_code_hash = data.archive_file.ingest.output_base64sha256
  memory_size      = 512
  timeout          = 900

  environment {
    variables = {
      WORKGROUP      = aws_athena_workgroup.this.name
      BUCKET         = aws_s3_bucket.raw.bucket
      CONTROL_DEVICE = local.cloud_device
      HOME_ASN       = jsonencode(local.home_asn)
      COUNTRY        = "TR"
    }
  }

  logging_config {
    log_format = "Text"
    log_group  = aws_cloudwatch_log_group.analytics.name
  }

  depends_on = [aws_iam_role_policy.analytics]
}

# 00:30 UTC, for the day that just ended.
resource "aws_cloudwatch_event_rule" "analytics" {
  name                = "heimdall-analytics-daily"
  description         = "Daily analysis of the previous UTC day"
  schedule_expression = "cron(30 0 * * ? *)"
}

resource "aws_cloudwatch_event_target" "analytics" {
  rule = aws_cloudwatch_event_rule.analytics.name
  arn  = aws_lambda_function.analytics.arn
}

resource "aws_lambda_permission" "analytics" {
  statement_id  = "AllowEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.analytics.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.analytics.arn
}

resource "aws_lambda_function_event_invoke_config" "analytics" {
  function_name          = aws_lambda_function.analytics.function_name
  maximum_retry_attempts = 1
}

# Runs the analysis once for each listed day at apply time, for backfills:
#   terraform apply -var 'analytics_backfill=["2026-10-26"]'
resource "aws_lambda_invocation" "analytics_backfill" {
  for_each      = toset(var.analytics_backfill)
  function_name = aws_lambda_function.analytics.function_name
  input         = jsonencode({ date = each.value })
}
