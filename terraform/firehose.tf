resource "aws_cloudwatch_log_group" "firehose" {
  name              = "/aws/kinesisfirehose/heimdall-samples"
  retention_in_days = var.log_retention_days
}

resource "aws_cloudwatch_log_stream" "firehose" {
  name           = "DestinationDelivery"
  log_group_name = aws_cloudwatch_log_group.firehose.name
}

data "aws_iam_policy_document" "firehose_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["firehose.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "sts:ExternalId"
      values   = [var.aws_account_id]
    }
  }
}

resource "aws_iam_role" "firehose" {
  name               = "heimdall-firehose"
  assume_role_policy = data.aws_iam_policy_document.firehose_assume.json
}

data "aws_iam_policy_document" "firehose" {
  statement {
    sid = "WriteRawBucket"
    actions = [
      "s3:AbortMultipartUpload", "s3:GetBucketLocation", "s3:GetObject", "s3:ListBucket",
      "s3:ListBucketMultipartUploads", "s3:PutObject",
    ]
    resources = [aws_s3_bucket.raw.arn, "${aws_s3_bucket.raw.arn}/*"]
  }
  statement {
    sid     = "ReadSchema"
    actions = ["glue:GetTable", "glue:GetTableVersion", "glue:GetTableVersions"]
    resources = [
      "arn:aws:glue:${var.aws_region}:${var.aws_account_id}:catalog",
      "arn:aws:glue:${var.aws_region}:${var.aws_account_id}:database/${aws_glue_catalog_database.this.name}",
      "arn:aws:glue:${var.aws_region}:${var.aws_account_id}:table/${aws_glue_catalog_database.this.name}/${aws_glue_catalog_table.samples.name}",
    ]
  }
  statement {
    sid       = "Logs"
    actions   = ["logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.firehose.arn}:log-stream:*"]
  }
}

resource "aws_iam_role_policy" "firehose" {
  name   = "delivery"
  role   = aws_iam_role.firehose.id
  policy = data.aws_iam_policy_document.firehose.json
}

resource "aws_kinesis_firehose_delivery_stream" "samples" {
  name        = "heimdall-samples"
  destination = "extended_s3"

  extended_s3_configuration {
    role_arn   = aws_iam_role.firehose.arn
    bucket_arn = aws_s3_bucket.raw.arn

    # Record format conversion requires at least 64 MiB; at prototype
    # volumes the interval is what triggers delivery.
    buffering_size     = 64
    buffering_interval = 300
    # Parquet applies its own (Snappy) compression.
    compression_format  = "UNCOMPRESSED"
    custom_time_zone    = "UTC"
    file_extension      = ".parquet"
    prefix              = "raw/device=!{partitionKeyFromQuery:device}/dt=!{partitionKeyFromQuery:dt}/hour=!{partitionKeyFromQuery:hour}/"
    error_output_prefix = "errors/!{firehose:error-output-type}/dt=!{timestamp:yyyy-MM-dd}/"

    dynamic_partitioning_configuration {
      enabled = true
    }

    processing_configuration {
      enabled = true
      processors {
        type = "MetadataExtraction"
        parameters {
          parameter_name  = "JsonParsingEngine"
          parameter_value = "JQ-1.6"
        }
        parameters {
          parameter_name  = "MetadataExtractionQuery"
          parameter_value = "{device:.device,dt:.dt,hour:.hour}"
        }
      }
    }

    data_format_conversion_configuration {
      input_format_configuration {
        deserializer {
          open_x_json_ser_de {}
        }
      }
      output_format_configuration {
        serializer {
          parquet_ser_de {
            compression = "SNAPPY"
          }
        }
      }
      schema_configuration {
        database_name = aws_glue_catalog_database.this.name
        table_name    = aws_glue_catalog_table.samples.name
        role_arn      = aws_iam_role.firehose.arn
        region        = var.aws_region
      }
    }

    cloudwatch_logging_options {
      enabled         = true
      log_group_name  = aws_cloudwatch_log_group.firehose.name
      log_stream_name = aws_cloudwatch_log_stream.firehose.name
    }
  }

  depends_on = [aws_iam_role_policy.firehose]
}
