locals {
  # Columns of the samples table. Firehose converts each JSON record to
  # Parquet with this schema; JSON keys that are not columns (including the
  # partition keys device, dt and hour) are dropped from the file.
  sample_columns = [
    { name = "ts_ms", type = "bigint", comment = "probe wall clock at measurement start, ms since epoch" },
    { name = "seq", type = "bigint", comment = "per-run sample sequence number" },
    { name = "kind", type = "string" },
    { name = "category", type = "string" },
    { name = "service", type = "string" },
    { name = "target_id", type = "string" },
    { name = "dst_ip", type = "string" },
    { name = "dst_port", type = "int" },
    { name = "rtt_ms", type = "double", comment = "null when no answer" },
    { name = "status", type = "string" },
    { name = "resolver_id", type = "string" },
    { name = "extra", type = "string", comment = "kind-specific fields as a JSON object" },
    { name = "recv_ts_ms", type = "bigint", comment = "ingest receive time" },
    { name = "src_ip", type = "string", comment = "public address the batch came from" },
    { name = "src_asn", type = "int" },
    { name = "run_id", type = "string", comment = "probe process instance; (device, run_id, seq) is unique" },
    { name = "batch_seq", type = "bigint" },
    { name = "probe_version", type = "string" },
    { name = "clock_offset_ms", type = "double", comment = "probe clock offset when the batch was sent; positive means the probe clock is behind" },
  ]
}

resource "aws_glue_catalog_database" "this" {
  name        = local.name
  description = "heimdall latency samples and analysis tables"
}

resource "aws_glue_catalog_table" "samples" {
  name          = "samples"
  database_name = aws_glue_catalog_database.this.name
  table_type    = "EXTERNAL_TABLE"
  description   = "Raw probe samples, one row per measurement or event"

  parameters = {
    "classification"              = "parquet"
    "EXTERNAL"                    = "TRUE"
    "parquet.compression"         = "SNAPPY"
    "projection.enabled"          = "true"
    "projection.device.type"      = "enum"
    "projection.device.values"    = join(",", var.devices)
    "projection.dt.type"          = "date"
    "projection.dt.format"        = "yyyy-MM-dd"
    "projection.dt.range"         = "2026-10-01,NOW"
    "projection.dt.interval"      = "1"
    "projection.dt.interval.unit" = "DAYS"
    "projection.hour.type"        = "integer"
    "projection.hour.range"       = "0,23"
    "projection.hour.digits"      = "2"
    "storage.location.template"   = "s3://${aws_s3_bucket.raw.bucket}/raw/device=$${device}/dt=$${dt}/hour=$${hour}/"
  }

  partition_keys {
    name = "device"
    type = "string"
  }
  partition_keys {
    name = "dt"
    type = "string"
  }
  partition_keys {
    name = "hour"
    type = "string"
  }

  storage_descriptor {
    location      = "s3://${aws_s3_bucket.raw.bucket}/raw/"
    input_format  = "org.apache.hadoop.hive.ql.io.parquet.MapredParquetInputFormat"
    output_format = "org.apache.hadoop.hive.ql.io.parquet.MapredParquetOutputFormat"

    ser_de_info {
      serialization_library = "org.apache.hadoop.hive.ql.io.parquet.serde.ParquetHiveSerDe"
      parameters = {
        "serialization.format" = "1"
      }
    }

    dynamic "columns" {
      for_each = local.sample_columns
      content {
        name    = columns.value.name
        type    = columns.value.type
        comment = lookup(columns.value, "comment", null)
      }
    }
  }
}

resource "aws_athena_workgroup" "this" {
  name          = local.name
  force_destroy = false

  configuration {
    enforce_workgroup_configuration    = true
    publish_cloudwatch_metrics_enabled = true
    bytes_scanned_cutoff_per_query     = 10 * 1024 * 1024 * 1024

    result_configuration {
      output_location = "s3://${aws_s3_bucket.athena.bucket}/results/"
      encryption_configuration {
        encryption_option = "SSE_S3"
      }
    }
  }
}
