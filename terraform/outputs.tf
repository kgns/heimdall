output "ingest_url" {
  description = "Where the probe posts batches."
  value       = var.custom_domain ? "https://${local.ingest_domain}/v1/batch" : "${aws_apigatewayv2_api.ingest.api_endpoint}/v1/batch"
}

output "raw_bucket" {
  value = aws_s3_bucket.raw.bucket
}

output "athena_workgroup" {
  value = aws_athena_workgroup.this.name
}

output "glue_table" {
  value = "${aws_glue_catalog_database.this.name}.${aws_glue_catalog_table.samples.name}"
}

output "firehose_stream" {
  value = aws_kinesis_firehose_delivery_stream.samples.name
}
