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

output "grafana_url" {
  value = "https://${local.grafana_domain}/"
}

output "grafana_admin_password_parameter" {
  description = "SSM SecureString with the password of the Grafana user admin."
  value       = aws_ssm_parameter.grafana_admin_password.name
}

output "reflector_ip" {
  value = aws_eip.reflector.public_ip
}

output "reflector_host" {
  value = local.reflector_domain
}
