locals {
  base_domain   = "${var.subdomain}.${var.zone}"
  ingest_domain = "ingest.${local.base_domain}"
}

data "cloudflare_zone" "this" {
  count = var.custom_domain ? 1 : 0
  filter = {
    name = var.zone
  }
}

resource "aws_acm_certificate" "ingest" {
  count             = var.custom_domain ? 1 : 0
  domain_name       = local.ingest_domain
  validation_method = "DNS"

  lifecycle {
    create_before_destroy = true
  }
}

resource "cloudflare_dns_record" "ingest_validation" {
  for_each = var.custom_domain ? {
    for o in aws_acm_certificate.ingest[0].domain_validation_options : o.domain_name => o
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

resource "aws_acm_certificate_validation" "ingest" {
  count                   = var.custom_domain ? 1 : 0
  certificate_arn         = aws_acm_certificate.ingest[0].arn
  validation_record_fqdns = [for r in cloudflare_dns_record.ingest_validation : r.name]
}

resource "aws_apigatewayv2_domain_name" "ingest" {
  count       = var.custom_domain ? 1 : 0
  domain_name = local.ingest_domain

  domain_name_configuration {
    certificate_arn = aws_acm_certificate_validation.ingest[0].certificate_arn
    endpoint_type   = "REGIONAL"
    security_policy = "TLS_1_2"
  }
}

resource "aws_apigatewayv2_api_mapping" "ingest" {
  count       = var.custom_domain ? 1 : 0
  api_id      = aws_apigatewayv2_api.ingest.id
  domain_name = aws_apigatewayv2_domain_name.ingest[0].id
  stage       = aws_apigatewayv2_stage.default.id
}

resource "cloudflare_dns_record" "ingest" {
  count   = var.custom_domain ? 1 : 0
  zone_id = data.cloudflare_zone.this[0].id
  name    = local.ingest_domain
  type    = "CNAME"
  content = aws_apigatewayv2_domain_name.ingest[0].domain_name_configuration[0].target_domain_name
  ttl     = 300
  # DNS only: the probe talks to API Gateway directly.
  proxied = false
  comment = "heimdall: ingest API"
}
