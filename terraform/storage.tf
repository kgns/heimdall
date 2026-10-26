locals {
  name             = "heimdall"
  raw_bucket       = "heimdall-raw-${var.aws_account_id}"
  athena_bucket    = "heimdall-athena-${var.aws_account_id}"
  artifacts_bucket = "heimdall-artifacts-${var.aws_account_id}"
}

resource "aws_s3_bucket" "raw" {
  bucket = local.raw_bucket
}

resource "aws_s3_bucket" "athena" {
  bucket = local.athena_bucket
}

# Binaries and configuration that the reflector instance installs at boot.
resource "aws_s3_bucket" "artifacts" {
  bucket = local.artifacts_bucket
}

locals {
  bucket_ids = {
    raw       = aws_s3_bucket.raw.id
    athena    = aws_s3_bucket.athena.id
    artifacts = aws_s3_bucket.artifacts.id
  }
}

resource "aws_s3_bucket_ownership_controls" "this" {
  for_each = local.bucket_ids
  bucket   = each.value
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_public_access_block" "this" {
  for_each                = local.bucket_ids
  bucket                  = each.value
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "this" {
  for_each = local.bucket_ids
  bucket   = each.value
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

data "aws_iam_policy_document" "tls_only" {
  for_each = { raw = aws_s3_bucket.raw.arn, athena = aws_s3_bucket.athena.arn, artifacts = aws_s3_bucket.artifacts.arn }
  statement {
    sid       = "DenyInsecureTransport"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [each.value, "${each.value}/*"]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

resource "aws_s3_bucket_policy" "this" {
  for_each   = local.bucket_ids
  bucket     = each.value
  policy     = data.aws_iam_policy_document.tls_only[each.key].json
  depends_on = [aws_s3_bucket_public_access_block.this]
}

resource "aws_s3_bucket_lifecycle_configuration" "raw" {
  bucket = aws_s3_bucket.raw.id

  rule {
    id     = "raw-samples"
    status = "Enabled"
    filter {
      prefix = "raw/"
    }
    expiration {
      days = var.raw_retention_days
    }
  }

  rule {
    id     = "firehose-errors"
    status = "Enabled"
    filter {
      prefix = "errors/"
    }
    expiration {
      days = 30
    }
  }

  rule {
    id     = "abort-multipart"
    status = "Enabled"
    filter {}
    abort_incomplete_multipart_upload {
      days_after_initiation = 1
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "athena" {
  bucket = aws_s3_bucket.athena.id

  rule {
    id     = "query-results"
    status = "Enabled"
    filter {}
    expiration {
      days = 7
    }
    abort_incomplete_multipart_upload {
      days_after_initiation = 1
    }
  }
}
