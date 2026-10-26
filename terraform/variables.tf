variable "aws_profile" {
  type    = string
  default = "kgns"
}

variable "aws_region" {
  type    = string
  default = "eu-central-1"
}

variable "aws_account_id" {
  description = "The only account this configuration may change."
  type        = string
  default     = "359519776451"
}

variable "zone" {
  description = "Cloudflare zone that holds the prototype's records."
  type        = string
  default     = "kgns.dev"
}

variable "subdomain" {
  description = "All records live under <subdomain>.<zone>."
  type        = string
  default     = "lat"
}

variable "custom_domain" {
  description = "Serve the ingest API at ingest.<subdomain>.<zone>. Needs CLOUDFLARE_API_TOKEN; without it the execute-api URL is used. Grafana (grafana.tf) always needs Cloudflare."
  type        = bool
  default     = true
}

variable "devices" {
  description = "Device IDs that may upload. Each needs a token digest in SSM; see scripts/new-device-token."
  type        = list(string)
  default     = ["ex7501-home"]
}

variable "raw_retention_days" {
  type    = number
  default = 180
}

variable "log_retention_days" {
  type    = number
  default = 14
}

variable "ingest_rate_limit" {
  description = "Steady-state requests per second the ingest API accepts across all devices."
  type        = number
  default     = 10
}

variable "ingest_burst_limit" {
  type    = number
  default = 20
}
