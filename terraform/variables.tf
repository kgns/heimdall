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
  # mbp-kgns runs heimdall-client for comparisons with ex7501-home.
  # wx5600-ap-17479 is the mesh extender of ex7501-home.
  default = ["ex7501-home", "aws-euc1", "mbp-kgns", "wx5600-ap-17479"]
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

variable "grafana_anonymous" {
  description = "Let anyone with Grafana's URL view the dashboards without logging in, as a read-only Viewer. Viewers can also send their own queries to the Athena data source, so they can read every sample."
  type        = bool
  default     = true
}

variable "analytics_backfill" {
  description = "UTC days (YYYY-MM-DD) to run the daily analysis for during apply."
  type        = list(string)
  default     = []
}
