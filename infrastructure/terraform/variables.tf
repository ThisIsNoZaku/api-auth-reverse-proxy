variable "registry_json" {
  description = "Public API registry JSON array; secretArn values must be exact existing Secrets Manager ARNs, never secret values."
  type        = string
  validation {
    condition = try(length(jsondecode(var.registry_json)) > 0 && startswith(trimspace(var.registry_json), "[") && alltrue([
      for api in jsondecode(var.registry_json) :
      can(regex("^arn:aws(-us-gov|-cn)?:secretsmanager:[a-z0-9-]+:[0-9]{12}:secret:[A-Za-z0-9/_+=.@-]+$", api.secretArn))
    ]), false)
    error_message = "registry_json must be a nonempty JSON array with an exact secretArn for every API; wildcard ARNs are forbidden."
  }
}

variable "public_keys_json" {
  description = "Public verification JWKS JSON only. Never supply private or symmetric keys."
  type        = string
  validation {
    condition = try(length(jsondecode(var.public_keys_json).keys) > 0 && startswith(jsonencode(jsondecode(var.public_keys_json).keys), "[") && alltrue([
      for key in jsondecode(var.public_keys_json).keys :
      contains(["RSA", "OKP"], key.kty) && length(key.kid) > 0 &&
      try(key.use == "sig", true) &&
      try(key.key_ops == ["verify"], true) &&
      (
        try(key.kty == "OKP" && key.crv == "Ed25519" && can(regex("^[A-Za-z0-9_-]{43}$", key.x)) && try(key.alg == "EdDSA", true), false) ||
        try(key.kty == "RSA" && length(key.n) >= 342 && can(regex("^[A-Za-z0-9_-]+$", key.n)) && can(regex("^[A-Za-z0-9_-]+$", key.e)) && try(key.alg == "RS256", true), false)
        ) && alltrue([
          for field in ["d", "p", "q", "dp", "dq", "qi", "oth", "k"] : !contains(keys(key), field)
      ])
    ]) && length(distinct([for key in jsondecode(var.public_keys_json).keys : key.kid])) == length(jsondecode(var.public_keys_json).keys), false)
    error_message = "public_keys_json must contain uniquely identified Ed25519 or RSA-2048+ public verification JWKs only, without private or symmetric key material."
  }
}

variable "kms_key_arns" {
  description = "Optional exact CMK key ARNs used by the registry's existing secrets. No KMS permissions are granted by default."
  type        = list(string)
  default     = []
  validation {
    condition = alltrue([
      for arn in var.kms_key_arns :
      can(regex("^arn:aws(-us-gov|-cn)?:kms:[a-z0-9-]+:[0-9]{12}:key/[A-Za-z0-9-]+$", arn))
    ])
    error_message = "kms_key_arns must contain exact KMS key ARNs without wildcards."
  }
}

variable "region" {
  type    = string
  default = "us-east-1"
  validation {
    condition     = can(regex("^[a-z0-9-]+$", var.region))
    error_message = "region must be an AWS region identifier."
  }
}

variable "environment" {
  type    = string
  default = "dev"
  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{0,29}$", var.environment))
    error_message = "environment must be a lowercase name, at most 30 characters."
  }
}

variable "issuer" {
  type    = string
  default = "local-token-issuer"
  validation {
    condition     = length(var.issuer) > 0
    error_message = "issuer must be nonempty."
  }
}

variable "audience" {
  type    = string
  default = "multi-api-proxy"
  validation {
    condition     = length(var.audience) > 0
    error_message = "audience must be nonempty."
  }
}

variable "memory_size" {
  type    = number
  default = 256
  validation {
    condition     = floor(var.memory_size) == var.memory_size && var.memory_size >= 128 && var.memory_size <= 10240
    error_message = "memory_size must be an integer between 128 and 10240."
  }
}

variable "timeout_seconds" {
  type    = number
  default = 30
  validation {
    condition     = floor(var.timeout_seconds) == var.timeout_seconds && var.timeout_seconds >= 1 && var.timeout_seconds <= 30
    error_message = "timeout_seconds must be an integer between 1 and 30 (HTTP API integration limit)."
  }
}

variable "reserved_concurrency" {
  type    = number
  default = 10
  validation {
    condition     = floor(var.reserved_concurrency) == var.reserved_concurrency && var.reserved_concurrency >= 1 && var.reserved_concurrency <= 1000
    error_message = "reserved_concurrency must be an integer between 1 and 1000."
  }
}

variable "rate_limit" {
  type    = number
  default = 20
  validation {
    condition     = floor(var.rate_limit) == var.rate_limit && var.rate_limit >= 1 && var.rate_limit <= 100000
    error_message = "rate_limit must be an integer between 1 and 100000."
  }
}

variable "burst_limit" {
  type    = number
  default = 10
  validation {
    condition     = floor(var.burst_limit) == var.burst_limit && var.burst_limit >= 1 && var.burst_limit <= 100000
    error_message = "burst_limit must be an integer between 1 and 100000."
  }
}

variable "log_retention_days" {
  type    = number
  default = 30
  validation {
    condition     = contains([1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1096, 1827, 2192, 2557, 2922, 3288, 3653], var.log_retention_days)
    error_message = "log_retention_days must be a supported CloudWatch retention period."
  }
}

variable "duration_alarm_threshold_ms" {
  description = "Defaults to 80 percent of the configured timeout."
  type        = number
  default     = null
  nullable    = true
  validation {
    condition     = var.duration_alarm_threshold_ms == null ? true : floor(var.duration_alarm_threshold_ms) == var.duration_alarm_threshold_ms && var.duration_alarm_threshold_ms >= 1 && var.duration_alarm_threshold_ms <= 30000
    error_message = "duration_alarm_threshold_ms must be null or an integer between 1 and 30000."
  }
}
