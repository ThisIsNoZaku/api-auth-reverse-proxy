data "aws_partition" "current" {}

locals {
  name        = "api-auth-proxy-tf-${var.environment}"
  registry    = jsondecode(var.registry_json)
  public_keys = jsondecode(var.public_keys_json)
  secret_arns = distinct([for api in local.registry : api.secretArn])
  lambda_environment = {
    API_REGISTRY    = jsonencode(local.registry)
    JWT_PUBLIC_KEYS = jsonencode(local.public_keys)
    JWT_ISSUER      = var.issuer
    JWT_AUDIENCE    = var.audience
  }
  environment_base64 = base64encode(join("", [for key, value in local.lambda_environment : "${key}${value}"]))
  environment_bytes  = length(local.environment_base64) * 3 / 4 - (endswith(local.environment_base64, "==") ? 2 : endswith(local.environment_base64, "=") ? 1 : 0)
}

resource "aws_cloudwatch_log_group" "lambda" {
  name              = "/aws/lambda/${local.name}"
  retention_in_days = var.log_retention_days
}

resource "aws_cloudwatch_log_group" "api" {
  name              = "/aws/apigateway/${local.name}"
  retention_in_days = var.log_retention_days
}

resource "aws_iam_role" "lambda" {
  name = "${local.name}-lambda"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = "lambda.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy" "lambda" {
  name = "${local.name}-runtime"
  role = aws_iam_role.lambda.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat([
      {
        Effect   = "Allow"
        Action   = ["logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = ["${aws_cloudwatch_log_group.lambda.arn}:*"]
      },
      {
        Effect   = "Allow"
        Action   = ["secretsmanager:GetSecretValue"]
        Resource = local.secret_arns
      }
      ], length(var.kms_key_arns) == 0 ? [] : [{
        Effect   = "Allow"
        Action   = ["kms:Decrypt"]
        Resource = distinct(var.kms_key_arns)
        Condition = {
          StringEquals = {
            "kms:ViaService" = "secretsmanager.${var.region}.${data.aws_partition.current.dns_suffix}"
          }
        }
    }])
  })
}

resource "aws_lambda_function" "proxy" {
  function_name                  = local.name
  filename                       = "${path.module}/../../dist/lambda.zip"
  source_code_hash               = filebase64sha256("${path.module}/../../dist/lambda.zip")
  role                           = aws_iam_role.lambda.arn
  runtime                        = "nodejs24.x"
  architectures                  = ["arm64"]
  handler                        = "index.handler"
  memory_size                    = var.memory_size
  timeout                        = var.timeout_seconds
  reserved_concurrent_executions = var.reserved_concurrency
  environment {
    variables = local.lambda_environment
  }
  lifecycle {
    precondition {
      condition     = local.environment_bytes <= 4096
      error_message = "The Lambda environment exceeds AWS's 4096-byte combined key/value limit. Reduce the registry or public JWKS."
    }
  }
  depends_on = [aws_iam_role_policy.lambda, aws_cloudwatch_log_group.lambda]
}

resource "aws_apigatewayv2_api" "proxy" {
  name                         = local.name
  protocol_type                = "HTTP"
  disable_execute_api_endpoint = false
}

resource "aws_apigatewayv2_integration" "proxy" {
  api_id                 = aws_apigatewayv2_api.proxy.id
  integration_type       = "AWS_PROXY"
  integration_uri        = aws_lambda_function.proxy.invoke_arn
  payload_format_version = "2.0"
  timeout_milliseconds   = var.timeout_seconds * 1000
}

resource "aws_apigatewayv2_route" "default" {
  api_id             = aws_apigatewayv2_api.proxy.id
  route_key          = "$default"
  authorization_type = "NONE"
  target             = "integrations/${aws_apigatewayv2_integration.proxy.id}"
}

resource "aws_apigatewayv2_stage" "default" {
  api_id      = aws_apigatewayv2_api.proxy.id
  name        = "$default"
  auto_deploy = true
  default_route_settings {
    throttling_rate_limit  = var.rate_limit
    throttling_burst_limit = var.burst_limit
  }
  access_log_settings {
    destination_arn = aws_cloudwatch_log_group.api.arn
    format = jsonencode({
      requestId          = "$context.requestId"
      status             = "$context.status"
      responseLatency    = "$context.responseLatency"
      integrationLatency = "$context.integrationLatency"
    })
  }
}

resource "aws_lambda_permission" "api" {
  statement_id  = "AllowHttpApi"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.proxy.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_apigatewayv2_api.proxy.execution_arn}/*/*"
}

resource "aws_cloudwatch_metric_alarm" "lambda" {
  for_each = {
    Errors    = { statistic = "Sum", threshold = 1 }
    Throttles = { statistic = "Sum", threshold = 1 }
    Duration  = { statistic = "Maximum", threshold = coalesce(var.duration_alarm_threshold_ms, var.timeout_seconds * 800) }
  }
  alarm_name          = "${local.name}-${lower(each.key)}"
  namespace           = "AWS/Lambda"
  metric_name         = each.key
  statistic           = each.value.statistic
  period              = 60
  evaluation_periods  = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  threshold           = each.value.threshold
  treat_missing_data  = "notBreaching"
  dimensions          = { FunctionName = aws_lambda_function.proxy.function_name }
}

resource "aws_cloudwatch_metric_alarm" "api_5xx" {
  alarm_name          = "${local.name}-api-5xx"
  namespace           = "AWS/ApiGateway"
  metric_name         = "5xx"
  statistic           = "Sum"
  period              = 60
  evaluation_periods  = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  threshold           = 1
  treat_missing_data  = "notBreaching"
  dimensions          = { ApiId = aws_apigatewayv2_api.proxy.id }
}
