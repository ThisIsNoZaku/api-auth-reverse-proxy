mock_provider "aws" {
  mock_resource "aws_iam_role" {
    defaults = {
      arn = "arn:aws:iam::123456789012:role/mock-lambda"
    }
  }
  mock_resource "aws_cloudwatch_log_group" {
    defaults = {
      arn = "arn:aws:logs:us-east-1:123456789012:log-group:mock"
    }
  }
  mock_resource "aws_apigatewayv2_api" {
    defaults = {
      execution_arn = "arn:aws:execute-api:us-east-1:123456789012:mock"
      api_endpoint  = "https://mock.execute-api.us-east-1.amazonaws.com"
    }
  }
  mock_resource "aws_lambda_function" {
    defaults = {
      arn        = "arn:aws:lambda:us-east-1:123456789012:function:mock"
      invoke_arn = "arn:aws:apigateway:us-east-1:lambda:path/2015-03-31/functions/arn:aws:lambda:us-east-1:123456789012:function:mock/invocations"
    }
  }
}

variables {
  registry_json = jsonencode([
    {
      id             = "bearer-api"
      secretArn      = "arn:aws:secretsmanager:us-east-1:123456789012:secret:bearer-AbCdEf"
      authentication = { type = "bearer" }
      routes         = [{ path = "/status", methods = ["GET"], permissions = { GET = ["status:read"] } }]
    },
    {
      id             = "key-api"
      secretArn      = "arn:aws:secretsmanager:us-east-1:123456789012:secret:key-AbCdEf"
      authentication = { type = "apiKey", header = "x-api-key", secretField = "key" }
      routes         = [{ path = "/other", methods = ["POST"], permissions = { POST = ["other:write"] } }]
    },
  ])
  public_keys_json = jsonencode({
    keys = [
      { kty = "RSA", kid = "rsa-key", n = join("", [for index in range(342) : "w"]), e = "AQAB" },
      { kty = "OKP", kid = "ed25519-key", crv = "Ed25519", x = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo", alg = "EdDSA", use = "sig", key_ops = ["verify"] },
    ]
  })
}

run "heterogeneous_public_configuration" {
  command = apply

  assert {
    condition     = aws_lambda_function.proxy.runtime == "nodejs24.x" && aws_lambda_function.proxy.handler == "index.handler"
    error_message = "The shared Node 24 ESM Lambda artifact must be used."
  }

  assert {
    condition     = length(jsondecode(aws_iam_role_policy.lambda.policy).Statement) == 2
    error_message = "Default IAM policy must only grant logging and exact secret reads, not KMS decryption."
  }

  assert {
    condition = toset(jsondecode(aws_iam_role_policy.lambda.policy).Statement[1].Resource) == toset([
      "arn:aws:secretsmanager:us-east-1:123456789012:secret:bearer-AbCdEf",
      "arn:aws:secretsmanager:us-east-1:123456789012:secret:key-AbCdEf",
    ])
    error_message = "Secret reads must be limited to exact registry ARNs."
  }

  assert {
    condition     = aws_apigatewayv2_route.default.authorization_type == "NONE" && aws_apigatewayv2_integration.proxy.payload_format_version == "2.0"
    error_message = "The application-authenticated HTTP API must use payload version 2."
  }

  assert {
    condition     = aws_cloudwatch_metric_alarm.api_5xx.namespace == "AWS/ApiGateway" && aws_cloudwatch_metric_alarm.api_5xx.metric_name == "5xx" && aws_cloudwatch_metric_alarm.api_5xx.threshold == 1
    error_message = "HTTP API 5xx responses, including application-returned 502/504 responses, must be alarmed."
  }
}

run "reject_wildcard_secret_arn" {
  command = plan
  variables {
    registry_json = jsonencode([{ secretArn = "arn:aws:secretsmanager:us-east-1:123456789012:secret:prefix*" }])
  }
  expect_failures = [var.registry_json]
}

run "reject_private_jwk" {
  command = plan
  variables {
    public_keys_json = jsonencode({ keys = [{ kty = "RSA", n = "public", e = "AQAB", d = "not-allowed" }] })
  }
  expect_failures = [var.public_keys_json]
}

run "reject_wildcard_kms_arn" {
  command = plan
  variables {
    kms_key_arns = ["arn:aws:kms:us-east-1:123456789012:key/*"]
  }
  expect_failures = [var.kms_key_arns]
}

run "reject_oversized_environment" {
  command = plan
  variables {
    audience = join("", [for index in range(1024) : "éééé"])
  }
  expect_failures = [aws_lambda_function.proxy]
}

run "reject_weak_public_key" {
  command = plan
  variables {
    public_keys_json = jsonencode({ keys = [{ kty = "RSA", kid = "weak-key", n = "weak", e = "AQAB" }] })
  }
  expect_failures = [var.public_keys_json]
}
