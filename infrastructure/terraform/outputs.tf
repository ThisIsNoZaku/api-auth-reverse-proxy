output "proxy_url" {
  description = "HTTPS HTTP API endpoint. JWT validation is performed by the Lambda application."
  value       = aws_apigatewayv2_api.proxy.api_endpoint
}
