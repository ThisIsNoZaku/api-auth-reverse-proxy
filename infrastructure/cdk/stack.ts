import { existsSync } from 'node:fs';
import { resolve } from 'node:path';
import {
  ArnFormat, CfnOutput, Duration, Stack, type StackProps,
  aws_apigatewayv2 as apigateway, aws_cloudwatch as cloudwatch,
  aws_iam as iam, aws_lambda as lambda, aws_logs as logs,
} from 'aws-cdk-lib';
import type { Construct } from 'constructs';
import { parseConfig, type DeploymentConfig } from './config.js';

export interface ProxyStackProps extends StackProps {
  config: DeploymentConfig;
  artifactPath?: string;
}

export class ProxyStack extends Stack {
  constructor(scope: Construct, id: string, props: ProxyStackProps) {
    super(scope, id, props);
    const config = parseConfig(props.config);
    const artifact = resolve(props.artifactPath ?? 'dist/lambda.zip');
    if (!existsSync(artifact)) throw new Error('Missing dist/lambda.zip: run npm run build first');
    const name = `api-auth-proxy-cdk-${config.environment}`;
    const logGroup = new logs.LogGroup(this, 'LambdaLogs', {
      logGroupName: `/aws/lambda/${name}`,
      retention: config.logRetentionDays as logs.RetentionDays,
    });
    const role = new iam.Role(this, 'LambdaRole', {
      assumedBy: new iam.ServicePrincipal('lambda.amazonaws.com'),
    });
    role.addToPolicy(new iam.PolicyStatement({
      actions: ['logs:CreateLogStream', 'logs:PutLogEvents'],
      resources: [logGroup.logGroupArn],
    }));
    role.addToPolicy(new iam.PolicyStatement({
      actions: ['secretsmanager:GetSecretValue'],
      resources: [...new Set(config.registry.map((entry) => entry.secretArn as string))],
    }));
    if (config.kmsKeyArns.length > 0) {
      role.addToPolicy(new iam.PolicyStatement({
        actions: ['kms:Decrypt'],
        resources: [...new Set(config.kmsKeyArns)],
        conditions: { StringEquals: { 'kms:ViaService': `secretsmanager.${config.region}.${this.urlSuffix}` } },
      }));
    }
    const handler = new lambda.Function(this, 'Proxy', {
      functionName: name,
      runtime: lambda.Runtime.NODEJS_24_X,
      architecture: lambda.Architecture.ARM_64,
      code: lambda.Code.fromAsset(artifact),
      handler: 'index.handler',
      role,
      logGroup,
      memorySize: config.memorySize,
      timeout: Duration.seconds(config.timeoutSeconds),
      reservedConcurrentExecutions: config.reservedConcurrency,
      environment: {
        API_REGISTRY: JSON.stringify(config.registry),
        JWT_PUBLIC_KEYS: JSON.stringify(config.publicKeys),
        JWT_ISSUER: config.issuer,
        JWT_AUDIENCE: config.audience,
      },
    });
    const api = new apigateway.CfnApi(this, 'HttpApi', {
      name, protocolType: 'HTTP', disableExecuteApiEndpoint: false,
    });
    const integration = new apigateway.CfnIntegration(this, 'Integration', {
      apiId: api.ref, integrationType: 'AWS_PROXY', integrationUri: handler.functionArn,
      payloadFormatVersion: '2.0', timeoutInMillis: config.timeoutSeconds * 1000,
    });
    new apigateway.CfnRoute(this, 'DefaultRoute', {
      apiId: api.ref, routeKey: '$default', authorizationType: 'NONE',
      target: `integrations/${integration.ref}`,
    });
    const accessLogs = new logs.LogGroup(this, 'AccessLogs', {
      logGroupName: `/aws/apigateway/${name}`,
      retention: config.logRetentionDays as logs.RetentionDays,
    });
    new apigateway.CfnStage(this, 'DefaultStage', {
      apiId: api.ref, stageName: '$default', autoDeploy: true,
      defaultRouteSettings: { throttlingRateLimit: config.rateLimit, throttlingBurstLimit: config.burstLimit },
      accessLogSettings: {
        destinationArn: accessLogs.logGroupArn,
        format: JSON.stringify({
          requestId: '$context.requestId', status: '$context.status',
          responseLatency: '$context.responseLatency', integrationLatency: '$context.integrationLatency',
        }),
      },
    });
    new lambda.CfnPermission(this, 'ApiPermission', {
      action: 'lambda:InvokeFunction', functionName: handler.functionName,
      principal: 'apigateway.amazonaws.com',
      sourceArn: this.formatArn({
        service: 'execute-api', resource: api.ref, resourceName: '*/*', arnFormat: ArnFormat.SLASH_RESOURCE_NAME,
      }),
    });
    for (const [metric, threshold] of [
      [handler.metricErrors({ period: Duration.minutes(1), statistic: 'Sum' }), 1],
      [handler.metricThrottles({ period: Duration.minutes(1), statistic: 'Sum' }), 1],
      [handler.metricDuration({ period: Duration.minutes(1), statistic: 'Maximum' }), config.durationAlarmThresholdMs],
    ] as const) {
      new cloudwatch.Alarm(this, `${metric.metricName}Alarm`, {
        alarmName: `${name}-${metric.metricName.toLowerCase()}`,
        metric, threshold, evaluationPeriods: 1,
        comparisonOperator: cloudwatch.ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD,
        treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
      });
    }
    new cloudwatch.Alarm(this, 'Api5xxAlarm', {
      alarmName: `${name}-api-5xx`,
      metric: new cloudwatch.Metric({
        namespace: 'AWS/ApiGateway', metricName: '5xx',
        dimensionsMap: { ApiId: api.ref }, statistic: 'Sum', period: Duration.minutes(1),
      }),
      threshold: 1, evaluationPeriods: 1,
      comparisonOperator: cloudwatch.ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD,
      treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
    });
    new CfnOutput(this, 'proxy_url', { value: api.attrApiEndpoint });
  }
}
