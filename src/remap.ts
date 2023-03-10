import fs from "fs";
import { cloudwatch, iam, lambda, scheduler, sqs, ssm } from "@pulumi/aws";
import {
  ComponentResource,
  Input,
  Output,
  output,
  ResourceOptions,
} from "@pulumi/pulumi";
import { CfnElement } from "aws-cdk-lib";

import { ResourceMapping } from "@pulumi/cdk/interop.js";
import { FromPulumi } from "./bridge.js";

import * as AWS from "./cfn.generated.js";
import { isPromise } from "util/types";

export function remapCloudControlResource(
  element: CfnElement,
  logicalId: string,
  typeName: string,
  props: any = {},
  options: ResourceOptions
): ResourceMapping | undefined {
  const name = logicalId.slice(0, 92);
  // todo
  if (is<AWS.Lambda.Function>("AWS::Lambda::Function", props)) {
    if (props.FileSystemConfigs && props.FileSystemConfigs.length > 1) {
      console.warn(
        `Function.FileSystemConfigs array can only be length, falling back to Cloud Control API`
      );
      return undefined;
    }

    const func = new lambda.Function(
      name,
      {
        architectures: props.Architectures,
        // code: new RemoteAsset(),
        name: props.FunctionName,
        role: props.Role,
        runtime: props.Runtime,
        s3Bucket: props.Code.S3Bucket,
        s3Key: props.Code.S3Key,
        s3ObjectVersion: props.Code.S3ObjectVersion,
        environment: props.Environment?.Variables
          ? {
              variables: props.Environment.Variables,
            }
          : undefined,
        codeSigningConfigArn: props.CodeSigningConfigArn,
        deadLetterConfig: props.DeadLetterConfig?.TargetArn
          ? {
              targetArn: props.DeadLetterConfig?.TargetArn,
            }
          : undefined,
        description: props.Description,
        ephemeralStorage: props.EphemeralStorage
          ? {
              size: props.EphemeralStorage.Size,
            }
          : undefined,
        fileSystemConfig: props.FileSystemConfigs
          ? {
              arn: props.FileSystemConfigs[0].Arn,
              localMountPath: props.FileSystemConfigs[0].LocalMountPath,
            }
          : undefined,
        handler: props.Handler,
        imageConfig: props.ImageConfig
          ? {
              commands: props.ImageConfig.Command,
              entryPoints: props.ImageConfig.EntryPoint,
              workingDirectory: props.ImageConfig.WorkingDirectory,
            }
          : undefined,
        imageUri: props.Code.ImageUri,
        kmsKeyArn: props.KmsKeyArn,
        layers: props.Layers,
        memorySize: props.MemorySize,
        packageType: props.PackageType,

        // TODO: what should this default be?
        // publish: true

        reservedConcurrentExecutions: props.ReservedConcurrentExecutions,
        snapStart: props.SnapStart?.ApplyOn
          ? {
              applyOn: props.SnapStart?.ApplyOn,
              // TODO
              // optimizationStatus: undefined
            }
          : undefined,

        // TODO:
        // sourceCodeHash: undefined

        tags: props.Tags
          ? // @ts-ignore
            Object.fromEntries(
              // @ts-ignore
              props.Tags.map(({ Key, Value }) => ({
                // @ts-ignore
                [Key]: Value,
              }))
            )
          : undefined,

        timeout: props.Timeout,
        tracingConfig: props.TracingConfig?.Mode
          ? {
              mode: props.TracingConfig.Mode,
            }
          : undefined,
        vpcConfig:
          props.VpcConfig?.SubnetIds && props.VpcConfig?.SecurityGroupIds
            ? {
                securityGroupIds: props.VpcConfig.SecurityGroupIds,
                subnetIds: props.VpcConfig.SubnetIds,
              }
            : undefined,

        // TODO:
        // imageUri: undefined
      },
      options
    );

    return {
      attributes: {
        arn: func.arn,
        "SnapStartResponse.ApplyOn": func.snapStart?.apply(
          (st) => st?.applyOn!
        ),
        "SnapStartResponse.OptimizationStatus": func.snapStart?.apply(
          (st) => st?.optimizationStatus!
        ),
      }, // satisfies FromPulumi<Partial<AWS.Lambda.Function.Attr>>,
      resource: func,
    };
  } else if (is<AWS.IAM.Role>("AWS::IAM::Role", props)) {
    const role = new iam.Role(
      name,
      {
        assumeRolePolicy: props.AssumeRolePolicyDocument,
        description: props.Description,
        // forceDetachPolicies: false,
        inlinePolicies: props.Policies?.map((policy) => ({
          name: policy.PolicyName,
          policy: policy.PolicyDocument,
        })),
        managedPolicyArns: props.ManagedPolicyArns,
        maxSessionDuration: props.MaxSessionDuration,
        name: props.RoleName,
        // namePrefix: undefined,
        path: props.Path,
        permissionsBoundary: props.PermissionsBoundary,

        // TODO
        // tags: undefined,
      },
      options
    );

    return {
      resource: role,
      attributes: {
        arn: role.arn,
        roleId: role.uniqueId,
      },
    };
  } else if (is<AWS.Events.EventBus>("AWS::Events::EventBus", props)) {
    const bus = new cloudwatch.EventBus(
      name,
      {
        name: props.Name,
        eventSourceName: props.EventSourceName,
        // TODO
        // tags: props.Tags,
      },
      options
    );

    return {
      resource: bus,
      attributes: {
        arn: bus.arn,
        name: bus.name,
        // TODO:
        policy: output(Promise.resolve(JSON.stringify("{}"))),
      },
    };
  } else if (
    is<AWS.Scheduler.ScheduleGroup>("AWS::Scheduler::ScheduleGroup", props)
  ) {
    const sg = new scheduler.ScheduleGroup(
      name,
      {
        name: props?.Name,
        // TODO;
        // tags: props.Tags,
      },
      options
    );

    return sg;
  } else if (is<AWS.SSM.Parameter>("AWS::SSM::Parameter", props)) {
    return new ssm.Parameter(
      name,
      {
        type: props.Type,
        allowedPattern: props.AllowedPattern,
        dataType: props.DataType,
        description: props.Description,
        // CloudFormation doesn't support SecureString
        // keyId: props.
        name: props.Name,
        value: props.Value,
      },
      options
    );
  } else if (
    is<AWS.Lambda.EventInvokeConfig>("AWS::Lambda::EventInvokeConfig", props)
  ) {
    return new lambda.FunctionEventInvokeConfig(
      name,
      {
        functionName: props.FunctionName,
        destinationConfig: props.DestinationConfig
          ? {
              onFailure: props.DestinationConfig.OnFailure
                ? {
                    destination: props.DestinationConfig.OnFailure.Destination,
                  }
                : undefined,
              onSuccess: props.DestinationConfig.OnSuccess
                ? {
                    destination: props.DestinationConfig.OnSuccess.Destination,
                  }
                : undefined,
            }
          : undefined,
      },
      options
    );
  } else if (is<AWS.Events.Rule>("AWS::Events::Rule", props)) {
    return new cloudwatch.EventRule(
      name,
      {
        description: props.Description,
        eventBusName: props.EventBusName,
        eventPattern: toJson(props.EventPattern),
        name: props.Name,
        roleArn: props.RoleArn,
        scheduleExpression: props.ScheduleExpression,
      },
      options
    );
  } else if (is<AWS.SQS.QueuePolicy>("AWS::SQS::QueuePolicy", props)) {
    const comp = new ComponentResource(
      "AWS::SQS::QueuePolicy",
      name,
      {},
      options
    );

    props.Queues.map(
      (queueUrl, i) =>
        new sqs.QueuePolicy(
          `QueuePolicy${i}`,
          {
            policy: toJson(props.PolicyDocument),
            queueUrl,
          },
          {
            parent: comp,
          }
        )
    );
    return comp;
  } else if (is<AWS.Lambda.Permission>("AWS::Lambda::Permission", props)) {
    return new lambda.Permission(
      name,
      {
        action: props.Action,
        function: props.FunctionName,
        principal: props.Principal,
        eventSourceToken: props.EventSourceToken,
        functionUrlAuthType: props.FunctionUrlAuthType,
        principalOrgId: props.PrincipalOrgID,
        sourceAccount: props.SourceAccount,
        sourceArn: props.SourceArn,
      },
      options
    );
  } else if (is<AWS.SQS.Queue>("AWS::SQS::Queue", props)) {
    return new sqs.Queue(
      name,
      {
        contentBasedDeduplication: props.ContentBasedDeduplication,
        deduplicationScope: props.DeduplicationScope,
        delaySeconds: props.DelaySeconds,
        fifoQueue: props.FifoQueue,
        fifoThroughputLimit: props.FifoThroughputLimit,
        kmsDataKeyReusePeriodSeconds: props.KmsDataKeyReusePeriodSeconds,
        kmsMasterKeyId: props.KmsMasterKeyId,
        maxMessageSize: props.MaximumMessageSize,
        messageRetentionSeconds: props.MessageRetentionPeriod,
        name: props.QueueName,
        receiveWaitTimeSeconds: props.ReceiveMessageWaitTimeSeconds,
        redriveAllowPolicy: props.RedriveAllowPolicy,
        redrivePolicy: props.RedrivePolicy,
        sqsManagedSseEnabled: props.SqsManagedSseEnabled,
        visibilityTimeoutSeconds: props.VisibilityTimeout,
      },
      options
    );
  } else if (
    is<AWS.Lambda.EventSourceMapping>("AWS::Lambda::EventSourceMapping", props)
  ) {
    return new lambda.EventSourceMapping(
      name,
      {
        amazonManagedKafkaEventSourceConfig:
          props.AmazonManagedKafkaEventSourceConfig
            ? {
                consumerGroupId:
                  props.AmazonManagedKafkaEventSourceConfig.ConsumerGroupId,
              }
            : undefined,
        batchSize: props.BatchSize,
        bisectBatchOnFunctionError: props.BisectBatchOnFunctionError,
        destinationConfig: props.DestinationConfig?.OnFailure?.Destination
          ? {
              onFailure: {
                destinationArn: props.DestinationConfig.OnFailure.Destination,
              },
            }
          : undefined,
        enabled: props.Enabled,
        eventSourceArn: props.EventSourceArn,
        filterCriteria: props.FilterCriteria?.Filters
          ? {
              filters: props.FilterCriteria.Filters.map((filter) => ({
                pattern: filter.Pattern,
              })),
            }
          : undefined,
        functionName: props.FunctionName,
        functionResponseTypes: props.FunctionResponseTypes,
        maximumBatchingWindowInSeconds: props.MaximumBatchingWindowInSeconds,
        maximumRecordAgeInSeconds: props.MaximumRecordAgeInSeconds,
        maximumRetryAttempts: props.MaximumRetryAttempts,
        parallelizationFactor: props.ParallelizationFactor,
        queues: props.Queues,
        selfManagedEventSource: props.SelfManagedEventSource?.Endpoints
          ?.KafkaBootstrapServers
          ? {
              endpoints: {
                KAFKA_BOOTSTRAP_SERVERS:
                  props.SelfManagedEventSource.Endpoints?.KafkaBootstrapServers.join(
                    ","
                  ),
              },
            }
          : undefined,
        selfManagedKafkaEventSourceConfig: props
          .SelfManagedKafkaEventSourceConfig?.ConsumerGroupId
          ? {
              consumerGroupId:
                props.SelfManagedKafkaEventSourceConfig.ConsumerGroupId,
            }
          : undefined,
        sourceAccessConfigurations: props.SourceAccessConfigurations
          ? props.SourceAccessConfigurations.flatMap((c) =>
              c.Type && c.URI
                ? [
                    {
                      type: c.Type,
                      uri: c.URI,
                    },
                  ]
                : []
            )
          : undefined,
        startingPosition: props.StartingPosition,
        startingPositionTimestamp: props.StartingPositionTimestamp
          ? map(props.StartingPositionTimestamp, (ts) =>
              new Date(ts).toISOString()
            )
          : undefined,
        topics: props.Topics,
        tumblingWindowInSeconds: props.TumblingWindowInSeconds,
      },
      options
    );
  }
  return undefined;

  function is<T>(name: string, props: any): props is FromPulumi<T> {
    return typeName === name;
  }
}

function toJson(input: Input<any>): Input<string> {
  return map(input, JSON.stringify);
}

function map<T, U>(input: Input<T>, f: (t: T) => U): Input<U> {
  if (isPromise(input)) {
    return input.then((i) => f(i));
  } else if (Output.isInstance(input)) {
    return input.apply((i) => f(i));
  } else {
    return f(input);
  }
}
