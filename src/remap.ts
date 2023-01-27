import { cloudwatch, iam, lambda } from "@pulumi/aws";
import { output, ResourceOptions } from "@pulumi/pulumi";
import { CfnElement } from "aws-cdk-lib";

import { ResourceMapping } from "@pulumi/cdk/interop.js";
import { FromPulumi } from "./bridge.js";

import * as AWS from "./cfn.generated.js";

export function remapCloudControlResource(
  element: CfnElement,
  logicalId: string,
  typeName: string,
  props: any,
  options: ResourceOptions
): ResourceMapping | undefined {
  const name = element.node.path;
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
        environment: {
          variables: props.Environment?.Variables,
        },
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
        Arn: func.arn,
        "SnapStartResponse.ApplyOn": func.snapStart?.apply(
          (st) => st?.applyOn!
        ),
        "SnapStartResponse.OptimizationStatus": func.snapStart?.apply(
          (st) => st?.optimizationStatus!
        ),
      } satisfies FromPulumi<Partial<AWS.Lambda.Function.Attr>>,
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
        Arn: role.arn,
        RoleId: role.uniqueId,
      } satisfies FromPulumi<Partial<AWS.IAM.Role.Attr>>,
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
        Arn: bus.arn,
        Name: bus.name,
        // TODO:
        Policy: output(
          Promise.reject(
            new Error(`Role attribute 'Policy' cannot be polyfilled`)
          )
        ),
      } satisfies FromPulumi<Partial<AWS.Events.EventBus.Attr>>,
    };
  }
  return undefined;

  function is<T>(name: string, props: any): props is FromPulumi<T> {
    return typeName === name;
  }
}
