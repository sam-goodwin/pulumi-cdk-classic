import fs from "fs";
import { iam, lambda } from "@pulumi/aws";
import type { ResourceOptions } from "@pulumi/pulumi";
import { CfnElement, isResolvableObject } from "aws-cdk-lib";
import { CfnRole, PolicyDocument } from "aws-cdk-lib/aws-iam";

import { CfnFunction } from "aws-cdk-lib/aws-lambda";
import { RemoteAsset } from "@pulumi/pulumi/asset";
import { ResourceMapping } from "@pulumi/cdk/interop.js";
import cfn from "@aws-cdk/cfnspec";
import { Lambda } from "./cfn.generated.js";

export function remapCloudControlResource(
  element: CfnElement,
  logicalId: string,
  typeName: string,
  props: any,
  options: ResourceOptions
): ResourceMapping | undefined {
  // todo
  if (element instanceof CfnFunction) {
    const functionProps: Lambda.Function = props;
    console.log(props);
    return new lambda.Function(
      element.node.path,
      {
        architectures: props.Architectures,
        // code: new RemoteAsset(),
        name: props.FunctionName,
        role: props.Role,
        runtime: props.Runtime,
        code: {},
        // environment: {
        //   variables: element.environment,
        // },
      },
      options
    );
  }

  return undefined;
}
