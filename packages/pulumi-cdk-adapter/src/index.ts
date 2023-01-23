import fs from "fs";
import { iam, lambda } from "@pulumi/aws";
import type { ResourceMapping } from "@pulumi/cdk/interop";
import type { ResourceOptions } from "@pulumi/pulumi";
import { CfnElement, isResolvableObject } from "aws-cdk-lib";
import { CfnRole, PolicyDocument } from "aws-cdk-lib/aws-iam";

import { CfnFunction } from "aws-cdk-lib/aws-lambda";
import { RemoteAsset } from "@pulumi/pulumi/asset";

export function remapCloudControlResource(
  element: CfnElement,
  logicalId: string,
  typeName: string,
  props: any,
  options: ResourceOptions
): ResourceMapping | undefined {
  if (element instanceof CfnFunction) {
    console.log(props);
    return new lambda.Function(
      element.node.path,
      {
        architectures: props.Architectures,
        // code: new RemoteAsset(),
        name: props.FunctionName,
        role: props.Role,
        runtime: props.Runtime,
        // environment: {
        //   variables: element.environment,
        // },
      },
      options
    );
  }

  return undefined;
}

// function resolve(val: any) {
//   if (isResolvableObject(val)) {
//     val.resolve({});
//   }
// }
