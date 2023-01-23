import fs from "fs";
import { iam, lambda } from "@pulumi/aws";
import type { ResourceMapping } from "@pulumi/cdk/interop";
import type { ResourceOptions } from "@pulumi/pulumi";
import { CfnElement, isResolvableObject } from "aws-cdk-lib";
import { CfnRole, PolicyDocument } from "aws-cdk-lib/aws-iam";

import { CfnFunction } from "aws-cdk-lib/aws-lambda";

export function remapCloudControlResource(
  element: CfnElement,
  logicalId: string,
  typeName: string,
  props: any,
  options: ResourceOptions
): ResourceMapping | undefined {
  if (element instanceof CfnFunction) {
    fs.writeFileSync("props.json", JSON.stringify(props, null, 2));

    // return new lambda.Function(
    //   element.node.path,
    //   {
    //     code: element.code,
    //     runtime: element.runtime,
    //     role: element.role,
    //     architectures: element.architectures,
    //     layers: element.layers,
    //     codeSigningConfigArn: element.codeSigningConfigArn,
    //   },
    //   options
    // );
  }

  return undefined;
}
