import * as cdk from "@pulumi/cdk";
import { remapCloudControlResource } from "../../src";
import { aws_lambda } from "aws-cdk-lib";
import { iam } from "@pulumi/aws";
import path from "path";

const role = new iam.Role("my-role", {
  assumeRolePolicy: {
    Version: "2012-10-17",
    Statement: [
      {
        Effect: "Allow",
        Action: "sts:AssumeRole",
        Principal: {
          Service: "lambda.amazonaws.com",
        },
      },
    ],
  },
});

class MyStack extends cdk.Stack {
  constructor(id: string) {
    super(id, {
      remapCloudControlResource,
    });

    new aws_lambda.Function(this, "Foo", {
      code: aws_lambda.Code.fromAsset(path.join(__dirname, "handler")),
      // code: aws_lambda.Code.fromInline("export function handler() { }"),
      handler: "index.handler",
      runtime: aws_lambda.Runtime.NODEJS_18_X,
    });

    this.synth();
  }
}

new MyStack("my-stack");
