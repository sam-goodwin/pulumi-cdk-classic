// import * as cdk from "@pulumi/cdk";
// import { remapCloudControlResource } from "pulumi-l2";
// import { aws_lambda } from "aws-cdk-lib";
import { iam, lambda } from "@pulumi/aws";

const role = new iam.Role("my-role", {
  assumeRolePolicy: {
    Version: "2012-10-17",
    Statement: [
      {
        Effect: "Allow",
        Action: "sts:AssumeRole",
        Principal: {
          AWS: "lambda.amazonaws.com",
        },
      },
    ],
  },
});

// new lambda.Function("my-func", {
//   role: role.arn,
//   architectures: ["arm64"],
//   code: new StringAsset("export function handle() { }"),
// });
