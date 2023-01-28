# pulumi-cdk-classic

This library maps Pulumi AWS Native Resources to Pulumi Classic Resources. Native Resources use AWS's Cloud Control API which often times have significantly worse performance. By mapping to Pulumi Classic, many stacks can save 60+% off of their deployment time.

It is built on top of the [pulumi-cdk](https://github.com/pulumi/pulumi-cdk) bridge that makes it possible to deploy AWS CDK applications with the Pulumi engine. It also makes it possible for those applications to interact with other Resources from the wider Pulumi ecosystem - including non-AWS resources.

## Installation

Install the AWS CDK, Pulumi CDK and Pulumi CDK Classic adapter.

```
npm install --save aws-cdk-lib @pulumi/pulumi-cdk pulumi-cdk-classic
```

## Usage

When instantiating your Stack, pass in the `remapCloudControlResource` function in to the options to enable the classic adapter.

```ts
import { remapCloudControlResource } from "pulumi-cdk-classic;
import { Stack } from "@pulumi/pulumi-cdk";
import { aws_lambda } from "aws-cdk-lib";

class MyStack extends Stack {
  constructor(name: string) {
    super(name, { remapCloudControlResource });

    const func = new aws_lambda.Function(this, "Func", {
      // etc.
    });

    this.functionArn = this.asOutput(func.functionArn);

    // be sure to call this
    this.synth();
  }
}

const myStack = new MyStack("my-stack");

// export the Function's ARN Output
export const functionArn = myStack.functionArn;
```
