import { asString, Stack, StackOptions } from "@pulumi/cdk";
import { Input, output, Output } from "@pulumi/pulumi";
import { Token } from "aws-cdk-lib";
import type { Construct } from "constructs";
import { isPromise } from "util/types";
import { remapCloudControlResource } from "./remap.js";

type OutputTypes = string | number | boolean | string[];
type BridgedTypes = OutputTypes | Construct | Record<string, any>;

export type FromCDK<C> = {
  [k in keyof Pick<
    C,
    Exclude<KeysOfType<C, BridgedTypes>, KeysOfType<C, (...args: any[]) => any>>
  >]: C[k] extends OutputTypes ? Output<C[k]> : FromCDK<C[k]>;
};

export type Constructor = new (
  scope: Construct,
  id: string,
  props?: any
) => Construct;

export type BridgedConstructor<C extends Constructor> = new (
  name: string,
  props: FromPulumi<ConstructorParameters<C>[2]>,
  options?: StackOptions
) => FromCDK<InstanceType<C>>;

export function Bridge<C extends Constructor>(ctor: C): BridgedConstructor<C> {
  return class extends BridgedConstruct {
    constructor(name: string, props: any, options?: StackOptions) {
      super(name, {
        ...(options ?? {}),
        remapCloudControlResource,
      });

      const instance = new ctor(this, name, fromPulumi(props));

      this.synth();

      const bridged: any = {};
      return new Proxy(this, {
        get: (self, prop) => {
          return (bridged[prop] ??= self.fromCDK((instance as any)[prop]));
        },
      }) as this;
    }
  } as BridgedConstructor<C>;
}

export class BridgedConstruct extends Stack {
  public fromCDK<T>(value: T): FromCDK<T> {
    return fromCDK(this, value);
  }
}

/**
 * Bridges a CDK value into the Pulumi world.
 *
 * 1. Tokens and IResolvable are converted to Output values.
 * 2. Objects and Arrays are recursively mapped.
 * 3. Functions are dropped as we cannot map them and mutability on a
 *    CDK Construct is dangerous from outside. TODO: re-visit this limitation.
 */
export function fromCDK<T>(stack: Stack, value: T): FromCDK<T> {
  if (Token.isUnresolved(value)) {
    return stack.asOutput(value) as FromCDK<T>;
  } else if (Array.isArray(value)) {
    return value.map(fromCDK) as FromCDK<T>;
  } else if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value).flatMap(([k, v]) => {
        if (typeof v === "function") {
          return [];
        } else {
          return [[k, fromCDK(stack, v)]];
        }
      })
    ) as FromCDK<T>;
  } else if (typeof value === "function") {
    return undefined!;
  } else {
    return value as FromCDK<T>;
  }
}

export type FromPulumi<T> = T extends Construct
  ? FromCDK<T>
  : T extends Record<string, any>
  ? {
      [k in keyof T]: FromPulumi<T[k]>;
    }
  : T extends Array<infer U>
  ? FromPulumi<U>[]
  : T extends Output<any> | Promise<any>
  ? T
  : T extends boolean | number | string
  ? Input<T>
  : T;

/**
 * Bridges a value from Pulumi ecosystem into the CDK world.
 *
 * Outputs are converted to
 * @param value
 */
export function fromPulumi<T>(input: T): FromPulumi<T> {
  if (Output.isInstance(input)) {
    return asString(input as any) as FromPulumi<T>;
  } else if (isPromise(input)) {
    return fromPulumi(output(input)) as FromPulumi<T>;
  } else if (Array.isArray(input)) {
    return input.map(fromPulumi) as FromPulumi<T>;
  } else if (input && typeof input === "object") {
    return Object.fromEntries(
      Object.entries(input).flatMap(([k, v]) => {
        if (typeof v === "function") {
          return [];
        } else {
          return [[k, fromPulumi(v)]];
        }
      })
    ) as FromPulumi<T>;
  } else {
    return input as FromPulumi<T>;
  }
}

type KeysOfType<Obj, Type> = Extract<
  {
    [k in keyof Obj]: Obj[k] extends Type ? k : never;
  }[keyof Obj],
  keyof Obj
>;
