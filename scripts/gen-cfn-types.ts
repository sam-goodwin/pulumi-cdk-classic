import path from "path";
import fs from "fs/promises";
import ts from "typescript";
import cfn from "@aws-cdk/cfnspec";
import prettier from "prettier";
import * as url from "url";
import { isPrimitiveProperty } from "@aws-cdk/cfnspec/lib/schema/property.js";

const __dirname = url.fileURLToPath(new URL(".", import.meta.url));

const namespaces = cfn.namespaces();
const specification = cfn.specification();

const statements: ts.Statement[] = [];

type CfnType<T extends cfn.schema.ResourceType | cfn.schema.PropertyType> = [
  fqn: string,
  spec: T
];

for (const namespace of namespaces) {
  const resources = filterByPrefix(
    specification.ResourceTypes,
    `${namespace}::`
  );
  const properties = filterByPrefix(
    specification.PropertyTypes,
    `${namespace}::`
  );

  const [, service] = namespace.split("::");

  statements.push(
    createNamespace(service, [
      ...resourcesToInterfaces(resources),
      ...propertiesToInterfaces(service, resources, properties),
    ])
  );
}

const sourceFile = ts.factory.createSourceFile(
  statements,
  ts.factory.createToken(ts.SyntaxKind.EndOfFileToken),
  ts.NodeFlags.None
);

const printer = ts.createPrinter();

const text = prettier.format(printer.printFile(sourceFile), {
  parser: "typescript",
});

await fs.writeFile(path.join(__dirname, "..", "src", "cfn.generated.ts"), text);

function createNamespace(name: string, statements: ts.Statement[]) {
  return ts.factory.createModuleDeclaration(
    [ts.factory.createToken(ts.SyntaxKind.ExportKeyword)],
    ts.factory.createIdentifier(name),
    ts.factory.createModuleBlock(statements),
    ts.NodeFlags.Namespace
  );
}

function resourcesToInterfaces(resources: CfnType<cfn.schema.ResourceType>[]) {
  return resources.map(([fqn, type]) => {
    const [, , name] = fqn.split("::");

    return typeToInterface(name, type);
  });
}

function propertiesToInterfaces(
  serviceName: string,
  resources: CfnType<cfn.schema.ResourceType>[],
  properties: CfnType<cfn.schema.PropertyType>[]
): ts.Statement[] {
  const nestedTypes = properties
    .filter(([name]) => name.includes("."))
    .reduce<Record<string, Record<string, cfn.schema.PropertyType>>>(
      (resources, [fqn, propertyType]) => {
        const [, , resourceAndProperty] = fqn.split("::");
        const [resourceName, propertyName] = resourceAndProperty.split(".");

        resources[resourceName] ??= {};
        resources[resourceName][propertyName] = propertyType;

        return resources;
      },
      {}
    );
  const rootTypes = [
    ...resources,
    ...properties.filter(([name]) => !name.includes(".")),
  ];

  return [
    ...rootTypes.flatMap(([fqn, type]) => {
      let [, , typeName] = fqn.split("::");

      const fieldTypes = nestedTypes[typeName];
      return [
        typeToInterface(typeName, type),
        ...(fieldTypes
          ? [
              createNamespace(typeName, [
                ...Object.entries(fieldTypes ?? {}).map(
                  ([propertyName, type]) => typeToInterface(propertyName, type)
                ),
              ]),
            ]
          : []),
      ];
    }),
  ];
}

function typeToInterface(
  name: string,
  type: cfn.schema.ResourceType | cfn.schema.PropertyType
): ts.InterfaceDeclaration {
  let properties: ts.PropertySignature[] | undefined = undefined;
  if ("Properties" in type) {
    properties = Object.entries(type.Properties ?? {}).flatMap(
      ([name, type]) => {
        if (isPrimitiveProperty(type)) {
          return ts.factory.createPropertySignature(
            undefined,
            ts.factory.createIdentifier(name),
            !type.Required
              ? ts.factory.createToken(ts.SyntaxKind.QuestionToken)
              : undefined,
            isPrimitiveProperty(type)
              ? ts.factory.createKeywordTypeNode(
                  type.PrimitiveType === cfn.schema.PrimitiveType.Boolean
                    ? ts.SyntaxKind.BooleanKeyword
                    : type.PrimitiveType === cfn.schema.PrimitiveType.Double
                    ? ts.SyntaxKind.NumberKeyword
                    : type.PrimitiveType === cfn.schema.PrimitiveType.Integer
                    ? ts.SyntaxKind.NumberKeyword
                    : type.PrimitiveType === cfn.schema.PrimitiveType.Json
                    ? ts.SyntaxKind.AnyKeyword
                    : type.PrimitiveType === cfn.schema.PrimitiveType.Long
                    ? ts.SyntaxKind.NumberKeyword
                    : type.PrimitiveType === cfn.schema.PrimitiveType.String
                    ? ts.SyntaxKind.StringKeyword
                    : type.PrimitiveType === cfn.schema.PrimitiveType.Timestamp
                    ? ts.SyntaxKind.StringKeyword
                    : 1
                )
              : ts.factory.createTypeReferenceNode(type)
          );
        }
        return [];
      }
    );
  }
  return ts.factory.createInterfaceDeclaration(
    [ts.factory.createToken(ts.SyntaxKind.ExportKeyword)],
    name,
    undefined,
    undefined,
    [...(properties ?? [])]
  );
}

function filterByPrefix<T>(
  object: Record<string, T>,
  prefix: string
): [string, T][] {
  return Object.entries(object).flatMap(([name, type]) =>
    name.startsWith(prefix) ? [[name, type]] : []
  );
}
