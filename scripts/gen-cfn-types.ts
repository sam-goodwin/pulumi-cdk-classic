import cfn from "@aws-cdk/cfnspec";
import {
  isComplexListProperty,
  isComplexProperty,
  isListProperty,
  isMapOfListsOfPrimitivesProperty,
  isMapOfStructsProperty,
  isMapProperty,
  isPrimitiveListProperty,
  isPrimitiveMapProperty,
  isPrimitiveProperty,
} from "@aws-cdk/cfnspec/lib/schema/property.js";
import { Attribute } from "@aws-cdk/cfnspec/lib/schema/resource-type.js";
import fs from "fs/promises";
import path from "path";
import prettier from "prettier";
import ts from "typescript";
import * as url from "url";

const __dirname = url.fileURLToPath(new URL(".", import.meta.url));

const namespaces = cfn.namespaces();
const specification = cfn.specification();

const statements: ts.Statement[] = [
  typeToInterface("Tag", specification.PropertyTypes.Tag, "resource"),
];

const resourceByNamespace = Object.entries(specification.ResourceTypes).reduce<
  Record<string, Record<string, cfn.schema.ResourceType>>
>((namespaces, [fqn, type]) => {
  const { namespace, resourceFullName } = parseFqn(fqn);
  namespaces[namespace] ??= {};
  namespaces[namespace][resourceFullName!] = type;
  return namespaces;
}, {});

const propertiesByResource = Object.entries(specification.PropertyTypes).reduce<
  Record<string, Record<string, cfn.schema.PropertyType>>
>((resources, [fqn, type]) => {
  const { resourceFullName, property } = parseFqn(fqn);
  if (resourceFullName === undefined || property === undefined) {
    return resources;
  }

  resources[resourceFullName] ??= {};
  resources[resourceFullName][property] = type;
  return resources;
}, {});

function parseFqn(fqn: string): {
  domain: string;
  namespace: string;
  service: string;
  resource?: string;
  resourceFullName?: string;
  property?: string;
} {
  const [domain, service, resourceAndProperty] = fqn.split("::");
  const [resource, property] = resourceAndProperty?.split(".") ?? [];
  return {
    domain,
    service,
    resource,
    resourceFullName: resource
      ? `${domain}::${service}::${resource}`
      : undefined,
    property,
    namespace: `${domain}::${service}`,
  };
}

for (const namespace of namespaces) {
  const resources = resourceByNamespace[namespace];

  const [, service] = namespace.split("::");

  statements.push(createNamespace(service, toInterfaces(resources)));
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

function toInterfaces(
  resources: Record<string, cfn.schema.ResourceType>
): ts.Statement[] {
  return Object.entries(resources).flatMap(([fqn, type]) => {
    const { resource } = parseFqn(fqn);
    if (resource === undefined) {
      throw new Error(`resource should have a resource name: ${fqn}`);
    }

    const fieldTypes = propertiesByResource[fqn];
    return [
      typeToInterface(resource, type, "resource"),
      ...(fieldTypes
        ? [
            createNamespace(resource, [
              ...(type.Attributes
                ? [typeToInterface("Attr", type.Attributes!, "attribute")]
                : []),
              ...Object.entries(fieldTypes ?? {}).map(([propertyName, type]) =>
                typeToInterface(propertyName, type, "property")
              ),
            ]),
          ]
        : []),
    ];
  });
}

function typeToInterface(
  typeName: string,
  type:
    | cfn.schema.ResourceType
    | cfn.schema.PropertyType
    | Record<string, Attribute>,
  kind: "resource" | "property" | "attribute"
): ts.InterfaceDeclaration {
  let properties: ts.PropertySignature[] | undefined = undefined;
  const Properties =
    kind === "attribute"
      ? type
      : "Properties" in type
      ? type.Properties
      : undefined;
  if (Properties) {
    properties = Object.entries(Properties).flatMap(([propName, propType]) => {
      const prop = ts.factory.createPropertySignature(
        undefined,
        propName.includes(".")
          ? ts.factory.createStringLiteral(propName)
          : ts.factory.createIdentifier(propName),
        kind !== "attribute" && !propType.Required
          ? ts.factory.createToken(ts.SyntaxKind.QuestionToken)
          : undefined,
        toTypeNode(propType)
      );

      return prop;
    });

    function toTypeNode(type: cfn.schema.Property | string): ts.TypeNode {
      if (typeof type === "string") {
        if (type === "Json") {
          return ts.factory.createKeywordTypeNode(ts.SyntaxKind.AnyKeyword);
        } else if (type === "String") {
          return ts.factory.createKeywordTypeNode(ts.SyntaxKind.StringKeyword);
        } else if (
          type === "Number" ||
          type === "Double" ||
          type === "Integer"
        ) {
          return ts.factory.createKeywordTypeNode(ts.SyntaxKind.NumberKeyword);
        } else if (type === "Boolean") {
          return ts.factory.createKeywordTypeNode(ts.SyntaxKind.BooleanKeyword);
        } else if (
          type === "Tag" ||
          kind === "property" ||
          kind === "attribute"
        ) {
          return ts.factory.createTypeReferenceNode(type);
        } else {
          return ts.factory.createTypeReferenceNode(
            ts.factory.createQualifiedName(
              ts.factory.createIdentifier(typeName),
              type
            )
          );
        }
      } else if (isPrimitiveProperty(type)) {
        return ts.factory.createKeywordTypeNode(
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
        );
      } else if (isComplexProperty(type)) {
        return toTypeNode(type.Type);
      } else if (type.ItemTypes) {
        return ts.factory.createUnionTypeNode(type.ItemTypes?.map(toTypeNode));
      } else if (isComplexListProperty(type)) {
        return ts.factory.createArrayTypeNode(toTypeNode(type.ItemType));
      } else if (isPrimitiveListProperty(type)) {
        return ts.factory.createArrayTypeNode(
          toTypeNode(type.PrimitiveItemType)
        );
      } else if (isMapOfStructsProperty(type)) {
        return ts.factory.createTypeReferenceNode(
          ts.factory.createIdentifier("Record"),
          [
            ts.factory.createKeywordTypeNode(ts.SyntaxKind.StringKeyword),
            toTypeNode(type.ItemType),
          ]
        );
      } else if (isMapOfListsOfPrimitivesProperty(type)) {
        return ts.factory.createTypeReferenceNode(
          ts.factory.createIdentifier("Record"),
          [
            ts.factory.createKeywordTypeNode(ts.SyntaxKind.StringKeyword),
            ts.factory.createArrayTypeNode(
              toTypeNode(type.PrimitiveItemItemType)
            ),
          ]
        );
      } else if (isPrimitiveMapProperty(type)) {
        return ts.factory.createTypeReferenceNode(
          ts.factory.createIdentifier("Record"),
          [
            ts.factory.createKeywordTypeNode(ts.SyntaxKind.StringKeyword),
            toTypeNode(type.PrimitiveItemType),
          ]
        );
      } else {
        return ts.factory.createKeywordTypeNode(ts.SyntaxKind.NeverKeyword);
      }
    }
  }

  const iface = ts.factory.createInterfaceDeclaration(
    [ts.factory.createToken(ts.SyntaxKind.ExportKeyword)],
    typeName,
    undefined,
    undefined,
    [...(properties ?? [])]
  );

  return iface;
}

function filterByPrefix<T>(
  object: Record<string, T>,
  prefix: string
): [string, T][] {
  return Object.entries(object).flatMap(([name, type]) =>
    name.startsWith(prefix) ? [[name, type]] : []
  );
}
