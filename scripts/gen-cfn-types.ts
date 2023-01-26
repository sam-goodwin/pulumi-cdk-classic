import path from "path";
import fs from "fs/promises";
import ts, { SelectionRange } from "typescript";
import cfn from "@aws-cdk/cfnspec";
import prettier from "prettier";
import * as url from "url";
const __dirname = url.fileURLToPath(new URL(".", import.meta.url));

const namespaces = cfn.namespaces();
const specification = cfn.specification();

const statements: ts.Statement[] = [];

type CfnType<T extends cfn.schema.ResourceType | cfn.schema.PropertyType> = [
  fqn: string,
  spec: T
];

for (const namespace of namespaces) {
  const resources = filterByPrefix(specification.ResourceTypes, namespace);
  const properties = filterByPrefix(specification.PropertyTypes, namespace);

  const [, service] = namespace.split("::");
  console.log(namespace, service);

  statements.push(
    createNamespace(service, [
      ...resourcesToInterfaces(resources),
      ...propertiesToInterfaces(properties),
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
  properties: CfnType<cfn.schema.PropertyType>[]
): ts.Statement[] {
  const declarations: (ts.ModuleDeclaration | ts.InterfaceDeclaration)[] = [];

  const nestedTypes = properties
    .filter(([name]) => name.includes("."))
    .reduce<Record<string, Record<string, cfn.schema.PropertyType>>>(
      (obj, [name, val]) => ({
        ...obj,
        [name]: obj[name] ? { ...obj[name], [name]: val } : { [name]: val },
      }),
      {}
    );
  const rootTypes = properties.filter(([name]) => !name.includes("."));

  return [
    ...rootTypes.flatMap(([fqn, type]) => {
      let [, , typeName] = fqn.split("::");

      return [
        typeToInterface(typeName, type),
        createNamespace(typeName, [
          typeToInterface(typeName, type),
          ...Object.entries(nestedTypes[typeName] ?? {}).map(
            ([propertyName, type]) => typeToInterface(propertyName, type)
          ),
        ]),
      ];
    }),
  ];
}

function typeToInterface(
  name: string,
  type: cfn.schema.ResourceType | cfn.schema.PropertyType
): ts.InterfaceDeclaration {
  return ts.factory.createInterfaceDeclaration(
    undefined,
    name,
    undefined,
    undefined,
    []
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
