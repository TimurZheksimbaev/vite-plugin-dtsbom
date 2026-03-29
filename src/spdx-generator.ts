import type { PackageInfo, Dependency } from './types.js';
import { generateSPDXId } from './utils.js';

export interface SPDXDocument {
  spdxVersion: string;
  dataLicense: string;
  SPDXID: string;
  name: string;
  documentNamespace: string;
  creationInfo: {
    created: string;
    creators: string[];
  };
  packages: SPDXPackage[];
  relationships: SPDXRelationship[];
}

export interface SPDXPackage {
  SPDXID: string;
  name: string;
  versionInfo?: string;
  downloadLocation: string;
  filesAnalyzed: boolean;
  licenseDeclared?: string;
  licenseConcluded?: string;
  copyrightText?: string;
  description?: string;
  comment?: string;
  homepage?: string;
  externalRefs?: Array<{
    referenceCategory: string;
    referenceType: string;
    referenceLocator: string;
  }>;
}

export interface SPDXRelationship {
  spdxElementId: string;
  relationshipType: string;
  relatedSpdxElement: string;
}

export function generateSPDX(
  packageInfo: PackageInfo,
  dependencies: Dependency[],
  options: {
    version?: string;
    packageName?: string;
    packageVersion?: string;
  } = {}
): SPDXDocument {
  const now = new Date().toISOString();
  const packageName = options.packageName || packageInfo.name || 'unknown-package';
  const packageVersion = options.packageVersion || packageInfo.version || '0.0.0';
  const documentId = `SPDXRef-DOCUMENT`;
  const rootPackageId = `SPDXRef-Package-${generateSPDXId(packageName)}`;
  const namespace = `https://spdx.org/spdxdocs/${packageName}-${packageVersion}-${Date.now()}`;

  const packages: SPDXPackage[] = [
    {
      SPDXID: rootPackageId,
      name: packageName,
      versionInfo: packageVersion,
      downloadLocation: 'NOASSERTION',
      filesAnalyzed: false,
      licenseDeclared: packageInfo.license || 'NOASSERTION',
      description: packageInfo.description,
      homepage: packageInfo.homepage,
      externalRefs: packageInfo.repository?.url
        ? [
            {
              referenceCategory: 'SECURITY',
              referenceType: 'cpe22Type',
              referenceLocator: `cpe:/a:${packageName}:${packageName}:${packageVersion}`,
            },
          ]
        : undefined,
    },
  ];

  const relationships: SPDXRelationship[] = [];

  // Add dependencies as packages
  for (const dep of dependencies) {
    const depId = `SPDXRef-Package-${generateSPDXId(dep.name)}`;
    
    packages.push({
      SPDXID: depId,
      name: dep.name,
      versionInfo: dep.version,
      downloadLocation: `pkg:npm/${dep.name}@${dep.version}`,
      filesAnalyzed: false,
      licenseDeclared: dep.license || 'NOASSERTION',
      homepage: dep.homepage,
      ...(dep.chunks?.length
        ? { comment: `Vite output chunks: ${dep.chunks.join(', ')}` }
        : {}),
    });

    relationships.push({
      spdxElementId: rootPackageId,
      relationshipType: 'DEPENDS_ON',
      relatedSpdxElement: depId,
    });
  }

  return {
    spdxVersion: 'SPDX-2.3',
    dataLicense: 'CC0-1.0',
    SPDXID: documentId,
    name: `${packageName} ${packageVersion} SBOM`,
    documentNamespace: namespace,
    creationInfo: {
      created: now,
      creators: ['Tool: vite-plugin-dtsbom'],
    },
    packages,
    relationships,
  };
}

export function generateSPDXJSON(
  packageInfo: PackageInfo,
  dependencies: Dependency[],
  options: {
    version?: string;
    packageName?: string;
    packageVersion?: string;
  } = {}
): string {
  const spdx = generateSPDX(packageInfo, dependencies, options);
  return JSON.stringify(spdx, null, 2);
}

