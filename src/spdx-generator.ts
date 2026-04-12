import type { PackageInfo, Dependency, VulnInfo } from './types.js';
import { generateSPDXId } from './utils.js';

// ---------------------------------------------------------------------------
// SPDX 2.3 type definitions
// ---------------------------------------------------------------------------

export interface SPDXDocument {
  spdxVersion: string;
  dataLicense: string;
  SPDXID: string;
  name: string;
  documentNamespace: string;
  creationInfo: {
    created: string;
    creators: string[];
    comment?: string;
  };
  packages: SPDXPackage[];
  relationships: SPDXRelationship[];
  /** Optional annotations for packages (e.g. vulnerability notes) */
  annotations?: SPDXAnnotation[];
}

export interface SPDXPackage {
  SPDXID: string;
  name: string;
  versionInfo?: string;
  /** Download location — for npm packages this is the registry URL */
  downloadLocation: string;
  filesAnalyzed: boolean;
  licenseDeclared?: string;
  licenseConcluded?: string;
  copyrightText?: string;
  description?: string;
  comment?: string;
  homepage?: string;
  supplier?: string;
  /** Cross-references: SECURITY (advisory/CVE), PACKAGE-MANAGER (purl), OTHER */
  externalRefs?: SPDXExternalRef[];
}

export interface SPDXExternalRef {
  referenceCategory: 'SECURITY' | 'PACKAGE-MANAGER' | 'OTHER';
  referenceType: string;
  referenceLocator: string;
  comment?: string;
}

export interface SPDXRelationship {
  spdxElementId: string;
  relationshipType: string;
  relatedSpdxElement: string;
}

export interface SPDXAnnotation {
  annotationType: 'REVIEW' | 'OTHER';
  annotator: string;
  annotationDate: string;
  comment: string;
  annotationSPDXID?: string;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function npmDownloadUrl(name: string, version: string): string {
  return `https://registry.npmjs.org/${name}/-/${name.split('/').pop()}-${version}.tgz`;
}

function buildSecurityRefs(vulns: VulnInfo[]): SPDXExternalRef[] {
  const refs: SPDXExternalRef[] = [];
  for (const v of vulns) {
    // SPDX uses "advisory" as referenceType for SECURITY refs pointing at advisories
    refs.push({
      referenceCategory: 'SECURITY',
      referenceType: v.id.startsWith('CVE-') ? 'cve' : 'advisory',
      referenceLocator: v.url,
      comment: `[${v.severity.toUpperCase()} | CVSS ${v.cvss ?? 'N/A'}] ${v.title}${v.fixedVersion ? ` — fix: ${v.fixedVersion}` : ''}`,
    });
  }
  return refs;
}

function buildVulnComment(vulns: VulnInfo[]): string {
  return vulns
    .map(v => {
      const cvss = v.cvss !== undefined ? ` CVSS:${v.cvss}` : '';
      const fix = v.fixedVersion ? ` Fix: ${v.fixedVersion}.` : ' No fix available yet.';
      const cwe = v.cwe?.length ? ` CWE: ${v.cwe.join(', ')}.` : '';
      return `[${v.id}] ${v.severity.toUpperCase()}${cvss} — ${v.title}.${fix}${cwe} ${v.url}`;
    })
    .join('\n');
}

// ---------------------------------------------------------------------------
// Generator
// ---------------------------------------------------------------------------

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

  const totalVulns = dependencies.reduce(
    (sum, d) => sum + (d.vulnerabilities?.length ?? 0),
    0
  );

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
      copyrightText: 'NOASSERTION',
      externalRefs: [
        {
          referenceCategory: 'PACKAGE-MANAGER',
          referenceType: 'purl',
          referenceLocator: `pkg:npm/${packageName}@${packageVersion}`,
        },
        ...(packageInfo.repository?.url
          ? [
              {
                referenceCategory: 'SECURITY' as const,
                referenceType: 'cpe22Type',
                referenceLocator: `cpe:/a:${packageName}:${packageName}:${packageVersion}`,
              },
            ]
          : []),
      ],
    },
  ];

  const relationships: SPDXRelationship[] = [];
  const annotations: SPDXAnnotation[] = [];

  for (const dep of dependencies) {
    const depId = `SPDXRef-Package-${generateSPDXId(dep.name)}`;
    const hasVulns = !!dep.vulnerabilities?.length;

    // Build externalRefs for this package
    const externalRefs: SPDXExternalRef[] = [
      {
        referenceCategory: 'PACKAGE-MANAGER',
        referenceType: 'purl',
        referenceLocator: `pkg:npm/${dep.name}@${dep.version}`,
      },
    ];

    // Security advisory refs for each vulnerability
    if (hasVulns) {
      externalRefs.push(...buildSecurityRefs(dep.vulnerabilities!));
    }

    // Build the human-readable comment
    const commentParts: string[] = [];

    if (dep.type !== 'dependencies') {
      commentParts.push(`Dependency type: ${dep.type}.`);
    }

    if (dep.chunks?.length) {
      commentParts.push(`Vite output chunks: ${dep.chunks.join(', ')}.`);
    }

    if (hasVulns) {
      commentParts.push(
        `\n⚠  KNOWN VULNERABILITIES (${dep.vulnerabilities!.length}):\n` +
          buildVulnComment(dep.vulnerabilities!)
      );
    }

    const pkg: SPDXPackage = {
      SPDXID: depId,
      name: dep.name,
      versionInfo: dep.version,
      downloadLocation: npmDownloadUrl(dep.name, dep.version),
      filesAnalyzed: false,
      licenseDeclared: dep.license || 'NOASSERTION',
      licenseConcluded: dep.license || 'NOASSERTION',
      copyrightText: 'NOASSERTION',
      externalRefs,
    };

    if (dep.description) {
      pkg.description = dep.description;
    }

    if (dep.homepage) {
      pkg.homepage = dep.homepage;
    }

    if (dep.author) {
      pkg.supplier = `Person: ${dep.author}`;
    }

    if (commentParts.length) {
      pkg.comment = commentParts.join('\n').trim();
    }

    packages.push(pkg);

    relationships.push({
      spdxElementId: rootPackageId,
      relationshipType: 'DEPENDS_ON',
      relatedSpdxElement: depId,
    });

    // Add a REVIEW annotation for each vulnerable package so tooling can surface it
    if (hasVulns) {
      for (const v of dep.vulnerabilities!) {
        annotations.push({
          annotationType: 'REVIEW',
          annotator: 'Tool: vite-plugin-dtsbom',
          annotationDate: now,
          annotationSPDXID: depId,
          comment: `${v.id} [${v.severity.toUpperCase()}${v.cvss !== undefined ? ` CVSS:${v.cvss}` : ''}] ${v.title}. ${v.description} See: ${v.url}`,
        });
      }
    }
  }

  const creationComment = totalVulns > 0
    ? `This SBOM contains ${totalVulns} known vulnerabilit${totalVulns === 1 ? 'y' : 'ies'} across ${dependencies.filter(d => d.vulnerabilities?.length).length} package(s). Review SECURITY externalRefs and REVIEW annotations for details.`
    : 'No known vulnerabilities detected in the bundled dependencies.';

  return {
    spdxVersion: 'SPDX-2.3',
    dataLicense: 'CC0-1.0',
    SPDXID: documentId,
    name: `${packageName} ${packageVersion} SBOM`,
    documentNamespace: namespace,
    creationInfo: {
      created: now,
      creators: ['Tool: vite-plugin-dtsbom'],
      comment: creationComment,
    },
    packages,
    relationships,
    ...(annotations.length ? { annotations } : {}),
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
