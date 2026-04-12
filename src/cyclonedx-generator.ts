import type { PackageInfo, Dependency, VulnInfo } from './types.js';

// ---------------------------------------------------------------------------
// CycloneDX 1.5 type definitions
// ---------------------------------------------------------------------------

export interface CycloneDXComponent {
  type: string;
  /** Unique reference within this BOM — used by the vulnerabilities section */
  'bom-ref': string;
  name: string;
  version: string;
  description?: string;
  author?: string;
  purl?: string;
  licenses?: Array<{ license?: { id?: string } }>;
  externalReferences?: Array<{ type: string; url: string }>;
  properties?: Array<{ name: string; value: string }>;
}

export interface CycloneDXVulnerability {
  /** CVE or GHSA identifier */
  id: string;
  source?: { name: string; url?: string };
  ratings?: Array<{
    source?: { name: string };
    score?: number;
    severity: string;
    method?: string;
  }>;
  cwes?: number[];
  description?: string;
  detail?: string;
  recommendation?: string;
  advisories?: Array<{ title?: string; url: string }>;
  /** References to affected BOM components via their bom-ref */
  affects: Array<{
    ref: string;
    versions?: Array<{ version: string; status: string }>;
  }>;
}

export interface CycloneDXBom {
  bomFormat: string;
  specVersion: string;
  serialNumber?: string;
  version: number;
  metadata: {
    timestamp: string;
    tools?: Array<{ vendor?: string; name: string; version: string }>;
    component?: {
      type: string;
      name: string;
      version: string;
      description?: string;
      licenses?: Array<{ license?: { id?: string } }>;
    };
    authors?: Array<{ name?: string; email?: string }>;
  };
  components?: CycloneDXComponent[];
  vulnerabilities?: CycloneDXVulnerability[];
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function bomRef(dep: Pick<Dependency, 'name' | 'version'>): string {
  return `pkg:npm/${dep.name}@${dep.version}`;
}

function severityToSource(vuln: VulnInfo): { name: string; url?: string } {
  if (vuln.id.startsWith('CVE-')) {
    return { name: 'NVD', url: `https://nvd.nist.gov/vuln/detail/${vuln.id}` };
  }
  if (vuln.id.startsWith('GHSA-')) {
    return {
      name: 'GitHub Advisory Database',
      url: `https://github.com/advisories/${vuln.id}`,
    };
  }
  return { name: 'Advisory DB', url: vuln.url };
}

function parseCweNumber(cwe: string): number | null {
  const m = cwe.match(/(\d+)/);
  return m ? parseInt(m[1], 10) : null;
}

function buildVulnerability(
  vuln: VulnInfo,
  affectedRef: string
): CycloneDXVulnerability {
  const source = severityToSource(vuln);

  const entry: CycloneDXVulnerability = {
    id: vuln.id,
    source,
    ratings: [
      {
        source: { name: source.name },
        ...(vuln.cvss !== undefined ? { score: vuln.cvss } : {}),
        severity: vuln.severity,
        method: 'CVSSv3',
      },
    ],
    description: vuln.title,
    detail: vuln.description,
    advisories: [{ title: vuln.title, url: vuln.url }],
    affects: [
      {
        ref: affectedRef,
      },
    ],
  };

  if (vuln.fixedVersion) {
    entry.recommendation = `Upgrade to version ${vuln.fixedVersion} or later.`;
  }

  if (vuln.cwe?.length) {
    const cweNums = vuln.cwe
      .map(parseCweNumber)
      .filter((n): n is number => n !== null);
    if (cweNums.length) {
      entry.cwes = cweNums;
    }
  }

  return entry;
}

// ---------------------------------------------------------------------------
// Generator
// ---------------------------------------------------------------------------

export function generateCycloneDX(
  packageInfo: PackageInfo,
  dependencies: Dependency[],
  options: {
    version?: string;
    packageName?: string;
    packageVersion?: string;
  } = {}
): CycloneDXBom {
  const packageName = options.packageName || packageInfo.name || 'unknown-package';
  const packageVersion = options.packageVersion || packageInfo.version || '0.0.0';

  const bom: CycloneDXBom = {
    bomFormat: 'CycloneDX',
    specVersion: '1.5',
    version: 1,
    metadata: {
      timestamp: new Date().toISOString(),
      tools: [
        {
          name: 'vite-plugin-dtsbom',
          version: '1.0.0',
        },
      ],
      component: {
        type: 'application',
        name: packageName,
        version: packageVersion,
        description: packageInfo.description,
      },
    },
    components: [],
    vulnerabilities: [],
  };

  if (packageInfo.license) {
    bom.metadata.component!.licenses = [{ license: { id: packageInfo.license } }];
  }

  if (packageInfo.author) {
    bom.metadata.authors = [
      typeof packageInfo.author === 'string'
        ? { name: packageInfo.author }
        : {
            name: packageInfo.author.name,
            email: packageInfo.author.email,
          },
    ];
  }

  for (const dep of dependencies) {
    const ref = bomRef(dep);

    // ---- Component --------------------------------------------------------
    const component: CycloneDXComponent = {
      type: 'library',
      'bom-ref': ref,
      name: dep.name,
      version: dep.version,
      purl: ref,
    };

    if (dep.description) {
      component.description = dep.description;
    }

    if (dep.author) {
      component.author = dep.author;
    }

    if (dep.license) {
      component.licenses = [{ license: { id: dep.license } }];
    }

    // Build externalReferences array
    const externalRefs: CycloneDXComponent['externalReferences'] = [];

    if (dep.homepage) {
      externalRefs.push({ type: 'website', url: dep.homepage });
    }

    if (dep.repository) {
      const repoUrl = dep.repository.replace(/^git\+/, '').replace(/\.git$/, '');
      externalRefs.push({ type: 'vcs', url: dep.repository });
      if (!dep.homepage) {
        externalRefs.push({ type: 'website', url: repoUrl });
      }
    }

    // npm registry link is always useful
    externalRefs.push({
      type: 'distribution',
      url: `https://www.npmjs.com/package/${dep.name}/v/${dep.version}`,
    });

    if (externalRefs.length) {
      component.externalReferences = externalRefs;
    }

    // Build properties
    const properties: CycloneDXComponent['properties'] = [];

    if (dep.type && dep.type !== 'dependencies') {
      properties.push({ name: 'npm:dependencyType', value: dep.type });
    }

    if (dep.keywords?.length) {
      properties.push({ name: 'npm:keywords', value: dep.keywords.join(', ') });
    }

    if (dep.chunks?.length) {
      properties.push({ name: 'vite:outputChunks', value: dep.chunks.join(', ') });
    }

    if (properties.length) {
      component.properties = properties;
    }

    bom.components!.push(component);

    // ---- Vulnerabilities -------------------------------------------------
    if (dep.vulnerabilities?.length) {
      for (const vuln of dep.vulnerabilities) {
        bom.vulnerabilities!.push(buildVulnerability(vuln, ref));
      }
    }
  }

  // Remove empty arrays to keep output tidy
  if (!bom.vulnerabilities?.length) {
    delete bom.vulnerabilities;
  }

  return bom;
}

export function generateCycloneDXJSON(
  packageInfo: PackageInfo,
  dependencies: Dependency[],
  options: {
    version?: string;
    packageName?: string;
    packageVersion?: string;
  } = {}
): string {
  const bom = generateCycloneDX(packageInfo, dependencies, options);
  return JSON.stringify(bom, null, 2);
}
