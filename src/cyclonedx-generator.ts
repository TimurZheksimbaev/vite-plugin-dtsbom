import type { PackageInfo, Dependency } from './types.js';

export interface CycloneDXBom {
  bomFormat: string;
  specVersion: string;
  serialNumber?: string;
  version: number;
  metadata: {
    timestamp: string;
    tools?: Array<{
      vendor?: string;
      name: string;
      version: string;
    }>;
    component?: {
      type: string;
      name: string;
      version: string;
      description?: string;
      licenses?: Array<{
        license?: {
          id?: string;
        };
      }>;
    };
    authors?: Array<{
      name?: string;
      email?: string;
    }>;
  };
  components?: Array<{
    type: string;
    name: string;
    version: string;
    purl?: string;
    properties?: Array<{
      name: string;
      value: string;
    }>;
    licenses?: Array<{
      license?: {
        id?: string;
      };
    }>;
    externalReferences?: Array<{
      type: string;
      url: string;
    }>;
  }>;
}

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
  };

  // Add license to root component
  if (packageInfo.license) {
    bom.metadata.component!.licenses = [
      {
        license: {
          id: packageInfo.license,
        },
      },
    ];
  }

  // Add author information
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

  // Add dependencies as components
  for (const dep of dependencies) {
    const component: NonNullable<CycloneDXBom['components']>[0] = {
      type: 'library',
      name: dep.name,
      version: dep.version,
      purl: `pkg:npm/${dep.name}@${dep.version}`,
    };

    if (dep.license) {
      component.licenses = [
        {
          license: {
            id: dep.license,
          },
        },
      ];
    }

    if (dep.homepage) {
      component.externalReferences = [
        {
          type: 'website',
          url: dep.homepage,
        },
      ];
    }

    if (dep.chunks?.length) {
      component.properties = [
        {
          name: 'vite:outputChunks',
          value: dep.chunks.join(','),
        },
      ];
    }

    bom.components!.push(component);
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

