export interface PluginOptions {
  /**
   * Directory where SBOM files and the HTML report are written.
   *
   * **Default: `'sbom'`** — a folder at the project root, deliberately outside
   * the Vite build output (`dist/`). This keeps security-sensitive dependency
   * manifests away from the public deployment bundle.
   *
   * Set to `'dist'` (or whatever your `build.outDir` is) only if you
   * intentionally want the SBOM to be part of the deployed artefacts.
   *
   * @default 'sbom'
   */
  outputDir?: string;

  /**
   * Generate SPDX format
   * @default true
   */
  spdx?: boolean;

  /**
   * Generate CycloneDX format
   * @default true
   */
  cyclonedx?: boolean;

  /**
   * SPDX format version
   * @default '2.3'
   */
  spdxVersion?: string;

  /**
   * CycloneDX format version
   * @default '1.5'
   */
  cyclonedxVersion?: string;

  /**
   * Include dev dependencies
   * @default false
   */
  includeDevDependencies?: boolean;

  /**
   * Custom package name (if different from package.json)
   */
  packageName?: string;

  /**
   * Custom package version (if different from package.json)
   */
  packageVersion?: string;

  /**
   * Parse node_modules to include all installed packages (including transitive dependencies)
   * @default true
   */
  parseNodeModules?: boolean;

  /**
   * Include transitive dependencies (dependencies of dependencies)
   * Only applies when parseNodeModules is true
   * @default true
   */
  includeTransitiveDependencies?: boolean;

  /**
   * How dependencies are collected:
   * - `bundle`: only packages whose modules appear in the Rollup graph after tree-shaking (recommended)
   * - `packageGraph`: scan package.json / node_modules like a traditional SBOM tool
   * @default 'bundle'
   */
  analysisMode?: 'bundle' | 'packageGraph';

  /**
   * Query the OSV.dev API to enrich each dependency with known vulnerabilities.
   * Requires an internet connection at build time. The build will never fail if
   * the network is unavailable — a warning is printed and the field is omitted.
   * @default true
   */
  fetchVulnerabilities?: boolean;

  /**
   * Timeout in milliseconds for the OSV.dev API request.
   * @default 15000
   */
  vulnFetchTimeoutMs?: number;

  /**
   * Generate a human-readable HTML report alongside the SBOM files.
   * The report includes a summary dashboard, full package table and
   * detailed vulnerability cards (severity, CVSS, CWE, fix version, advisory link).
   * @default true
   */
  report?: boolean;

  /**
   * File name for the HTML report (written to the same outputDir as the SBOM files).
   * @default 'sbom-report.html'
   */
  reportFileName?: string;
}

export interface PackageInfo {
  name: string;
  version: string;
  description?: string;
  license?: string;
  author?: string | {
    name?: string;
    email?: string;
    url?: string;
  };
  homepage?: string;
  repository?: {
    type?: string;
    url?: string;
  };
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
  peerDependencies?: Record<string, string>;
  optionalDependencies?: Record<string, string>;
}

/**
 * A single known vulnerability entry from the static database or an advisory feed.
 */
export interface VulnInfo {
  /** CVE identifier (e.g. "CVE-2020-7660") or GHSA identifier (e.g. "GHSA-5c6j-r48x-rmvq") */
  id: string;
  /** Qualitative severity level */
  severity: 'critical' | 'high' | 'moderate' | 'low';
  /** CVSS v3 base score (0.0 – 10.0) */
  cvss?: number;
  /** Short human-readable title */
  title: string;
  /** Full description of the vulnerability */
  description: string;
  /** Primary advisory or NVD URL */
  url: string;
  /**
   * Affected semver range in compact notation (only present when sourced from a local DB).
   * Examples: "<3.1.0"  "<=4.17.21"  ">=1.0.0 <2.0.0"
   * When the data comes from OSV.dev, this field is omitted.
   */
  affectedRange?: string;
  /** First version that ships the fix, if known */
  fixedVersion?: string;
  /** CWE identifiers (e.g. ["CWE-79", "CWE-94"]) */
  cwe?: string[];
}

export interface Dependency {
  name: string;
  version: string;
  type: 'dependencies' | 'devDependencies' | 'peerDependencies' | 'optionalDependencies';
  /** Short description from the package's package.json */
  description?: string;
  /** Declared license identifier (SPDX expression) */
  license?: string;
  /** Author string from the package's package.json */
  author?: string;
  /** Homepage URL */
  homepage?: string;
  /** Repository URL */
  repository?: string;
  /** Keywords from the package's package.json */
  keywords?: string[];
  /** Known vulnerabilities matching the installed version */
  vulnerabilities?: VulnInfo[];
  /** Vite/Rollup output chunk file names that reference this package (bundle analysis only) */
  chunks?: string[];
}
