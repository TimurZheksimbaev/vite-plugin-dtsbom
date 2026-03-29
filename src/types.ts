export interface PluginOptions {
  /**
   * Output directory for SBOM files
   * @default 'dist'
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

export interface Dependency {
  name: string;
  version: string;
  type: 'dependencies' | 'devDependencies' | 'peerDependencies' | 'optionalDependencies';
  license?: string;
  homepage?: string;
  repository?: string;
  /** Vite/Rollup output chunk file names that reference this package (bundle analysis only) */
  chunks?: string[];
}

