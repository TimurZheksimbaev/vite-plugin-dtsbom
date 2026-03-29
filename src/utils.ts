import { readFileSync, existsSync, readdirSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import type { PackageInfo, Dependency } from './types.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

export function readPackageJson(root: string): PackageInfo | null {
  const packageJsonPath = join(root, 'package.json');
  
  if (!existsSync(packageJsonPath)) {
    return null;
  }

  try {
    const content = readFileSync(packageJsonPath, 'utf-8');
    return JSON.parse(content);
  } catch (error) {
    console.warn(`Failed to read package.json: ${error}`);
    return null;
  }
}

export function collectDependencies(
  packageJson: PackageInfo,
  includeDev: boolean = false
): Dependency[] {
  const dependencies: Dependency[] = [];

  const depTypes: Array<keyof PackageInfo> = ['dependencies'];
  
  if (includeDev) {
    depTypes.push('devDependencies');
  }
  
  depTypes.push('peerDependencies', 'optionalDependencies');

  for (const depType of depTypes) {
    const deps = packageJson[depType] as Record<string, string> | undefined;
    if (deps) {
      for (const [name, version] of Object.entries(deps)) {
        dependencies.push({
          name,
          version: normalizeVersion(version),
          type: depType.replace('Dependencies', '') as Dependency['type'],
        });
      }
    }
  }

  return dependencies;
}

function normalizeVersion(version: string): string {
  // Remove version prefixes like ^, ~, >=, etc.
  return version.replace(/^[\^~>=<]+/, '');
}

export function getLicenseInfo(packageName: string, root: string): string | undefined {
  // Try to read license from node_modules
  const nodeModulesPath = join(root, 'node_modules', packageName, 'package.json');
  
  if (existsSync(nodeModulesPath)) {
    try {
      const content = readFileSync(nodeModulesPath, 'utf-8');
      const pkg = JSON.parse(content);
      return typeof pkg.license === 'string' 
        ? pkg.license 
        : pkg.license?.type || 'NOASSERTION';
    } catch {
      // Ignore errors
    }
  }
  
  return undefined;
}

export function generateSPDXId(name: string): string {
  // SPDX IDs must be valid identifiers
  return name.replace(/[^a-zA-Z0-9.-]/g, '-').replace(/^-+|-+$/g, '');
}

/**
 * Parse node_modules directory to collect all installed packages
 */
export function scanNodeModules(
  root: string,
  includeTransitive: boolean = true
): Map<string, Dependency> {
  const packages = new Map<string, Dependency>();
  const nodeModulesPath = join(root, 'node_modules');

  if (!existsSync(nodeModulesPath)) {
    return packages;
  }

  function scanDirectory(dir: string, depth: number = 0): void {
    // Limit depth to avoid infinite recursion and skip scoped packages nested too deep
    if (depth > 10) {
      return;
    }

    try {
      const entries = readdirSync(dir, { withFileTypes: true });

      for (const entry of entries) {
        const fullPath = join(dir, entry.name);

        if (entry.isDirectory()) {
          // Check if this directory contains a package.json
          const packageJsonPath = join(fullPath, 'package.json');
          
          if (existsSync(packageJsonPath)) {
            try {
              const content = readFileSync(packageJsonPath, 'utf-8');
              const pkg = JSON.parse(content);
              
              if (pkg.name && pkg.version) {
                // Skip if already processed (avoid duplicates)
                if (!packages.has(pkg.name)) {
                  packages.set(pkg.name, {
                    name: pkg.name,
                    version: pkg.version,
                    type: 'dependencies', // Default type
                    license: typeof pkg.license === 'string'
                      ? pkg.license
                      : pkg.license?.type || undefined,
                    homepage: pkg.homepage,
                    repository: typeof pkg.repository === 'string'
                      ? pkg.repository
                      : pkg.repository?.url,
                  });
                }
              }

              // If including transitive dependencies, scan this package's node_modules
              if (includeTransitive) {
                const nestedNodeModules = join(fullPath, 'node_modules');
                if (existsSync(nestedNodeModules)) {
                  scanDirectory(nestedNodeModules, depth + 1);
                }
              }
            } catch (error) {
              // Skip invalid package.json files
              continue;
            }
          } else {
            // If no package.json, might be a scoped package directory
            // Continue scanning if it looks like a package name
            if (entry.name.startsWith('@')) {
              scanDirectory(fullPath, depth + 1);
            }
          }
        }
      }
    } catch (error) {
      // Skip directories we can't read
      return;
    }
  }

  scanDirectory(nodeModulesPath);
  return packages;
}

/**
 * Collect all dependencies from package.json and optionally from node_modules
 */
export function collectAllDependencies(
  packageJson: PackageInfo,
  root: string,
  options: {
    includeDev: boolean;
    parseNodeModules: boolean;
    includeTransitive: boolean;
  }
): Dependency[] {
  const { includeDev, parseNodeModules, includeTransitive } = options;
  
  // Start with direct dependencies from package.json
  const directDeps = collectDependencies(packageJson, includeDev);
  const allDeps = new Map<string, Dependency>();

  // Add direct dependencies
  for (const dep of directDeps) {
    allDeps.set(dep.name, dep);
  }

  // If parsing node_modules, add all installed packages
  if (parseNodeModules) {
    const installedPackages = scanNodeModules(root, includeTransitive);
    
    for (const [name, pkg] of installedPackages) {
      // Merge with direct dependencies, preserving type from package.json
      if (!allDeps.has(name)) {
        allDeps.set(name, pkg);
      } else {
        // Update with more complete information from node_modules
        const existing = allDeps.get(name)!;
        allDeps.set(name, {
          ...existing,
          version: pkg.version, // Use actual installed version
          license: pkg.license || existing.license,
          homepage: pkg.homepage || existing.homepage,
          repository: pkg.repository || existing.repository,
        });
      }
    }
  }

  // Enrich all dependencies with license info from node_modules
  const enrichedDeps: Dependency[] = [];
  for (const dep of allDeps.values()) {
    const license = getLicenseInfo(dep.name, root) || dep.license;
    enrichedDeps.push({
      ...dep,
      license,
    });
  }

  return enrichedDeps;
}

