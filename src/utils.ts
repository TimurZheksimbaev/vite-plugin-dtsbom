import { readFileSync, existsSync, readdirSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import type { PackageInfo, Dependency } from './types.js';
import { fetchVulnerabilitiesBatch, type FetchVulnOptions } from './vuln-fetcher.js';

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
  return version.replace(/^[\^~>=<]+/, '');
}

export function getLicenseInfo(packageName: string, root: string): string | undefined {
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
  return name.replace(/[^a-zA-Z0-9.-]/g, '-').replace(/^-+|-+$/g, '');
}

/**
 * Parse node_modules directory to collect all installed packages with full metadata.
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
    if (depth > 10) {
      return;
    }

    try {
      const entries = readdirSync(dir, { withFileTypes: true });

      for (const entry of entries) {
        const fullPath = join(dir, entry.name);

        if (entry.isDirectory()) {
          const packageJsonPath = join(fullPath, 'package.json');
          
          if (existsSync(packageJsonPath)) {
            try {
              const content = readFileSync(packageJsonPath, 'utf-8');
              const pkg = JSON.parse(content) as {
                name?: string;
                version?: string;
                description?: string;
                license?: string | { type?: string };
                author?: string | { name?: string; email?: string; url?: string };
                homepage?: string;
                repository?: string | { url?: string };
                keywords?: string[];
              };
              
              if (pkg.name && pkg.version && !packages.has(pkg.name)) {
                const license =
                  typeof pkg.license === 'string' ? pkg.license : pkg.license?.type;
                const repository =
                  typeof pkg.repository === 'string' ? pkg.repository : pkg.repository?.url;
                const author =
                  typeof pkg.author === 'string'
                    ? pkg.author
                    : pkg.author?.name
                      ? [pkg.author.name, pkg.author.email, pkg.author.url]
                          .filter(Boolean)
                          .join(' ')
                      : undefined;

                packages.set(pkg.name, {
                  name: pkg.name,
                  version: pkg.version,
                  type: 'dependencies',
                  description: pkg.description,
                  license: license || undefined,
                  author,
                  homepage: pkg.homepage,
                  repository,
                  keywords: Array.isArray(pkg.keywords) ? pkg.keywords : undefined,
                });
              }

              if (includeTransitive) {
                const nestedNodeModules = join(fullPath, 'node_modules');
                if (existsSync(nestedNodeModules)) {
                  scanDirectory(nestedNodeModules, depth + 1);
                }
              }
            } catch {
              continue;
            }
          } else {
            if (entry.name.startsWith('@')) {
              scanDirectory(fullPath, depth + 1);
            }
          }
        }
      }
    } catch {
      return;
    }
  }

  scanDirectory(nodeModulesPath);
  return packages;
}

/**
 * Collect all dependencies from package.json and optionally from node_modules.
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
  
  const directDeps = collectDependencies(packageJson, includeDev);
  const allDeps = new Map<string, Dependency>();

  for (const dep of directDeps) {
    allDeps.set(dep.name, dep);
  }

  if (parseNodeModules) {
    const installedPackages = scanNodeModules(root, includeTransitive);
    
    for (const [name, pkg] of installedPackages) {
      if (!allDeps.has(name)) {
        allDeps.set(name, pkg);
      } else {
        const existing = allDeps.get(name)!;
        allDeps.set(name, {
          ...existing,
          version: pkg.version,
          description: pkg.description || existing.description,
          license: pkg.license || existing.license,
          author: pkg.author || existing.author,
          homepage: pkg.homepage || existing.homepage,
          repository: pkg.repository || existing.repository,
          keywords: pkg.keywords || existing.keywords,
        });
      }
    }
  }

  const enrichedDeps: Dependency[] = [];
  for (const dep of allDeps.values()) {
    const license = getLicenseInfo(dep.name, root) || dep.license;
    enrichedDeps.push({ ...dep, license });
  }

  return enrichedDeps;
}

/**
 * Enrich a list of dependencies with live vulnerability data fetched from OSV.dev.
 * Mutates each entry in place and returns the same array for convenience.
 *
 * Network failures are handled gracefully — the build never fails.
 */
export async function enrichWithVulnerabilities(
  deps: Dependency[],
  opts: FetchVulnOptions = {}
): Promise<Dependency[]> {
  const vulnMap = await fetchVulnerabilitiesBatch(
    deps.map(d => ({ name: d.name, version: d.version })),
    opts
  );

  for (const dep of deps) {
    const key = `${dep.name}@${dep.version}`;
    const vulns = vulnMap.get(key);
    if (vulns?.length) {
      dep.vulnerabilities = vulns;
    }
  }

  return deps;
}
