import { readFileSync, existsSync } from 'fs';
import { dirname, join } from 'path';
import { fileURLToPath } from 'url';
import type { SbomModuleGraphContext, SbomOutputBundleLike } from './build-shim.js';
import type { Dependency } from './types.js';
import { getLicenseInfo } from './utils.js';

function toFsPath(moduleId: string): string | null {
  if (moduleId.startsWith('\0') || moduleId.startsWith('virtual:')) {
    return null;
  }
  if (moduleId.startsWith('file:')) {
    try {
      return fileURLToPath(moduleId);
    } catch {
      return null;
    }
  }
  if (/^([A-Za-z]:)?[/\\]/.test(moduleId) || moduleId.startsWith('/')) {
    return moduleId;
  }
  return null;
}

/**
 * Walk up from a module file path until a package.json with name+version is found.
 */
export function readPackageMetaFromModulePath(
  modulePath: string
): {
  name: string;
  version: string;
  license?: string;
  homepage?: string;
  repository?: string;
} | null {
  let dir = dirname(modulePath);
  for (let depth = 0; depth < 40; depth++) {
    const pj = join(dir, 'package.json');
    if (existsSync(pj)) {
      try {
        const pkg = JSON.parse(readFileSync(pj, 'utf-8')) as {
          name?: string;
          version?: string;
          license?: string | { type?: string };
          homepage?: string;
          repository?: string | { url?: string };
        };
        if (pkg.name && pkg.version) {
          const license =
            typeof pkg.license === 'string'
              ? pkg.license
              : pkg.license?.type;
          const repository =
            typeof pkg.repository === 'string'
              ? pkg.repository
              : pkg.repository?.url;
          return {
            name: pkg.name,
            version: pkg.version,
            license,
            homepage: pkg.homepage,
            repository,
          };
        }
      } catch {
        // keep walking
      }
    }
    const parent = dirname(dir);
    if (parent === dir) {
      break;
    }
    dir = parent;
  }
  return null;
}

function dependencyKey(dep: Pick<Dependency, 'name' | 'version'>): string {
  return `${dep.name}@${dep.version}`;
}

/**
 * Packages linked into the Rollup module graph (post tree-shaking) with chunk mapping.
 */
export function collectBundleDependencies(
  context: SbomModuleGraphContext,
  bundle: SbomOutputBundleLike,
  root: string
): Dependency[] {
  const keyToChunks = new Map<string, Set<string>>();
  const keyToDep = new Map<string, Dependency>();

  const considerModule = (moduleId: string, chunkFileName: string | null) => {
    const fsPath = toFsPath(moduleId);
    if (!fsPath) {
      return;
    }
    const meta = readPackageMetaFromModulePath(fsPath);
    if (!meta) {
      return;
    }
    const dep: Dependency = {
      name: meta.name,
      version: meta.version,
      type: 'dependencies',
      license: meta.license || getLicenseInfo(meta.name, root),
      homepage: meta.homepage,
      repository: meta.repository,
    };
    const key = dependencyKey(dep);
    if (!keyToDep.has(key)) {
      keyToDep.set(key, dep);
    }
    if (chunkFileName) {
      if (!keyToChunks.has(key)) {
        keyToChunks.set(key, new Set());
      }
      keyToChunks.get(key)!.add(chunkFileName);
    }
  };

  for (const [fileName, output] of Object.entries(bundle)) {
    if (output.type !== 'chunk') {
      continue;
    }
    const ids = output.moduleIds ?? [];
    for (const id of ids) {
      considerModule(id, fileName);
    }
  }

  for (const id of context.getModuleIds()) {
    considerModule(id, null);
  }

  const result: Dependency[] = [];
  for (const [key, dep] of keyToDep) {
    const chunks = keyToChunks.has(key)
      ? [...keyToChunks.get(key)!].sort()
      : [];
    result.push({
      ...dep,
      chunks,
    });
  }

  result.sort((a, b) => a.name.localeCompare(b.name) || a.version.localeCompare(b.version));
  return result;
}
