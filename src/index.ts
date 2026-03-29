import { writeFileSync, mkdirSync, existsSync } from 'fs';
import { join, resolve } from 'path';
import type { SbomModuleGraphContext, SbomOutputBundleLike, SbomResolvedConfigSlice } from './build-shim.js';
import type { Dependency, PluginOptions } from './types.js';
import { readPackageJson, collectAllDependencies } from './utils.js';
import { collectBundleDependencies } from './bundle-analyzer.js';
import { generateSPDXJSON } from './spdx-generator.js';
import { generateCycloneDXJSON } from './cyclonedx-generator.js';

/**
 * Структурный тип плагина без привязки к конкретной копии `vite` в node_modules.
 * Совместим с `PluginOption` в конфиге Vite.
 */
export interface VitePluginDtsbomHandle {
  name: string;
  enforce?: 'pre' | 'post';
  configResolved?(config: SbomResolvedConfigSlice): void;
  generateBundle?(
    this: SbomModuleGraphContext,
    options: unknown,
    bundle: SbomOutputBundleLike
  ): void | Promise<void>;
  writeBundle?(): void | Promise<void>;
}

export default function vitePluginDtsbom(options: PluginOptions = {}): VitePluginDtsbomHandle {
  const {
    outputDir = 'dist',
    spdx = true,
    cyclonedx = true,
    includeDevDependencies = false,
    packageName,
    packageVersion,
    parseNodeModules = true,
    includeTransitiveDependencies = true,
    analysisMode = 'bundle',
  } = options;

  let root = '';
  let resolvedOutDir = '';
  let packageInfo: ReturnType<typeof readPackageJson> = null;

  function emitSbom(dependencies: Dependency[]) {
    if (!packageInfo) {
      console.warn('[vite-plugin-dtsbom] package.json not found, skipping SBOM generation');
      return;
    }

    const outputPath = resolve(root, resolvedOutDir || outputDir);

    if (!existsSync(outputPath)) {
      mkdirSync(outputPath, { recursive: true });
    }

    const genOptions = {
      packageName: packageName || packageInfo.name,
      packageVersion: packageVersion || packageInfo.version,
    };

    if (spdx) {
      const spdxContent = generateSPDXJSON(packageInfo, dependencies, genOptions);
      const spdxPath = join(outputPath, 'sbom.spdx.json');
      writeFileSync(spdxPath, spdxContent, 'utf-8');
      console.log(`[vite-plugin-dtsbom] Generated SPDX SBOM: ${spdxPath}`);
    }

    if (cyclonedx) {
      const cyclonedxContent = generateCycloneDXJSON(packageInfo, dependencies, genOptions);
      const cyclonedxPath = join(outputPath, 'sbom.cyclonedx.json');
      writeFileSync(cyclonedxPath, cyclonedxContent, 'utf-8');
      console.log(`[vite-plugin-dtsbom] Generated CycloneDX SBOM: ${cyclonedxPath}`);
    }
  }

  return {
    name: 'vite-plugin-dtsbom',
    enforce: 'post',

    configResolved(config: SbomResolvedConfigSlice) {
      root = config.root;
      resolvedOutDir = config.build.outDir;
      packageInfo = readPackageJson(root);
    },

    generateBundle(
      this: SbomModuleGraphContext,
      _options: unknown,
      bundle: SbomOutputBundleLike
    ) {
      if (analysisMode !== 'bundle') {
        return;
      }

      try {
        const dependencies = collectBundleDependencies(this, bundle, root);
        emitSbom(dependencies);
      } catch (error) {
        console.error('[vite-plugin-dtsbom] Error generating SBOM:', error);
      }
    },

    writeBundle() {
      if (analysisMode !== 'packageGraph') {
        return;
      }

      if (!packageInfo) {
        console.warn('[vite-plugin-dtsbom] package.json not found, skipping SBOM generation');
        return;
      }

      try {
        const dependencies = collectAllDependencies(packageInfo, root, {
          includeDev: includeDevDependencies,
          parseNodeModules,
          includeTransitive: includeTransitiveDependencies,
        });
        emitSbom(dependencies);
      } catch (error) {
        console.error('[vite-plugin-dtsbom] Error generating SBOM:', error);
      }
    },
  };
}

export type { PluginOptions } from './types.js';
