/**
 * Локальные типы без импорта `vite` / `rollup`, чтобы в проекте-потребителе не было
 * двух копий типов Vite (несовместимых для TypeScript при `file:` / вложенных node_modules).
 */

/** Минимальный контекст плагина Rollup/Vite для обхода графа модулей */
export interface SbomModuleGraphContext {
  getModuleIds(): IterableIterator<string>;
}

export interface SbomOutputChunkLike {
  type: string;
  moduleIds?: readonly string[];
}

export type SbomOutputBundleLike = Record<string, SbomOutputChunkLike>;

/** Подмножество ResolvedConfig, которое использует плагин */
export interface SbomResolvedConfigSlice {
  root: string;
  build: { outDir: string };
}
