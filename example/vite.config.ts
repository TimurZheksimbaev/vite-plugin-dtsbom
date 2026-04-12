import { defineConfig, type PluginOption } from 'vite';
import react from '@vitejs/plugin-react';
import vitePluginDtsbom from 'vite-plugin-dtsbom';

export default defineConfig({
  // Явный тип массива: при `file:..` у плагина могла остаться вторая копия `vite` в node_modules,
  // из‑за чего TS считает `Plugin` из разных путей несовместимыми.
  plugins: [
    react(),
    vitePluginDtsbom({
      // 'sbom' is the default — outside dist/ so reports never ship to production
      outputDir: 'dist',
      spdx: true,
      cyclonedx: true,
      analysisMode: 'bundle',
    }),
  ] as PluginOption[],
});
