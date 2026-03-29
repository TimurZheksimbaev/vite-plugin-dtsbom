# vite-plugin-dtsbom

Vite plugin для генерации SBOM (Software Bill of Materials) в форматах SPDX и CycloneDX.

**Исходники:** [github.com/timurzeksimbaev/vite-plugin-dtsbom](https://github.com/timurzeksimbaev/vite-plugin-dtsbom) (если форк под другим пользователем — поправь ссылку в README и в `package.json`). Публикация в npm и push на GitHub: см. [DEPLOY.md](./DEPLOY.md).

## Описание

Интеграция с «сборщиком Vite» выполняется через официальный API плагинов (Rollup `generateBundle`): отдельный форк репозитория Vite для диплома обычно не нужен — та же точка расширения, что использует сам Vite для сборки.

`vite-plugin-dtsbom` автоматически генерирует SBOM файлы для вашего проекта во время сборки Vite. По умолчанию список компонентов строится по **фактическому графу модулей Rollup** (после tree-shaking и разбиения на чанки), а не по полному `node_modules`. Плагин поддерживает два основных формата:

- **SPDX** (Software Package Data Exchange) - стандарт ISO/IEC 5962:2021
- **CycloneDX** - формат OWASP для управления зависимостями и уязвимостями

## Установка

```bash
npm install --save-dev vite-plugin-dtsbom
```

или

```bash
yarn add -D vite-plugin-dtsbom
```

или

```bash
pnpm add -D vite-plugin-dtsbom
```

**Peer dependency:** в проекте должен быть установлен **Vite 4–8** (см. `peerDependencies` в `package.json`). Если раньше `npm install` ругался на peer deps и помогал только `--legacy-peer-deps`, чаще всего причина в том, что в приложении стоял **Vite 7/8**, а в старой версии плагина в peer были только 4–6 — обнови плагин до **≥1.0.1**.

## Использование

### Базовое использование

```typescript
// vite.config.ts
import { defineConfig } from 'vite';
import vitePluginDtsbom from 'vite-plugin-dtsbom';

export default defineConfig({
  plugins: [
    vitePluginDtsbom()
  ]
});
```

### Расширенная конфигурация

```typescript
// vite.config.ts
import { defineConfig } from 'vite';
import vitePluginDtsbom from 'vite-plugin-dtsbom';

export default defineConfig({
  plugins: [
    vitePluginDtsbom({
      outputDir: 'dist',                    // Директория для сохранения SBOM файлов
      spdx: true,                           // Генерировать SPDX формат
      cyclonedx: true,                      // Генерировать CycloneDX формат
      analysisMode: 'bundle',               // 'bundle' | 'packageGraph' (см. ниже)
      includeDevDependencies: false,        // Только для packageGraph: dev зависимости
      parseNodeModules: true,               // Только для packageGraph: парсить node_modules
      includeTransitiveDependencies: true,  // Только для packageGraph: транзитивные
      packageName: 'my-package',            // Кастомное имя пакета (опционально)
      packageVersion: '1.0.0',             // Кастомная версия (опционально)
    })
  ]
});
```

## Опции

| Опция | Тип | По умолчанию | Описание |
|-------|-----|--------------|----------|
| `outputDir` | `string` | `'dist'` | Директория для сохранения SBOM файлов |
| `spdx` | `boolean` | `true` | Генерировать SPDX формат |
| `cyclonedx` | `boolean` | `true` | Генерировать CycloneDX формат |
| `analysisMode` | `'bundle' \| 'packageGraph'` | `'bundle'` | **`bundle`**: только пакеты, чьи файлы попали в итоговый бандл; привязка к чанкам (CycloneDX `properties` `vite:outputChunks`, SPDX `comment`). **`packageGraph`**: прежнее поведение — обход `package.json` / `node_modules` |
| `includeDevDependencies` | `boolean` | `false` | Только `packageGraph`: включать dev зависимости |
| `parseNodeModules` | `boolean` | `true` | Только `packageGraph`: парсить node_modules |
| `includeTransitiveDependencies` | `boolean` | `true` | Только `packageGraph`: транзитивные зависимости |
| `packageName` | `string` | `undefined` | Кастомное имя пакета (если отличается от package.json) |
| `packageVersion` | `string` | `undefined` | Кастомная версия (если отличается от package.json) |

## Выходные файлы

После сборки проекта плагин создаст следующие файлы в указанной директории (`outputDir`):

- `sbom.spdx.json` - SBOM в формате SPDX 2.3
- `sbom.cyclonedx.json` - SBOM в формате CycloneDX 1.5

## Примеры

### Генерация только SPDX

```typescript
vitePluginDtsbom({
  spdx: true,
  cyclonedx: false,
})
```

### Генерация только CycloneDX

```typescript
vitePluginDtsbom({
  spdx: false,
  cyclonedx: true,
})
```

### Включение dev зависимостей

```typescript
vitePluginDtsbom({
  includeDevDependencies: true,
})
```

### Только прямые зависимости (без парсинга node_modules)

```typescript
vitePluginDtsbom({
  parseNodeModules: false,
})
```

### Парсинг node_modules без транзитивных зависимостей

```typescript
vitePluginDtsbom({
  parseNodeModules: true,
  includeTransitiveDependencies: false,
})
```

## Парсинг node_modules

По умолчанию плагин парсит директорию `node_modules` для получения:

- **Реальных установленных версий** - вместо диапазонов версий из `package.json` (например, `^1.0.0` → `1.2.3`)
- **Транзитивных зависимостей** - все зависимости ваших зависимостей
- **Точной информации о лицензиях** - из реальных установленных пакетов
- **Дополнительной метаинформации** - homepage, repository и т.д.

Это важно для полноценного SBOM, так как:
- `package.json` содержит только прямые зависимости с диапазонами версий
- Реальные версии могут отличаться из-за разрешения зависимостей
- Транзитивные зависимости не видны в `package.json`, но присутствуют в `node_modules`

Если вы хотите включить только прямые зависимости из `package.json`, установите `parseNodeModules: false`.

## Форматы SBOM

### SPDX

Плагин генерирует SBOM в формате SPDX 2.3, который включает:

- Метаданные документа
- Информацию о корневом пакете
- Список всех зависимостей
- Связи между пакетами (DEPENDS_ON)
- Информацию о лицензиях

### CycloneDX

Плагин генерирует SBOM в формате CycloneDX 1.5, который включает:

- Метаданные с информацией о инструменте
- Корневой компонент приложения
- Компоненты зависимостей
- PURL (Package URL) для каждой зависимости
- Информацию о лицензиях

## Требования

- Node.js >= 16.0.0
- Vite >= 4.0.0 или >= 5.0.0

## Лицензия

MIT

## Разработка

```bash
# Установка зависимостей (в корне пакета `vite` нет в devDependencies — типы плагина не привязаны к копии Vite в этом репозитории)
npm install

# Сборка проекта
npm run build

# Режим разработки с watch
npm run dev
```

### TypeScript: «две копии Vite» / `Plugin` не совместим с `PluginOption`

Если при линковке через `file:..` в `vite-plugin-dtsbom/node_modules` осталась старая папка `vite`, TypeScript видит два разных типа `Plugin`. Удалите вложенный `vite` или переустановите зависимости; в примере `example/` после `npm install` скрипт `postinstall` пытается убрать `node_modules/vite-plugin-dtsbom/node_modules/vite` автоматически. В крайнем случае в `vite.config.ts` можно задать `plugins: [...] as import('vite').PluginOption[]`.

## Публикация в npm

```bash
# Сборка проекта
npm run build

# Публикация
npm publish
```

## Поддержка

Если вы нашли баг или у вас есть предложение, пожалуйста, создайте issue в репозитории проекта.

