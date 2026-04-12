# vite-plugin-dtsbom

Vite-плагин для автоматической генерации **SBOM (Software Bill of Materials)** во время сборки проекта.

Поддерживаемые форматы: **SPDX 2.3** и **CycloneDX 1.5**.  
Помимо SBOM файлов плагин генерирует **HTML-отчёт** с визуализацией всех зависимостей и найденных уязвимостей, получая актуальные данные CVE из открытой базы **[OSV.dev](https://osv.dev)** прямо во время сборки.

**Репозиторий:** [github.com/timurzeksimbaev/vite-plugin-dtsbom](https://github.com/timurzeksimbaev/vite-plugin-dtsbom)

---

## Возможности

- **Два формата SBOM**: SPDX 2.3 (ISO/IEC 5962:2021) и CycloneDX 1.5 (OWASP стандарт)
- **Анализ бандла**: список компонентов строится по фактическому графу модулей Rollup после tree-shaking — только то, что реально попало в сборку
- **Живая проверка уязвимостей**: батч-запрос к [OSV.dev API](https://osv.dev) во время сборки; находит CVE/GHSA для каждого пакета с CVSS-баллом, описанием, версией фикса и ссылкой на адвизори
- **HTML-отчёт**: наглядная страница со сводкой, таблицей пакетов и карточками CVE
- **Расширенные метаданные**: описание, автор, ключевые слова, лицензия, ссылки на репозиторий из каждого `package.json`
- **Безопасность по умолчанию**: файлы пишутся в `sbom/` вне `dist/`, не попадают в деплой и не занимают место в бандле; папка автоматически игнорируется Git через собственный `.gitignore`
- **Надёжность**: если сеть недоступна — плагин продолжает работу без уязвимостей, сборка никогда не падает

---

## Установка

```bash
npm install --save-dev vite-plugin-dtsbom
# или
yarn add -D vite-plugin-dtsbom
# или
pnpm add -D vite-plugin-dtsbom
```

**Требования:** Node.js ≥ 18, Vite 4–8.

---

## Быстрый старт

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

После `npm run build` файлы появятся в папке `sbom/` в корне проекта — **отдельно от `dist/`**:

```
my-project/
├── dist/                    # деплоится в прод, только JS/HTML/CSS
│   ├── index.html
│   └── assets/
└── sbom/                    # SBOM и отчёт, НЕ попадают в деплой
    ├── .gitignore           # создаётся автоматически, Git игнорирует папку
    ├── sbom.spdx.json
    ├── sbom.cyclonedx.json
    └── sbom-report.html
```

> **Почему не `dist/`?** SBOM раскрывает полный граф зависимостей — это ценная информация для Supply Chain атак. По умолчанию файлы пишутся за пределы build output, чтобы не уходить в продакшн и не раздувать бандл. При необходимости можно задать `outputDir: 'dist'`.

> **`.gitignore` не нужно трогать вручную.** Плагин сам создаёт файл `sbom/.gitignore` с содержимым `*` при первой генерации — Git подхватывает его автоматически.

---

## Все опции

```typescript
vitePluginDtsbom({
  // ── Выходные файлы ──────────────────────────────────────────────────────
  outputDir: 'sbom',              // куда писать файлы (по умолчанию вне dist/)
  spdx: true,                     // генерировать sbom.spdx.json
  cyclonedx: true,                // генерировать sbom.cyclonedx.json
  report: true,                   // генерировать sbom-report.html
  reportFileName: 'sbom-report.html',

  // ── Источник зависимостей ───────────────────────────────────────────────
  analysisMode: 'bundle',         // 'bundle' | 'packageGraph'

  // Только для analysisMode: 'packageGraph'
  includeDevDependencies: false,
  parseNodeModules: true,
  includeTransitiveDependencies: true,

  // ── Идентификация проекта ───────────────────────────────────────────────
  packageName: undefined,         // по умолчанию берётся из package.json
  packageVersion: undefined,

  // ── Проверка уязвимостей ────────────────────────────────────────────────
  fetchVulnerabilities: true,     // запрашивать OSV.dev при каждой сборке
  vulnFetchTimeoutMs: 15000,      // таймаут запроса к OSV.dev (мс)
})
```

### Таблица опций

| Опция | Тип | По умолчанию | Описание |
|---|---|---|---|
| `outputDir` | `string` | `'sbom'` | Папка для SBOM и HTML-отчёта. По умолчанию вне `dist/` — не попадает в деплой |
| `spdx` | `boolean` | `true` | Генерировать `sbom.spdx.json` |
| `cyclonedx` | `boolean` | `true` | Генерировать `sbom.cyclonedx.json` |
| `report` | `boolean` | `true` | Генерировать `sbom-report.html` |
| `reportFileName` | `string` | `'sbom-report.html'` | Имя файла HTML-отчёта |
| `analysisMode` | `'bundle' \| 'packageGraph'` | `'bundle'` | Источник списка зависимостей |
| `includeDevDependencies` | `boolean` | `false` | Включать devDependencies (только `packageGraph`) |
| `parseNodeModules` | `boolean` | `true` | Парсить `node_modules` (только `packageGraph`) |
| `includeTransitiveDependencies` | `boolean` | `true` | Транзитивные зависимости (только `packageGraph`) |
| `packageName` | `string` | из `package.json` | Переопределить имя корневого пакета |
| `packageVersion` | `string` | из `package.json` | Переопределить версию корневого пакета |
| `fetchVulnerabilities` | `boolean` | `true` | Запрашивать уязвимости с OSV.dev |
| `vulnFetchTimeoutMs` | `number` | `15000` | Таймаут HTTP-запроса к OSV.dev (мс) |

---

## Режимы анализа (`analysisMode`)

### `'bundle'` (рекомендуется, по умолчанию)

Плагин подключается к хуку Rollup `generateBundle` и обходит граф модулей **после tree-shaking**. В SBOM попадают только пакеты, чьи файлы реально присутствуют в итоговом бандле. Для каждого компонента сохраняется список выходных чанков, в которых он встречается (`vite:outputChunks`).

### `'packageGraph'`

Классический подход: читает `package.json` проекта и сканирует `node_modules`. Подходит для случаев, когда нужно учесть все установленные пакеты вне зависимости от tree-shaking.

---

## Проверка уязвимостей (OSV.dev)

При каждой сборке плагин выполняет **два шага**:

1. `POST /v1/querybatch` — один батч-запрос для всех пакетов, возвращает список ID уязвимостей
2. `GET /v1/vulns/{id}` — параллельные запросы деталей по каждому уникальному ID

Итого: 2 «раунда» вместо N последовательных запросов. Для 50 пакетов с 20 уникальными CVE это занимает ~1–2 секунды.

Для каждой найденной уязвимости записывается:

- Идентификатор CVE или GHSA
- Уровень опасности: `critical` / `high` / `moderate` / `low`
- CVSS v3 балл (вычисляется из вектора)
- Заголовок и полное описание
- Версия с исправлением (`fixedVersion`)
- Идентификаторы CWE
- Ссылка на адвизори (NVD или GitHub Security Advisories)

Если сеть недоступна или OSV.dev вернул ошибку — плагин выводит предупреждение и продолжает сборку без секции уязвимостей.

---

## Форматы SBOM

### CycloneDX 1.5

Каждый компонент содержит:

```json
{
  "type": "library",
  "bom-ref": "pkg:npm/moment@2.18.1",
  "name": "moment",
  "version": "2.18.1",
  "description": "Parse, validate, manipulate, and display dates",
  "author": "Iskren Ivov Chernev",
  "purl": "pkg:npm/moment@2.18.1",
  "licenses": [{ "license": { "id": "MIT" } }],
  "externalReferences": [
    { "type": "website", "url": "https://momentjs.com" },
    { "type": "distribution", "url": "https://www.npmjs.com/package/moment/v/2.18.1" }
  ],
  "properties": [
    { "name": "npm:keywords", "value": "moment, date, time" },
    { "name": "vite:outputChunks", "value": "index-abc123.js" }
  ]
}
```

Уязвимости выносятся в секцию верхнего уровня `vulnerabilities[]`:

```json
{
  "vulnerabilities": [
    {
      "id": "CVE-2022-24785",
      "source": { "name": "NVD", "url": "https://nvd.nist.gov/vuln/detail/CVE-2022-24785" },
      "ratings": [{ "score": 7.5, "severity": "high", "method": "CVSSv3" }],
      "description": "Path Traversal in moment.locale()",
      "detail": "Moment.js before 2.29.2 is vulnerable to path traversal...",
      "recommendation": "Upgrade to version 2.29.2 or later.",
      "cwes": [22],
      "advisories": [{ "url": "https://nvd.nist.gov/vuln/detail/CVE-2022-24785" }],
      "affects": [{ "ref": "pkg:npm/moment@2.18.1" }]
    }
  ]
}
```

### SPDX 2.3

Каждый пакет содержит:

- `purl` в `externalRefs` с категорией `PACKAGE-MANAGER`
- Для уязвимых пакетов — `externalRefs` с категорией `SECURITY` (`referenceType: "cve"` или `"advisory"`) и комментарием об уровне опасности и версии фикса
- `description`, `supplier` (автор), `downloadLocation` (ссылка на тарбол в npm registry)
- Секция `annotations[]` с `REVIEW`-аннотациями для каждой CVE
- `creationInfo.comment` — общая сводка по найденным уязвимостям

---

## HTML-отчёт

Самодостаточный HTML-файл (без внешних зависимостей, работает офлайн). Содержит:

- **Сводка**: карточки — всего пакетов / уязвимостей / затронутых пакетов / по каждому severity
- **Таблица пакетов**: сортировка по уровню уязвимости; уязвимые строки подсвечены, отображаются название, описание, версия, лицензия, ссылка
- **Карточки CVE**: severity-бейдж, CVSS-шкала с числовым баллом, заголовок, полное описание, затронутый пакет, версия фикса, CWE-ссылки, кнопка «View advisory»

---

## Вывод при сборке

```
[vite-plugin-dtsbom] Checking 12 package(s) against OSV.dev…
[vite-plugin-dtsbom] ⚠  Found 10 known vulnerabilities in 4 package(s): axios@1.14.0, lodash-es@4.17.23, moment@2.18.1, serialize-javascript@3.0.0
[vite-plugin-dtsbom] Generated SPDX SBOM:      sbom/sbom.spdx.json
[vite-plugin-dtsbom] Generated CycloneDX SBOM: sbom/sbom.cyclonedx.json
[vite-plugin-dtsbom] Generated HTML report:    sbom/sbom-report.html
```

---

## Разработка

```bash
# 1. Собрать плагин (TypeScript → dist/)
cd vite-plugin-dtsbom
npm install
npm run build

# 2. Запустить пример — сгенерирует SBOM + HTML-отчёт
cd example
npm install
npm run build
# Результат: example/sbom/

# Режим watch — пересборка плагина при изменениях src/
cd vite-plugin-dtsbom
npm run dev
```

При использовании `file:..` линковки TypeScript может видеть две копии `vite` в `node_modules`. Скрипт `postinstall` в `example/` убирает вложенный `node_modules/vite-plugin-dtsbom/node_modules/vite` автоматически. Если проблема остаётся — в `vite.config.ts` добавьте `as PluginOption[]`:

```typescript
plugins: [react(), vitePluginDtsbom()] as PluginOption[]
```

---

## Лицензия

MIT — © Timur Zheksimbaev
