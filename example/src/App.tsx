import React, { useEffect, useMemo, useState } from 'react';
import axios from 'axios';
import clsx from 'clsx';
import { format } from 'date-fns';
import { capitalize, uniqueId } from 'lodash-es';
import moment from 'moment';
import { nanoid } from 'nanoid';
import serialize from 'serialize-javascript';
import { z } from 'zod';

const payloadSchema = z.object({
  title: z.string().min(1),
  when: z.string().datetime(),
});

const FALLBACK_TEXT =
  'Локальный текст: запрос не прошёл (сеть / блокировка). Axios и остальные пакеты всё равно в бандле.';

// ⚠️  НАМЕРЕННО уязвимые версии — только для демонстрации SBOM:
//   serialize-javascript@3.0.0 — CVE-2020-7660 (XSS при сериализации RegExp/Date)
//   moment@2.18.1              — CVE-2022-24785 (Path Traversal), CVE-2017-18214 (ReDoS)
// Оба пакета попадут в SBOM, т.к. Rollup видит их в статическом module graph.
const SERIALIZED_META = serialize({ sbomDemo: true, pkgs: ['serialize-javascript@3.0.0', 'moment@2.18.1'] });

export function App(): React.JSX.Element {
  const [remote, setRemote] = useState<string>('Загрузка…');

  const demo = useMemo(() => {
    const when = new Date().toISOString();
    const parsed = payloadSchema.safeParse({
      title: capitalize('sbom demo'),
      when,
    });
    return {
      ok: parsed.success,
      id: nanoid(8),
      uid: uniqueId('row-'),
      label: format(new Date(when), 'yyyy-MM-dd HH:mm'),
    };
  }, []);

  async function loadRemote() {
    setRemote('Загрузка…');
    try {
      // Публичный JSONPlaceholder отдаёт CORS * — в браузере надёжнее, чем многие «цитатные» API.
      const { data } = await axios.get<{ title: string; body: string }>(
        'https://jsonplaceholder.typicode.com/posts/1',
        { timeout: 8000 }
      );
      const snippet = data.body.replace(/\s+/g, ' ').trim().slice(0, 180);
      setRemote(`${data.title} — ${snippet}…`);
    } catch {
      setRemote(FALLBACK_TEXT);
    }
  }

  // moment используется для форматирования — moment@2.18.1 имеет CVE-2022-24785.
  const momentLabel = moment().format('YYYY-MM-DD');

  useEffect(() => {
    void loadRemote();
  }, []);

  return (
    <main className={clsx('wrap', demo.ok && 'wrap--ok')}>
      <h1>Vite + SBOM — много зависимостей</h1>
      <p>
        Собрано с: axios, zod, date-fns, lodash-es, nanoid, clsx + react. После{' '}
        <code>npm run build</code> смотри <code>dist/sbom.*.json</code>.
      </p>
      <p className="meta">
        {demo.label} · <code>{demo.id}</code> · <code>{demo.uid}</code>
      </p>
      <details>
        <summary>⚠️ Уязвимые пакеты (SBOM demo)</summary>
        <ul>
          <li>
            <strong>serialize-javascript@3.0.0</strong> — CVE-2020-7660 (XSS)
            <br />
            <code style={{ fontSize: '0.8em' }}>{SERIALIZED_META}</code>
          </li>
          <li>
            <strong>moment@2.18.1</strong> — CVE-2022-24785 (Path Traversal), CVE-2017-18214 (ReDoS)
            <br />
            <code style={{ fontSize: '0.8em' }}>moment().format() → {momentLabel}</code>
          </li>
        </ul>
      </details>
      <button type="button" onClick={() => void loadRemote()}>
        Обновить данные (axios)
      </button>
      <blockquote>{remote}</blockquote>
    </main>
  );
}
