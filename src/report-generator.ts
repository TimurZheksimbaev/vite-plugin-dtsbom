import type { PackageInfo, Dependency, VulnInfo } from './types.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const SEVERITY_ORDER: Record<VulnInfo['severity'], number> = {
  critical: 0,
  high: 1,
  moderate: 2,
  low: 3,
};

const SEVERITY_COLOR: Record<VulnInfo['severity'], string> = {
  critical: '#b91c1c',
  high:     '#c2410c',
  moderate: '#b45309',
  low:      '#15803d',
};

const SEVERITY_BG: Record<VulnInfo['severity'], string> = {
  critical: '#fee2e2',
  high:     '#ffedd5',
  moderate: '#fef9c3',
  low:      '#dcfce7',
};

function esc(s: string): string {
  return s
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function severityBadge(s: VulnInfo['severity']): string {
  const color = SEVERITY_COLOR[s];
  const bg    = SEVERITY_BG[s];
  return `<span class="badge" style="color:${color};background:${bg}">${s.toUpperCase()}</span>`;
}

function cvssBar(score: number | undefined): string {
  if (score === undefined) return '<span class="na">N/A</span>';
  const pct = (score / 10) * 100;
  const color =
    score >= 9 ? SEVERITY_COLOR.critical :
    score >= 7 ? SEVERITY_COLOR.high :
    score >= 4 ? SEVERITY_COLOR.moderate :
                 SEVERITY_COLOR.low;
  return `
    <span class="cvss-wrap" title="CVSS ${score}">
      <span class="cvss-bar" style="width:${pct}%;background:${color}"></span>
      <span class="cvss-val">${score.toFixed(1)}</span>
    </span>`;
}

function countBySeverity(vulns: VulnInfo[]): Record<VulnInfo['severity'], number> {
  const counts: Record<VulnInfo['severity'], number> = { critical: 0, high: 0, moderate: 0, low: 0 };
  for (const v of vulns) counts[v.severity]++;
  return counts;
}

function repoLink(dep: Dependency): string {
  const url = dep.repository?.replace(/^git\+/, '').replace(/\.git$/, '')
    || dep.homepage;
  if (!url) return '';
  const label = dep.homepage ? dep.homepage : url;
  return `<a href="${esc(url)}" target="_blank" rel="noreferrer">${esc(label)}</a>`;
}

// ---------------------------------------------------------------------------
// Sections
// ---------------------------------------------------------------------------

function renderSummaryCards(
  deps: Dependency[],
  allVulns: VulnInfo[],
  counts: Record<VulnInfo['severity'], number>
): string {
  const vulnPkgs = deps.filter(d => d.vulnerabilities?.length).length;
  return `
  <section class="summary-grid">
    <div class="card">
      <div class="card-value">${deps.length}</div>
      <div class="card-label">Packages</div>
    </div>
    <div class="card">
      <div class="card-value">${allVulns.length}</div>
      <div class="card-label">Known vulnerabilities</div>
    </div>
    <div class="card">
      <div class="card-value">${vulnPkgs}</div>
      <div class="card-label">Affected packages</div>
    </div>
    <div class="card card--critical">
      <div class="card-value">${counts.critical}</div>
      <div class="card-label">Critical</div>
    </div>
    <div class="card card--high">
      <div class="card-value">${counts.high}</div>
      <div class="card-label">High</div>
    </div>
    <div class="card card--moderate">
      <div class="card-value">${counts.moderate}</div>
      <div class="card-label">Moderate</div>
    </div>
    <div class="card card--low">
      <div class="card-value">${counts.low}</div>
      <div class="card-label">Low</div>
    </div>
  </section>`;
}

function renderPackagesTable(deps: Dependency[]): string {
  const rows = deps.map(dep => {
    const vulnCount = dep.vulnerabilities?.length ?? 0;
    const maxSev = vulnCount
      ? dep.vulnerabilities!.reduce<VulnInfo | null>((worst, v) =>
          !worst || SEVERITY_ORDER[v.severity] < SEVERITY_ORDER[worst.severity] ? v : worst, null)
      : null;

    const vulnCell = vulnCount
      ? `<span class="vuln-count" style="color:${SEVERITY_COLOR[maxSev!.severity]}">${vulnCount} vuln${vulnCount > 1 ? 's' : ''}</span>`
      : `<span class="safe">✓ clean</span>`;

    const licenseCell = dep.license
      ? `<code class="license">${esc(dep.license)}</code>`
      : `<span class="na">—</span>`;

    const link = repoLink(dep);

    return `
      <tr class="${vulnCount ? 'row--vuln' : ''}">
        <td><strong>${esc(dep.name)}</strong>${dep.description ? `<br><small>${esc(dep.description.slice(0, 80))}${dep.description.length > 80 ? '…' : ''}</small>` : ''}</td>
        <td><code>${esc(dep.version)}</code></td>
        <td>${licenseCell}</td>
        <td>${link || '<span class="na">—</span>'}</td>
        <td>${vulnCell}</td>
      </tr>`;
  }).join('');

  return `
  <section>
    <h2>Packages <span class="count">(${deps.length})</span></h2>
    <div class="table-wrap">
      <table>
        <thead>
          <tr>
            <th>Package</th>
            <th>Version</th>
            <th>License</th>
            <th>Homepage</th>
            <th>Vulnerabilities</th>
          </tr>
        </thead>
        <tbody>${rows}</tbody>
      </table>
    </div>
  </section>`;
}

function renderVulnCards(deps: Dependency[]): string {
  const affected = deps.filter(d => d.vulnerabilities?.length);
  if (!affected.length) {
    return `
  <section>
    <h2>Vulnerabilities</h2>
    <div class="clean-banner">✓ No known vulnerabilities found in bundled dependencies.</div>
  </section>`;
  }

  // Flatten and sort by severity then CVSS
  const allEntries: Array<{ dep: Dependency; vuln: VulnInfo }> = [];
  for (const dep of affected) {
    for (const vuln of dep.vulnerabilities!) {
      allEntries.push({ dep, vuln });
    }
  }
  allEntries.sort((a, b) => {
    const sevDiff = SEVERITY_ORDER[a.vuln.severity] - SEVERITY_ORDER[b.vuln.severity];
    if (sevDiff !== 0) return sevDiff;
    return (b.vuln.cvss ?? 0) - (a.vuln.cvss ?? 0);
  });

  const cards = allEntries.map(({ dep, vuln }) => {
    const color  = SEVERITY_COLOR[vuln.severity];
    const bg     = SEVERITY_BG[vuln.severity];
    const cweList = vuln.cwe?.length
      ? vuln.cwe.map(c => `<a href="https://cwe.mitre.org/data/definitions/${c.replace('CWE-', '')}.html" target="_blank" rel="noreferrer" class="cwe-link">${esc(c)}</a>`).join(' ')
      : '<span class="na">—</span>';

    const fixBadge = vuln.fixedVersion
      ? `<span class="fix-badge">Fix: ${esc(vuln.fixedVersion)}</span>`
      : `<span class="nofix-badge">No fix available</span>`;

    // Render detail as simple paragraphs (strip markdown headers to plain text)
    const detailText = (vuln.description || '')
      .replace(/#{1,6}\s+/g, '')
      .replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')
      .replace(/`(.+?)`/g, '<code>$1</code>')
      .split('\n\n')
      .filter(p => p.trim())
      .slice(0, 4) // limit to first 4 paragraphs
      .map(p => `<p>${esc(p.trim()).replace(/\n/g, ' ')}</p>`)
      .join('');

    return `
    <div class="vuln-card" style="border-left-color:${color}">
      <div class="vuln-header">
        <div class="vuln-id-group">
          <a href="${esc(vuln.url)}" target="_blank" rel="noreferrer" class="vuln-id">${esc(vuln.id)}</a>
          ${severityBadge(vuln.severity)}
          ${fixBadge}
        </div>
        <div class="vuln-cvss">${cvssBar(vuln.cvss)}</div>
      </div>
      <div class="vuln-title">${esc(vuln.title)}</div>
      <div class="vuln-pkg">
        Affected: <strong>${esc(dep.name)}</strong> <code>@${esc(dep.version)}</code>
      </div>
      <div class="vuln-detail">${detailText}</div>
      <div class="vuln-footer">
        <span>CWE: ${cweList}</span>
        <a href="${esc(vuln.url)}" target="_blank" rel="noreferrer" class="advisory-link">View advisory →</a>
      </div>
    </div>`;
  }).join('');

  return `
  <section>
    <h2>Vulnerabilities <span class="count">(${allEntries.length})</span></h2>
    <div class="vuln-list">${cards}</div>
  </section>`;
}

// ---------------------------------------------------------------------------
// Full HTML document
// ---------------------------------------------------------------------------

const CSS = `
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

  body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    font-size: 14px;
    line-height: 1.6;
    color: #1e293b;
    background: #f8fafc;
    padding: 0 0 60px;
  }

  a { color: #2563eb; text-decoration: none; }
  a:hover { text-decoration: underline; }
  code { font-family: 'SFMono-Regular', Consolas, monospace; font-size: 0.85em; background: #f1f5f9; padding: 1px 5px; border-radius: 4px; }

  /* ── Header ── */
  .site-header {
    background: linear-gradient(135deg, #0f172a 0%, #1e3a5f 100%);
    color: #fff;
    padding: 32px 40px 28px;
    margin-bottom: 32px;
  }
  .site-header h1 { font-size: 1.6rem; font-weight: 700; letter-spacing: -0.3px; }
  .site-header .meta { margin-top: 6px; color: #94a3b8; font-size: 0.82rem; }
  .site-header .meta span { margin-right: 16px; }

  /* ── Layout ── */
  .container { max-width: 1100px; margin: 0 auto; padding: 0 24px; }

  section { margin-bottom: 40px; }
  section h2 {
    font-size: 1.1rem;
    font-weight: 700;
    color: #0f172a;
    margin-bottom: 16px;
    padding-bottom: 8px;
    border-bottom: 2px solid #e2e8f0;
  }
  .count { font-weight: 400; color: #64748b; }

  /* ── Summary cards ── */
  .summary-grid {
    display: flex;
    flex-wrap: wrap;
    gap: 12px;
    margin-bottom: 36px;
  }
  .card {
    flex: 1 1 100px;
    min-width: 100px;
    background: #fff;
    border: 1px solid #e2e8f0;
    border-radius: 10px;
    padding: 16px 18px;
    text-align: center;
    box-shadow: 0 1px 3px rgba(0,0,0,.04);
  }
  .card-value { font-size: 2rem; font-weight: 800; line-height: 1; }
  .card-label { font-size: 0.78rem; color: #64748b; margin-top: 4px; text-transform: uppercase; letter-spacing: .5px; }
  .card--critical .card-value { color: #b91c1c; }
  .card--high     .card-value { color: #c2410c; }
  .card--moderate .card-value { color: #b45309; }
  .card--low      .card-value { color: #15803d; }

  /* ── Table ── */
  .table-wrap { overflow-x: auto; border-radius: 10px; border: 1px solid #e2e8f0; box-shadow: 0 1px 3px rgba(0,0,0,.04); }
  table { width: 100%; border-collapse: collapse; background: #fff; }
  thead { background: #f1f5f9; }
  th { padding: 10px 14px; text-align: left; font-size: 0.78rem; text-transform: uppercase; letter-spacing: .5px; color: #475569; white-space: nowrap; }
  td { padding: 10px 14px; border-top: 1px solid #f1f5f9; vertical-align: top; }
  td small { color: #64748b; display: block; margin-top: 2px; }
  tr.row--vuln { background: #fffbeb; }
  tr.row--vuln:hover { background: #fef9c3; }
  tr:not(.row--vuln):hover td { background: #f8fafc; }

  .license { font-size: 0.8em; }
  .safe { color: #15803d; font-weight: 600; }
  .vuln-count { font-weight: 700; }
  .na { color: #94a3b8; }

  /* ── Severity badge ── */
  .badge {
    display: inline-block;
    font-size: 0.72rem;
    font-weight: 700;
    padding: 2px 8px;
    border-radius: 20px;
    letter-spacing: .4px;
    text-transform: uppercase;
  }

  /* ── CVSS bar ── */
  .cvss-wrap {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    width: 100%;
    min-width: 90px;
  }
  .cvss-bar {
    display: inline-block;
    height: 6px;
    border-radius: 3px;
    flex: 1;
  }
  .cvss-val { font-size: 0.85rem; font-weight: 700; white-space: nowrap; min-width: 26px; text-align: right; }

  /* ── Vuln cards ── */
  .vuln-list { display: flex; flex-direction: column; gap: 16px; }
  .vuln-card {
    background: #fff;
    border: 1px solid #e2e8f0;
    border-left: 4px solid #64748b;
    border-radius: 10px;
    padding: 18px 20px;
    box-shadow: 0 1px 3px rgba(0,0,0,.04);
  }
  .vuln-header {
    display: flex;
    justify-content: space-between;
    align-items: flex-start;
    gap: 12px;
    flex-wrap: wrap;
    margin-bottom: 8px;
  }
  .vuln-id-group { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
  .vuln-id { font-weight: 700; font-size: 0.92rem; font-family: monospace; }
  .vuln-cvss { min-width: 120px; max-width: 160px; flex: 1; }

  .fix-badge   { font-size: 0.75rem; background: #dcfce7; color: #15803d; padding: 2px 8px; border-radius: 20px; font-weight: 600; }
  .nofix-badge { font-size: 0.75rem; background: #f1f5f9; color: #64748b;  padding: 2px 8px; border-radius: 20px; font-weight: 600; }

  .vuln-title { font-weight: 600; font-size: 1rem; color: #0f172a; margin-bottom: 6px; }
  .vuln-pkg   { font-size: 0.82rem; color: #475569; margin-bottom: 10px; }

  .vuln-detail { font-size: 0.85rem; color: #475569; margin-bottom: 12px; }
  .vuln-detail p { margin-bottom: 4px; }

  .vuln-footer {
    display: flex;
    justify-content: space-between;
    align-items: center;
    flex-wrap: wrap;
    gap: 8px;
    font-size: 0.8rem;
    color: #64748b;
    padding-top: 10px;
    border-top: 1px solid #f1f5f9;
  }
  .cwe-link    { font-family: monospace; font-size: 0.8em; }
  .advisory-link { font-weight: 600; font-size: 0.82rem; }

  /* ── Clean banner ── */
  .clean-banner {
    background: #dcfce7;
    color: #15803d;
    border: 1px solid #bbf7d0;
    border-radius: 10px;
    padding: 20px 24px;
    font-weight: 600;
    font-size: 1rem;
  }

  /* ── Footer ── */
  .site-footer {
    margin-top: 48px;
    text-align: center;
    font-size: 0.78rem;
    color: #94a3b8;
  }
`;

export function generateHTMLReport(
  packageInfo: PackageInfo,
  dependencies: Dependency[],
  options: { packageName?: string; packageVersion?: string } = {}
): string {
  const pkgName    = options.packageName    || packageInfo.name    || 'unknown';
  const pkgVersion = options.packageVersion || packageInfo.version || '0.0.0';
  const now        = new Date().toUTCString();

  const allVulns = dependencies.flatMap(d => d.vulnerabilities ?? []);
  const counts   = countBySeverity(allVulns);

  // Sort: vulnerable packages first (by worst severity), then alphabetical
  const sorted = [...dependencies].sort((a, b) => {
    const aWorst = a.vulnerabilities?.reduce<number>((m, v) => Math.min(m, SEVERITY_ORDER[v.severity]), 99) ?? 99;
    const bWorst = b.vulnerabilities?.reduce<number>((m, v) => Math.min(m, SEVERITY_ORDER[v.severity]), 99) ?? 99;
    if (aWorst !== bWorst) return aWorst - bWorst;
    return a.name.localeCompare(b.name);
  });

  const vulnSummaryText = allVulns.length > 0
    ? `${allVulns.length} vulnerabilit${allVulns.length === 1 ? 'y' : 'ies'} found (${counts.critical} critical, ${counts.high} high, ${counts.moderate} moderate, ${counts.low} low)`
    : 'No known vulnerabilities';

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>SBOM Report — ${esc(pkgName)} ${esc(pkgVersion)}</title>
  <style>${CSS}</style>
</head>
<body>

  <header class="site-header">
    <div class="container">
      <h1>SBOM Report</h1>
      <div class="meta">
        <span>📦 ${esc(pkgName)} ${esc(pkgVersion)}</span>
        <span>🕐 Generated ${now}</span>
        <span>🔍 ${vulnSummaryText}</span>
      </div>
    </div>
  </header>

  <div class="container">
    ${renderSummaryCards(sorted, allVulns, counts)}
    ${renderPackagesTable(sorted)}
    ${renderVulnCards(sorted)}
  </div>

  <footer class="site-footer">
    <div class="container">
      Generated by <strong>vite-plugin-dtsbom</strong> · Vulnerability data from <a href="https://osv.dev" target="_blank">OSV.dev</a>
    </div>
  </footer>

</body>
</html>`;
}
