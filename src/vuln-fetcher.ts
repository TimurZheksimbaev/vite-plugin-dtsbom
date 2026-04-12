import type { VulnInfo } from './types.js';

// ---------------------------------------------------------------------------
// OSV.dev API types  (https://google.github.io/osv.dev/api/)
// ---------------------------------------------------------------------------

interface OsvVulnRef {
  id: string;
  modified?: string;
}

interface OsvQueryBatchResponse {
  results: Array<{ vulns?: OsvVulnRef[] }>;
}

interface OsvAffected {
  package?: { ecosystem: string; name: string };
  ranges?: Array<{
    type: 'SEMVER' | 'GIT' | 'ECOSYSTEM';
    events: Array<{ introduced?: string; fixed?: string; last_affected?: string }>;
  }>;
  versions?: string[];
}

interface OsvSeverityEntry {
  type: 'CVSS_V2' | 'CVSS_V3' | 'CVSS_V4';
  score: string; // vector string, e.g. "CVSS:3.1/AV:N/AC:L/..."
}

interface OsvDatabaseSpecific {
  severity?: string;   // "CRITICAL" | "HIGH" | "MODERATE" | "LOW"
  cwe_ids?: string[];
  github_reviewed?: boolean;
  cvss?: { score: number; vectorString: string };
}

interface OsvVulnDetail {
  id: string;
  summary?: string;
  details?: string;
  aliases?: string[];
  severity?: OsvSeverityEntry[];
  affected?: OsvAffected[];
  references?: Array<{ type: string; url: string }>;
  database_specific?: OsvDatabaseSpecific;
}

// ---------------------------------------------------------------------------
// CVSS v3 base score calculation from vector string
// Reference: https://www.first.org/cvss/calculator/3.1
// ---------------------------------------------------------------------------

const CVSS3_WEIGHTS: Record<string, Record<string, number>> = {
  AV: { N: 0.85, A: 0.62, L: 0.55, P: 0.2 },
  AC: { L: 0.77, H: 0.44 },
  PR: { N: 0.85, L: 0.62, H: 0.27 },
  UI: { N: 0.85, R: 0.62 },
  C:  { N: 0,    L: 0.22,  H: 0.56 },
  I:  { N: 0,    L: 0.22,  H: 0.56 },
  A:  { N: 0,    L: 0.22,  H: 0.56 },
};

function parseCvssV3Score(vector: string): number | undefined {
  const body = vector.replace(/^CVSS:\d+\.\d+\//, '');
  const parts: Record<string, string> = {};
  for (const kv of body.split('/')) {
    const [k, v] = kv.split(':');
    if (k && v) parts[k] = v;
  }
  try {
    const av = CVSS3_WEIGHTS['AV'][parts['AV']] ?? 0;
    const ac = CVSS3_WEIGHTS['AC'][parts['AC']] ?? 0;
    const pr = CVSS3_WEIGHTS['PR'][parts['PR']] ?? 0;
    const ui = CVSS3_WEIGHTS['UI'][parts['UI']] ?? 0;
    const c  = CVSS3_WEIGHTS['C'][parts['C']]   ?? 0;
    const i  = CVSS3_WEIGHTS['I'][parts['I']]   ?? 0;
    const a  = CVSS3_WEIGHTS['A'][parts['A']]   ?? 0;

    const iss = 1 - (1 - c) * (1 - i) * (1 - a);
    if (iss === 0) return 0;

    const scope = parts['S'];
    const impact =
      scope === 'U'
        ? 6.42 * iss
        : 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15);
    const exploitability = 8.22 * av * ac * pr * ui;
    const raw =
      scope === 'U'
        ? Math.min(impact + exploitability, 10)
        : Math.min(1.08 * (impact + exploitability), 10);

    return Math.ceil(raw * 10) / 10;
  } catch {
    return undefined;
  }
}

// ---------------------------------------------------------------------------
// Parsing helpers
// ---------------------------------------------------------------------------

function normalizeSeverity(raw?: string): VulnInfo['severity'] {
  switch (raw?.toUpperCase()) {
    case 'CRITICAL': return 'critical';
    case 'HIGH':     return 'high';
    case 'MODERATE': return 'moderate';
    case 'LOW':      return 'low';
    default:         return 'moderate';
  }
}

function extractFixedVersion(vuln: OsvVulnDetail, pkgName: string): string | undefined {
  for (const aff of vuln.affected ?? []) {
    if (aff.package?.name && aff.package.name !== pkgName) continue;
    for (const range of aff.ranges ?? []) {
      if (range.type !== 'SEMVER') continue;
      for (const ev of range.events) {
        if (ev.fixed) return ev.fixed;
      }
    }
  }
  return undefined;
}

function extractAdvisoryUrl(vuln: OsvVulnDetail): string {
  // Preferred reference types in order
  for (const type of ['ADVISORY', 'WEB', 'ARTICLE']) {
    const ref = vuln.references?.find(r => r.type === type);
    if (ref) return ref.url;
  }
  return vuln.references?.[0]?.url ?? `https://osv.dev/vulnerability/${vuln.id}`;
}

function osvDetailToVulnInfo(vuln: OsvVulnDetail, pkgName: string): VulnInfo {
  const severity = normalizeSeverity(vuln.database_specific?.severity);

  let cvss: number | undefined;
  if (typeof vuln.database_specific?.cvss?.score === 'number') {
    cvss = vuln.database_specific.cvss.score;
  } else {
    const v3 = vuln.severity?.find(s => s.type === 'CVSS_V3');
    if (v3) cvss = parseCvssV3Score(v3.score);
  }

  // Prefer the CVE alias as display ID (more recognisable)
  const cveAlias = vuln.aliases?.find(a => a.startsWith('CVE-'));
  const id = cveAlias ?? vuln.id;

  return {
    id,
    severity,
    cvss,
    title: vuln.summary ?? `Vulnerability ${id}`,
    description: vuln.details ?? vuln.summary ?? 'No description available.',
    url: extractAdvisoryUrl(vuln),
    fixedVersion: extractFixedVersion(vuln, pkgName),
    cwe: vuln.database_specific?.cwe_ids,
  };
}

// ---------------------------------------------------------------------------
// Network helpers
// ---------------------------------------------------------------------------

const OSV_BASE = 'https://api.osv.dev/v1';
const DEFAULT_TIMEOUT_MS = 15_000;

function createController(ms: number): { signal: AbortSignal; clear: () => void } {
  const ac = new AbortController();
  const timer = setTimeout(() => ac.abort(), ms);
  return { signal: ac.signal, clear: () => clearTimeout(timer) };
}

async function fetchJson<T>(
  url: string,
  init: RequestInit,
  timeoutMs: number
): Promise<T | null> {
  const { signal, clear } = createController(timeoutMs);
  try {
    const resp = await fetch(url, { ...init, signal });
    clear();
    if (!resp.ok) return null;
    return (await resp.json()) as T;
  } catch {
    clear();
    return null;
  }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

export interface FetchVulnOptions {
  timeoutMs?: number;
}

/**
 * Fetch vulnerability data for a batch of npm packages from OSV.dev.
 *
 * Flow:
 *   1. POST /v1/querybatch — get vuln IDs per package (one round-trip)
 *   2. GET  /v1/vulns/{id} — fetch full details in parallel
 *
 * Returns a Map keyed by "name@version" → VulnInfo[].
 * Gracefully returns an empty map if the network is unavailable — the build never fails.
 */
export async function fetchVulnerabilitiesBatch(
  packages: Array<{ name: string; version: string }>,
  opts: FetchVulnOptions = {}
): Promise<Map<string, VulnInfo[]>> {
  const result = new Map<string, VulnInfo[]>();
  if (!packages.length) return result;

  if (typeof fetch === 'undefined') {
    console.warn('[vite-plugin-dtsbom] global fetch not available (Node < 18) — skipping OSV lookup');
    return result;
  }

  const timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;

  console.log(
    `[vite-plugin-dtsbom] Checking ${packages.length} package(s) against OSV.dev…`
  );

  // ── Step 1: batch query to get vuln IDs per package ─────────────────────
  const queries = packages.map(p => ({
    package: { name: p.name, ecosystem: 'npm' },
    version: p.version,
  }));

  const batchResp = await fetchJson<OsvQueryBatchResponse>(
    `${OSV_BASE}/querybatch`,
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ queries }),
    },
    timeoutMs
  );

  if (!batchResp) {
    console.warn('[vite-plugin-dtsbom] OSV.dev querybatch failed — skipping vulnerability check');
    return result;
  }

  // Build: vulnId → [packages that have it]
  const idToPkgs = new Map<string, string[]>(); // vulnId → ["name@version", ...]
  for (let i = 0; i < packages.length; i++) {
    const key = `${packages[i].name}@${packages[i].version}`;
    for (const ref of batchResp.results[i]?.vulns ?? []) {
      const list = idToPkgs.get(ref.id) ?? [];
      list.push(key);
      idToPkgs.set(ref.id, list);
    }
  }

  const uniqueIds = [...idToPkgs.keys()];
  if (!uniqueIds.length) return result;

  // ── Step 2: fetch full details in parallel ───────────────────────────────
  const detailResults = await Promise.all(
    uniqueIds.map(id =>
      fetchJson<OsvVulnDetail>(`${OSV_BASE}/vulns/${id}`, { method: 'GET' }, timeoutMs)
    )
  );

  // Build per-package vuln list
  const pkgVulns = new Map<string, VulnInfo[]>(); // "name@version" → VulnInfo[]

  for (let i = 0; i < uniqueIds.length; i++) {
    const detail = detailResults[i];
    if (!detail) continue;

    const affectedPkgKeys = idToPkgs.get(uniqueIds[i]) ?? [];
    for (const pkgKey of affectedPkgKeys) {
      const pkgName = pkgKey.split('@')[0];
      const info = osvDetailToVulnInfo(detail, pkgName);
      const list = pkgVulns.get(pkgKey) ?? [];
      // Deduplicate by canonical id
      if (!list.some(v => v.id === info.id)) {
        list.push(info);
      }
      pkgVulns.set(pkgKey, list);
    }
  }

  for (const [key, vulns] of pkgVulns) {
    if (vulns.length) result.set(key, vulns);
  }

  return result;
}
