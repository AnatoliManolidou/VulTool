import { fetchRecentAdvisories } from '../src/components/alert-fetcher';

// Canonical GHSAs tracked in process_results.py's GROUND_TRUTH dict. Sibling GHSAs
// (same package + same installed version, different advisory ID — multer and
// nodemailer each have 3) are NOT tracked there, so a demo-mode pick landing on one
// produces zero scorable evaluation data for that slot.
const CANONICAL_GHSAS = new Set([
  'GHSA-36jr-mh4h-2g58', 'GHSA-f2jv-r9rf-7988', 'GHSA-phwq-j96m-2c2q', 'GHSA-hjrf-2m68-5959',
  'GHSA-wc9g-mqfw-jrwm', 'GHSA-2x7j-588g-ccc2', 'GHSA-2883-xcg3-v3hh', 'GHSA-jxfw-x594-9x9m',
  'GHSA-7w5x-hrqm-74c2', 'GHSA-rgj7-g3m4-5g8c', 'GHSA-j95f-988m-3j2f', 'GHSA-pfrx-2q88-qq97',
  'GHSA-9c47-m6qq-7p4h', 'GHSA-x5rq-j2xg-h7qm', 'GHSA-72xf-g2v4-qvf3', 'GHSA-cf4h-3jhx-xvhq',
  'GHSA-r683-j2x4-v87g',
]);
const SIBLING_GHSAS = new Set([
  'GHSA-535w-7cp7-47q4', 'GHSA-qfvm-cv95-jqjf', // multer siblings of GHSA-wc9g-mqfw-jrwm
  'GHSA-wmmp-3585-3rmp', 'GHSA-cc9r-2j5m-2m83', // nodemailer siblings of GHSA-2x7j-588g-ccc2
]);

describe('fetchRecentAdvisories — demo mode stratified sampling', () => {
  test('always returns exactly 25 entries', async () => {
    const advisories = await fetchRecentAdvisories('fake-token', [], [], true);
    expect(advisories).toHaveLength(25);
  });

  test('rescan mode returns only the single matching GHSA, ignoring sample size', async () => {
    const advisories = await fetchRecentAdvisories(
      'fake-token', [], [], true, 'GHSA-hjrf-2m68-5959',
    );
    expect(advisories.length).toBeGreaterThan(0);
    expect(advisories.every(a => a.ghsaId === 'GHSA-hjrf-2m68-5959')).toBe(true);
  });

  // Regression test: a prior version picked 2 of 21 reachable-pool entries uniformly,
  // 4 of which were sibling GHSAs not tracked by process_results.py. Simulating 2000
  // draws showed ~35% of runs lost at least one of the "guaranteed 2" scorable
  // observations to a sibling pick, and ~3% lost both. Siblings must be excluded from
  // both pools — removing them from the reachable list alone is not enough, since they
  // share the same installed package+version as their canonical counterpart and would
  // still get confirmed at C4 and reach C7-C9 if drawn as "filler," breaking that pool's
  // own guarantee.
  test('never draws a sibling GHSA, and always picks exactly 2 canonical (scorable) entries', async () => {
    const N = 300;
    for (let i = 0; i < N; i++) {
      const advisories = await fetchRecentAdvisories('fake-token', [], [], true);
      expect(advisories.some(a => SIBLING_GHSAS.has(a.ghsaId))).toBe(false);
      expect(advisories.filter(a => CANONICAL_GHSAS.has(a.ghsaId))).toHaveLength(2);
    }
  });
});
