import type { ScanResult, Verdict } from './run.js'

const MARKS: Record<Verdict, string> = {
  BLOCKED: '[+] BLOCKED  ',
  PREVENTED: '[=] PREVENTED',
  REACHED: '[!] REACHED  ',
  LUCKY: '[~] LUCKY    ',
  'NOT-APPLICABLE': '[-] N/A      ',
}

export const LEGEND = [
  '[+] BLOCKED    the client refused, and named the control that refused',
  '[=] PREVENTED  the attack never arrived, but the client named no control',
  '[!] REACHED    the client arrived, or never stopped reading',
  '[~] LUCKY      nothing refused it; something else failed first',
  '[-] N/A        the client has no hook this probe can use',
].join('\n')

/** Render 1 scan as a table for a terminal. */
export function renderTable(scan: ScanResult): string {
  const titleWidth = Math.max(...scan.results.map((row) => row.title.length))
  const lines = scan.results.map(
    (row) => `  ${MARKS[row.verdict]}  ${row.title.padEnd(titleWidth)}  ${row.note}`,
  )

  const summary =
    `  ${scan.blocked} blocked · ${scan.prevented} prevented · ${scan.reached} reached · ` +
    `${scan.lucky} lucky · ${scan.notApplicable} not applicable`

  return [`\n${scan.client}`, '-'.repeat(scan.client.length), ...lines, '', summary].join('\n')
}

export function renderJson(scans: readonly ScanResult[]): string {
  return JSON.stringify({ scans }, null, 2)
}
