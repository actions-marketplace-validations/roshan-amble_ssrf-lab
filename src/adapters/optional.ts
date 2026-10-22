/**
 * Packages ssrf-lab compares but does not depend on.
 *
 * Installing ssrf-lab must never install a package under test: `ssrf-agent`
 * pulls in `ip` 1.1.9, which carries CVE-2024-29415, and a security tool that
 * makes `npm audit` fail for its users has its priorities backwards. These are
 * devDependencies of this repository and loaded only when a scan selects them.
 */
export const OPTIONAL_PACKAGES = {
  'request-filtering-agent': '3.2.1',
  'ssrf-agent': '1.0.5',
  'ssrf-req-filter': '1.1.1',
  'guarded-fetch': '0.1.5',
} as const

export type OptionalPackage = keyof typeof OPTIONAL_PACKAGES

/**
 * A compared package is not installed.
 *
 * The checker lets this error end a scan instead of turning it into a verdict:
 * a client that never ran has neither blocked nor reached anything.
 */
export class MissingOptionalPackage extends Error {
  constructor(readonly packages: readonly OptionalPackage[]) {
    super(installHint(packages))
    this.name = 'MissingOptionalPackage'
  }
}

/** Load one compared package, or explain how to install it. */
export async function loadOptional<T>(name: OptionalPackage, load: () => Promise<T>): Promise<T> {
  try {
    return await load()
  } catch (error) {
    if (isMissing(error, name)) throw new MissingOptionalPackage([name])
    throw error
  }
}

/** The compared packages from `names` that cannot be loaded here. */
export async function missingOptionalPackages(
  names: readonly OptionalPackage[],
): Promise<OptionalPackage[]> {
  const missing: OptionalPackage[] = []
  for (const name of new Set(names)) {
    try {
      await import(name)
    } catch (error) {
      if (!isMissing(error, name)) throw error
      missing.push(name)
    }
  }
  return missing
}

/**
 * True for Node's "package not found" error about `name` itself.
 *
 * Any other failure, including a missing dependency OF that package, is a real
 * error and must surface as one.
 */
export function isMissing(error: unknown, name: string): boolean {
  if (!(error instanceof Error)) return false
  const code = (error as NodeJS.ErrnoException).code
  if (code !== 'ERR_MODULE_NOT_FOUND' && code !== 'MODULE_NOT_FOUND') return false
  return error.message.includes(`'${name}'`)
}

export function installHint(packages: readonly OptionalPackage[]): string {
  const specs = packages.map((name) => `${name}@${OPTIONAL_PACKAGES[name]}`)
  const npx = specs.map((spec) => `-p ${spec}`).join(' ')
  return [
    `Not installed: ${specs.join(', ')}.`,
    'ssrf-lab compares these packages but does not depend on them, so installing',
    'ssrf-lab never installs a package under test. Install them beside ssrf-lab:',
    '',
    `  npm install --save-dev ${specs.join(' ')}`,
    '',
    'or, with npx:',
    '',
    `  npx -p ssrf-lab ${npx} ssrf-lab scan ...`,
  ].join('\n')
}
