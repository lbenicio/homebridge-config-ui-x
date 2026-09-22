import { randomBytes } from 'node:crypto'
import { mkdtempSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'

import { copy, pathExists, remove, writeFile } from 'fs-extra'

/**
 * Snapshot the shared test storage directory before the run and restore it
 * afterwards.
 *
 * Every e2e spec points UIX_STORAGE_PATH at `test/.homebridge` and copies
 * mock fixtures (auth.json, config.json, ...) over whatever is
 * there. That is the same directory a developer's `npm run watch` runs
 * against - so running the suite silently replaced the dev auth file and
 * secrets (invalidating every JWT already issued) and any other live state.
 * The dashboard spec already restores its own file; this covers everything.
 */

const storageDir = resolve(__dirname, '.homebridge')
const generatedSecretsPath = resolve(__dirname, 'mocks', '.uix-secrets')
let snapshotDir: string | undefined

export async function setup(): Promise<void> {
  await writeFile(generatedSecretsPath, JSON.stringify({ secretKey: randomBytes(32).toString('hex') }))
  if (await pathExists(storageDir)) {
    snapshotDir = mkdtempSync(join(tmpdir(), 'uix-test-storage-'))
    await copy(storageDir, snapshotDir)
  }
}

export async function teardown(): Promise<void> {
  if (snapshotDir) {
    await remove(storageDir)
    await copy(snapshotDir, storageDir)
    await remove(snapshotDir)
  }
  await remove(generatedSecretsPath)
}
