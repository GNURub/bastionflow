import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { getCrowdSecConfig } from "./config";
import { normalizeBouncer, normalizeMachine } from "./normalizers";
import type { CrowdSecBouncer, CrowdSecMachine } from "./types";

const execFileAsync = promisify(execFile);
const cacheTtlMs = 30_000;
let machinesCache: { expiresAt: number; data: CrowdSecMachine[] } | null = null;
let bouncersCache: { expiresAt: number; data: CrowdSecBouncer[] } | null = null;

async function runCscli(args: readonly string[]): Promise<unknown[]> {
  const config = getCrowdSecConfig();
  const command = config.cscliUseSudo ? "sudo" : config.cscliBin;
  const finalArgs = config.cscliUseSudo ? ["-n", config.cscliBin, ...args] : [...args];
  const { stdout } = await execFileAsync(command, finalArgs, { timeout: config.cscliTimeoutMs, maxBuffer: 512_000 });
  const parsed = JSON.parse(stdout) as unknown;
  return Array.isArray(parsed) ? parsed : [parsed];
}

export async function listMachines(): Promise<CrowdSecMachine[]> {
  if (machinesCache && machinesCache.expiresAt > Date.now()) return machinesCache.data;
  try {
    const rows = await runCscli(["machines", "list", "-o", "json"]);
    const data = rows.map(normalizeMachine);
    machinesCache = { data, expiresAt: Date.now() + cacheTtlMs };
    return data;
  } catch {
    return machinesCache?.data ?? [];
  }
}

export async function listBouncers(): Promise<CrowdSecBouncer[]> {
  if (bouncersCache && bouncersCache.expiresAt > Date.now()) return bouncersCache.data;
  try {
    const rows = await runCscli(["bouncers", "list", "-o", "json"]);
    const data = rows.map(normalizeBouncer);
    bouncersCache = { data, expiresAt: Date.now() + cacheTtlMs };
    return data;
  } catch {
    return bouncersCache?.data ?? [];
  }
}
