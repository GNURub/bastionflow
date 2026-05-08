import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { getCrowdSecConfig } from "./config";
import { normalizeBouncer, normalizeMachine } from "./normalizers";
import type { CrowdSecBouncer, CrowdSecMachine } from "./types";

const execFileAsync = promisify(execFile);

async function runCscli(args: readonly string[]): Promise<unknown[]> {
  const config = getCrowdSecConfig();
  const command = config.cscliUseSudo ? "sudo" : config.cscliBin;
  const finalArgs = config.cscliUseSudo ? ["-n", config.cscliBin, ...args] : [...args];
  const { stdout } = await execFileAsync(command, finalArgs, { timeout: 5_000, maxBuffer: 512_000 });
  const parsed = JSON.parse(stdout) as unknown;
  return Array.isArray(parsed) ? parsed : [parsed];
}

export async function listMachines(): Promise<CrowdSecMachine[]> {
  try {
    const rows = await runCscli(["machines", "list", "-o", "json"]);
    return rows.map(normalizeMachine);
  } catch {
    return [];
  }
}

export async function listBouncers(): Promise<CrowdSecBouncer[]> {
  try {
    const rows = await runCscli(["bouncers", "list", "-o", "json"]);
    return rows.map(normalizeBouncer);
  } catch {
    return [];
  }
}
