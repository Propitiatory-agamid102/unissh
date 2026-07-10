// Pure transfer logic — conflict/resume decisions, EMA speed/ETA, and recursive
// directory enumeration. No bridge calls and no store access here, so this stays
// easy to reason about (and unit-testable if a runner is ever added). Time is
// passed in by the caller rather than read from a clock, for the same reason.

import type { Entry } from "@/store/sftp-types";
import type { FileSource } from "@/bridge/sources";
import { isSafeName } from "@/sftp/paths";

/** A name collision exists at the destination. */
export function hasConflict(target: Entry | null): boolean {
  return target != null;
}

/** Resume only makes sense when a strictly shorter, non-dir partial exists; the
 *  core's resumable upload/download appends from `offset` keeping the prefix. */
export function canResume(target: Entry | null, sourceSize: number): boolean {
  return target != null && !target.isDir && target.size > 0 && target.size < sourceSize;
}

/** Exponential-moving-average speedometer. `sample(bytesSoFar, nowMs)` is called
 *  on every progress tick; `speed()` is bytes/sec, `eta(remaining)` is seconds. */
export class Speedometer {
  private lastBytes = 0;
  private lastT = 0;
  private bps = 0;
  private started = false;

  sample(bytes: number, nowMs: number): void {
    if (!this.started) {
      this.started = true;
      this.lastBytes = bytes;
      this.lastT = nowMs;
      return;
    }
    const dt = (nowMs - this.lastT) / 1000;
    if (dt <= 0) return;
    const inst = (bytes - this.lastBytes) / dt;
    this.bps = this.bps === 0 ? inst : this.bps * 0.7 + inst * 0.3;
    this.lastBytes = bytes;
    this.lastT = nowMs;
  }

  speed(): number {
    return Math.max(0, this.bps);
  }

  eta(remaining: number): number {
    if (this.bps <= 0 || remaining <= 0) return remaining <= 0 ? 0 : Infinity;
    return remaining / this.bps;
  }
}

/** Bounded-concurrency gate. `run(fn)` waits for a free slot, runs `fn`, and
 *  releases the slot. `capacity` slots run at once; the rest queue FIFO. Used to
 *  cap concurrent SFTP operations to the channel-pool size so file transfers,
 *  directory listings, and mkdirs across a whole batch never exceed K in flight
 *  (more would just block on the core's pool anyway). Pure and self-contained. */
export class Semaphore {
  private avail: number;
  private readonly waiters: Array<() => void> = [];

  constructor(capacity: number) {
    this.avail = Math.max(1, Math.floor(capacity));
  }

  async run<T>(fn: () => Promise<T>): Promise<T> {
    await this.acquire();
    try {
      return await fn();
    } finally {
      this.release();
    }
  }

  private acquire(): Promise<void> {
    if (this.avail > 0) {
      this.avail -= 1;
      return Promise.resolve();
    }
    return new Promise<void>((resolve) => this.waiters.push(resolve));
  }

  private release(): void {
    const next = this.waiters.shift();
    if (next) next();
    else this.avail += 1;
  }
}

export interface WalkItem {
  relPath: string; // path relative to the walk root, joined with "/"
  isDir: boolean;
  size: number;
}

/** Result of scanning a directory tree: every sub-directory (relative paths,
 *  each listed AFTER its parent so a consumer can create them parent-first) and
 *  every file with its size. */
export interface TreeScan {
  dirs: string[];
  files: WalkItem[];
}

/** Recursively enumerate `root` on `src`, listing sibling sub-directories
 *  concurrently (bounded by `sem`) instead of one-round-trip-at-a-time. Cuts the
 *  scan "prologue" stall on wide/deep trees while still returning honest totals.
 *  Invariant: a directory always appears in `dirs` before any of its descendants
 *  (its parent pushes it before recursing), so `dirs` can be created parent-first.
 *  Names that could self-recurse or escape the tree ("."/".."/separators) are
 *  skipped, matching the old `walk`. */
export async function collectTree(
  src: FileSource,
  root: string,
  sem: Semaphore,
): Promise<TreeScan> {
  const dirs: string[] = [];
  const files: WalkItem[] = [];
  const visit = async (absDir: string, rel: string): Promise<void> => {
    const entries = await sem.run(() => src.list(absDir));
    entries.sort((a, b) => (a.isDir === b.isDir ? a.name.localeCompare(b.name) : a.isDir ? -1 : 1));
    const sub: Array<Promise<void>> = [];
    for (const e of entries) {
      if (!isSafeName(e.name)) continue;
      const childRel = rel ? `${rel}/${e.name}` : e.name;
      const childAbs = await src.join(absDir, e.name);
      if (e.isDir) {
        dirs.push(childRel);
        sub.push(visit(childAbs, childRel));
      } else {
        files.push({ relPath: childRel, isDir: false, size: e.size });
      }
    }
    await Promise.all(sub);
  };
  await visit(root, "");
  return { dirs, files };
}

/** Recursively enumerate `root` on `src`, yielding each directory BEFORE its
 *  contents so a consumer can mkdir the tree top-down. Relative paths use "/"
 *  regardless of source kind; the consumer rejoins against the target source. */
export async function* walk(src: FileSource, root: string, rel = ""): AsyncGenerator<WalkItem> {
  const entries = await src.list(root);
  entries.sort((a, b) => (a.isDir === b.isDir ? a.name.localeCompare(b.name) : a.isDir ? -1 : 1));
  for (const e of entries) {
    // Never recurse into "."/".." or a name with a separator — guards against a
    // server triggering infinite recursion or a path-traversal write.
    if (!isSafeName(e.name)) continue;
    const childRel = rel ? `${rel}/${e.name}` : e.name;
    const childAbs = await src.join(root, e.name);
    if (e.isDir) {
      yield { relPath: childRel, isDir: true, size: 0 };
      yield* walk(src, childAbs, childRel);
    } else {
      yield { relPath: childRel, isDir: false, size: e.size };
    }
  }
}
