// guard — behavior-preserving wrapper for the ubiquitous mutating-action pattern
//   try { await something(...); toast(t("…ok"), "ok"); }
//   catch (e) { toast(apiErrorMessage(e), "err"); }
// Runs `fn`, routing any thrown error to a toast (default: the standard
// `toast(apiErrorMessage(e), "err")`). Returns true on success, false if `fn`
// threw — letting callers gate follow-up work without re-catching.

import { toast } from "@/store/toast";
import { apiErrorMessage } from "@/bridge/types";

export async function guard(
  fn: () => Promise<void>,
  opts?: { onErr?: (e: unknown) => void },
): Promise<boolean> {
  try {
    await fn();
    return true;
  } catch (e) {
    (opts?.onErr ?? ((err) => toast(apiErrorMessage(err), "err")))(e);
    return false;
  }
}
