import type { AcsConfig } from "./config.js";

export const PROTECTED_TOOL = "acs_protected_append" as const;

async function readBounded(response: Response, maximumBytes: number): Promise<string> {
  if (!response.body) return "";
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > maximumBytes) {
        await reader.cancel();
        throw new Error("protected resource response exceeds configured limit");
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  return Buffer.concat(chunks.map((chunk) => Buffer.from(chunk))).toString("utf8");
}

export async function appendProtectedValue(
  config: NonNullable<AcsConfig["protectedResource"]>,
  capability: string,
  value: string,
  parentSignal?: AbortSignal,
): Promise<string> {
  const controller = new AbortController();
  const abort = () => controller.abort(parentSignal?.reason);
  parentSignal?.addEventListener("abort", abort, { once: true });
  const timer = setTimeout(() => controller.abort(), config.timeoutMs);
  try {
    const response = await fetch(config.url, {
      method: "POST",
      headers: { "content-type": "application/json", accept: "application/json" },
      body: JSON.stringify({ capability, value }),
      redirect: "error",
      signal: controller.signal,
    });
    const text = await readBounded(response, config.maxResponseBytes);
    if (!response.ok) throw new Error(`protected resource returned HTTP ${response.status}`);
    const result = JSON.parse(text) as unknown;
    if (typeof result !== "object" || result === null || Array.isArray(result)
      || (result as Record<string, unknown>).status !== "appended"
      || typeof (result as Record<string, unknown>).event_id !== "string") {
      throw new Error("protected resource returned an invalid response");
    }
    return `Protected append accepted: ${(result as Record<string, unknown>).event_id}`;
  } catch (error) {
    if (controller.signal.aborted) throw new Error("protected resource request timed out or was cancelled", { cause: error });
    throw error;
  } finally {
    clearTimeout(timer);
    parentSignal?.removeEventListener("abort", abort);
  }
}
