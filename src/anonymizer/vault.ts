import { randomBytes } from "node:crypto";
import { DetectedPII } from "../types/index.js";
import { scanPII } from "../detectors/pii.js";

const MAX_VAULT_ENTRIES = 5000;

export class AnonymizerVault {
  private vaultMap = new Map<string, string>(); // Token -> Raw
  private reverseMap = new Map<string, string>(); // Raw -> Token
  private counters: Record<string, number> = {};

  /**
   * Generates a unique, collision-resistant token with a cryptographic entropy suffix.
   */
  private generateToken(type: string, raw: string): string {
    if (this.reverseMap.has(raw)) {
      return this.reverseMap.get(raw)!;
    }

    // Prevent unbounded memory growth via LRU-style oldest eviction
    if (this.vaultMap.size >= MAX_VAULT_ENTRIES) {
      const oldestKey = this.vaultMap.keys().next().value;
      if (oldestKey) {
        const rawVal = this.vaultMap.get(oldestKey);
        this.vaultMap.delete(oldestKey);
        if (rawVal) this.reverseMap.delete(rawVal);
      }
    }

    this.counters[type] = (this.counters[type] || 0) + 1;
    const entropySuffix = randomBytes(3).toString("hex");
    const token = `[REDACTED_${type}_${this.counters[type]}_${entropySuffix}]`;

    this.vaultMap.set(token, raw);
    this.reverseMap.set(raw, token);
    return token;
  }

  /**
   * Sanitizes text by substituting all detected PII entities with safe tokens.
   * Resolves any overlapping spans cleanly to prevent corrupted string slices.
   */
  public sanitize(text: string): { sanitizedText: string; detectedPii: DetectedPII[] } {
    const piiItems = scanPII(text);
    if (piiItems.length === 0) {
      return { sanitizedText: text, detectedPii: [] };
    }

    // 1. Filter out overlapping intervals (prefer earlier or longer matches)
    const sortedAsc = [...piiItems].sort((a, b) => a.start - b.start || (b.end - b.start) - (a.end - a.start));
    const nonOverlapping: DetectedPII[] = [];
    let lastEnd = -1;

    for (const item of sortedAsc) {
      if (item.start >= lastEnd) {
        nonOverlapping.push(item);
        lastEnd = item.end;
      }
    }

    // 2. Sort descending by start index so replacements do not alter preceding coordinates
    const sortedDesc = [...nonOverlapping].sort((a, b) => b.start - a.start);

    let result = text;
    for (const item of sortedDesc) {
      const token = this.generateToken(item.type, item.raw);
      item.token = token;
      result = result.slice(0, item.start) + token + result.slice(item.end);
    }

    return { sanitizedText: result, detectedPii: nonOverlapping };
  }

  /**
   * Rehydrates an LLM response by substituting redaction tokens back with their original values.
   */
  public rehydrate(response: string): string {
    let rehydrated = response;
    for (const [token, raw] of this.vaultMap.entries()) {
      rehydrated = rehydrated.replaceAll(token, raw);
    }
    return rehydrated;
  }

  /**
   * Clears the current session token mappings.
   */
  public reset(): void {
    this.vaultMap.clear();
    this.reverseMap.clear();
    this.counters = {};
  }
}
