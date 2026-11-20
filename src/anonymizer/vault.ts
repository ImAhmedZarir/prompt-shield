import { DetectedPII } from "../types/index.js";
import { scanPII } from "../detectors/pii.js";

export class AnonymizerVault {
  private vaultMap = new Map<string, string>(); // Token -> Raw
  private reverseMap = new Map<string, string>(); // Raw -> Token
  private counters: Record<string, number> = {};

  /**
   * Generates a deterministic redaction token for a given type.
   */
  private generateToken(type: string, raw: string): string {
    if (this.reverseMap.has(raw)) {
      return this.reverseMap.get(raw)!;
    }

    this.counters[type] = (this.counters[type] || 0) + 1;
    const token = `[REDACTED_${type}_${this.counters[type]}]`;

    this.vaultMap.set(token, raw);
    this.reverseMap.set(raw, token);
    return token;
  }

  /**
   * Sanitizes text by substituting all detected PII entities with safe tokens.
   */
  public sanitize(text: string): { sanitizedText: string; detectedPii: DetectedPII[] } {
    const piiItems = scanPII(text);
    if (piiItems.length === 0) {
      return { sanitizedText: text, detectedPii: [] };
    }

    // Sort descending by starting index so replacements do not offset earlier coordinates
    const sorted = [...piiItems].sort((a, b) => b.start - a.start);

    let result = text;
    for (const item of sorted) {
      const token = this.generateToken(item.type, item.raw);
      item.token = token;
      result = result.slice(0, item.start) + token + result.slice(item.end);
    }

    return { sanitizedText: result, detectedPii: piiItems };
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
