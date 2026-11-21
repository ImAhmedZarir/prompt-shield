import { scanSecrets } from "../detectors/secrets.js";
import { scanInjections } from "../detectors/injection.js";
import { AnonymizerVault } from "../anonymizer/vault.js";
import { SecurityReport, ShieldConfig } from "../types/index.js";

export class SecurityPipeline {
  private config: ShieldConfig;
  private vault: AnonymizerVault;

  constructor(config: Partial<ShieldConfig> = {}) {
    this.config = {
      port: 8080,
      upstreamUrl: "https://api.openai.com",
      blockSecrets: true,
      anonymizePii: true,
      blockInjections: true,
      strictMode: false,
      entropyThreshold: 3.8,
      maxBodySize: 10 * 1024 * 1024, // 10MB default
      logLevel: "info",
      ...config
    };
    this.vault = new AnonymizerVault();
  }

  /**
   * Scans an input string through all configured security and privacy filters.
   */
  public analyze(input: string): SecurityReport {
    const startTime = performance.now();

    // 1. Scan for hardcoded credentials & API keys
    const secrets = this.config.blockSecrets ? scanSecrets(input, this.config.entropyThreshold) : [];

    // 2. Scan for prompt injection / jailbreak patterns
    const injections = this.config.blockInjections ? scanInjections(input) : [];

    // 3. Anonymize PII
    let sanitizedText = input;
    let piiList: any[] = [];
    if (this.config.anonymizePii) {
      const piiResult = this.vault.sanitize(input);
      sanitizedText = piiResult.sanitizedText;
      piiList = piiResult.detectedPii;
    }

    const hasCriticalThreat = secrets.length > 0 || injections.length > 0;
    const isSafe = !hasCriticalThreat && (!this.config.strictMode || piiList.length === 0);

    const scanDurationMs = Number((performance.now() - startTime).toFixed(2));

    return {
      isSafe,
      sanitizedText,
      secrets,
      pii: piiList,
      injections,
      scanDurationMs
    };
  }

  public getVault(): AnonymizerVault {
    return this.vault;
  }
}
