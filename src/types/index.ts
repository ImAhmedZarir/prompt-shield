export type ThreatSeverity = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";

export interface DetectedSecret {
  type: string;
  match: string;
  entropy: number;
  start: number;
  end: number;
  severity: ThreatSeverity;
}

export interface DetectedPII {
  type: "EMAIL" | "PHONE" | "CREDIT_CARD" | "IPV4" | "IPV6" | "SSN";
  raw: string;
  token: string;
  start: number;
  end: number;
}

export interface DetectedInjection {
  pattern: string;
  category: "OVERRIDE" | "DELIMITER_ESCAPE" | "ROLE_HIJACK" | "SYSTEM_LEAK";
  confidence: number;
}

export interface SecurityReport {
  isSafe: boolean;
  sanitizedText: string;
  secrets: DetectedSecret[];
  pii: DetectedPII[];
  injections: DetectedInjection[];
  scanDurationMs: number;
}

export interface ShieldConfig {
  port: number;
  upstreamUrl: string;
  blockSecrets: boolean;
  anonymizePii: boolean;
  blockInjections: boolean;
  strictMode: boolean;
  entropyThreshold: number;
  logLevel: "debug" | "info" | "warn" | "error";
}
