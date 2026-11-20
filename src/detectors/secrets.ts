import { calculateShannonEntropy } from "./entropy.js";
import { DetectedSecret, ThreatSeverity } from "../types/index.js";

interface SecretRule {
  type: string;
  pattern: RegExp;
  minEntropy: number;
  severity: ThreatSeverity;
}

export const SECRET_RULES: SecretRule[] = [
  {
    type: "AWS_ACCESS_KEY",
    pattern: /\b(AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}\b/g,
    minEntropy: 3.0,
    severity: "CRITICAL"
  },
  {
    type: "OPENAI_API_KEY",
    pattern: /\bsk-(?:proj-|live-)?[a-zA-Z0-9_-]{32,}\b/g,
    minEntropy: 3.5,
    severity: "CRITICAL"
  },
  {
    type: "ANTHROPIC_API_KEY",
    pattern: /\bsk-ant-[a-zA-Z0-9_-]{32,}\b/g,
    minEntropy: 3.5,
    severity: "CRITICAL"
  },
  {
    type: "GITHUB_PAT",
    pattern: /\b(?:ghp|gho|ghu|ghs|ghr)_[a-zA-Z0-9]{36}\b|\bgithub_pat_[a-zA-Z0-9_]{82}\b/g,
    minEntropy: 3.5,
    severity: "CRITICAL"
  },
  {
    type: "GOOGLE_API_KEY",
    pattern: /\bAIza[0-9A-Za-z\-_]{35}\b/g,
    minEntropy: 3.2,
    severity: "CRITICAL"
  },
  {
    type: "SLACK_TOKEN",
    pattern: /\bxox[baprs]-[0-9a-zA-Z]{10,48}\b/g,
    minEntropy: 3.0,
    severity: "HIGH"
  },
  {
    type: "RSA_PRIVATE_KEY",
    pattern: /-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/g,
    minEntropy: 4.0,
    severity: "CRITICAL"
  },
  {
    type: "GENERIC_JWT",
    pattern: /\beyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\b/g,
    minEntropy: 4.0,
    severity: "HIGH"
  }
];

export function scanSecrets(text: string, globalEntropyThreshold = 3.8): DetectedSecret[] {
  const detected: DetectedSecret[] = [];

  for (const rule of SECRET_RULES) {
    const matches = text.matchAll(rule.pattern);
    for (const match of matches) {
      const matchText = match[0];
      const entropy = calculateShannonEntropy(matchText);

      // Verify rule entropy threshold to prevent false positives on common words
      if (entropy >= rule.minEntropy) {
        detected.push({
          type: rule.type,
          match: matchText,
          entropy,
          start: match.index ?? 0,
          end: (match.index ?? 0) + matchText.length,
          severity: rule.severity
        });
      }
    }
  }

  // Generic High Entropy Token Detection for suspicious assignments (e.g. api_key="...")
  const assignmentPattern = /(?:api[_-]?key|secret|token|password|auth)\s*[:=]\s*["']?([a-zA-Z0-9_\-]{24,})["']?/gi;
  const assignmentMatches = text.matchAll(assignmentPattern);
  for (const m of assignmentMatches) {
    const candidate = m[1];
    const entropy = calculateShannonEntropy(candidate);
    if (entropy >= globalEntropyThreshold) {
      const alreadyCaptured = detected.some(d => d.match.includes(candidate));
      if (!alreadyCaptured) {
        detected.push({
          type: "HIGH_ENTROPY_TOKEN",
          match: candidate,
          entropy,
          start: (m.index ?? 0) + m[0].indexOf(candidate),
          end: (m.index ?? 0) + m[0].indexOf(candidate) + candidate.length,
          severity: "HIGH"
        });
      }
    }
  }

  return detected;
}
