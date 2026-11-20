import { DetectedInjection } from "../types/index.js";

interface InjectionRule {
  category: "OVERRIDE" | "DELIMITER_ESCAPE" | "ROLE_HIJACK" | "SYSTEM_LEAK";
  pattern: RegExp;
  weight: number;
}

export const INJECTION_RULES: InjectionRule[] = [
  // 1. Direct System Prompt Overrides
  {
    category: "OVERRIDE",
    pattern: /\b(?:ignore|disregard|forget|override)\s+(?:all\s+)?(?:previous|prior|above|existing)\s+(?:instructions|prompts|rules|commands|constraints)\b/i,
    weight: 0.95
  },
  {
    category: "OVERRIDE",
    pattern: /\bfrom\s+now\s+on\s*,?\s*you\s+(?:must|should|will)\s+(?:act|behave|respond)\s+as\b/i,
    weight: 0.8
  },

  // 2. Delimiter & Chat Format Escapes
  {
    category: "DELIMITER_ESCAPE",
    pattern: /<\/?(?:system|instruction|im_start|im_end|INST|SYS)>/i,
    weight: 0.95
  },
  {
    category: "DELIMITER_ESCAPE",
    pattern: /(?:```|""")\s*(?:system|override|admin)\b/i,
    weight: 0.85
  },

  // 3. Jailbreak Personas & Role Hijacking
  {
    category: "ROLE_HIJACK",
    pattern: /\b(?:DAN\s+mode|Developer\s+Mode|Do\s+Anything\s+Now|Jailbreak\s+enabled|unrestricted\s+mode)\b/i,
    weight: 0.95
  },
  {
    category: "ROLE_HIJACK",
    pattern: /\byou\s+have\s+been\s+freed\s+from\s+all\s+(?:rules|filters|limitations|safety)\b/i,
    weight: 0.9
  },

  // 4. System Prompt Extraction Attempts
  {
    category: "SYSTEM_LEAK",
    pattern: /\b(?:reveal|print|display|dump|output|repeat)\s+(?:your\s+)?(?:initial|hidden|system|confidential)\s+(?:prompt|instructions|rules)\b/i,
    weight: 0.9
  },
  {
    category: "SYSTEM_LEAK",
    pattern: /\bwhat\s+(?:were|are)\s+the\s+(?:exact\s+)?words\s+(?:above|at\s+the\s+beginning|in\s+your\s+system\s+message)\b/i,
    weight: 0.85
  }
];

export function scanInjections(text: string, confidenceThreshold = 0.8): DetectedInjection[] {
  const detections: DetectedInjection[] = [];

  for (const rule of INJECTION_RULES) {
    if (rule.pattern.test(text)) {
      if (rule.weight >= confidenceThreshold) {
        detections.push({
          pattern: rule.pattern.source,
          category: rule.category,
          confidence: rule.weight
        });
      }
    }
  }

  return detections;
}
