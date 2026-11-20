import { DetectedPII } from "../types/index.js";

/**
 * Validates a credit card number using the standard Luhn checksum algorithm (Mod 10).
 */
export function validateLuhn(ccNumber: string): boolean {
  const digits = ccNumber.replace(/\D/g, "");
  if (digits.length < 13 || digits.length > 19) return false;

  let sum = 0;
  let shouldDouble = false;

  for (let i = digits.length - 1; i >= 0; i--) {
    let digit = parseInt(digits.charAt(i), 10);

    if (shouldDouble) {
      digit *= 2;
      if (digit > 9) digit -= 9;
    }

    sum += digit;
    shouldDouble = !shouldDouble;
  }

  return sum % 10 === 0;
}

export function scanPII(text: string): DetectedPII[] {
  const piiList: DetectedPII[] = [];

  // 1. Emails
  const emailRegex = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b/g;
  for (const m of text.matchAll(emailRegex)) {
    piiList.push({
      type: "EMAIL",
      raw: m[0],
      token: "",
      start: m.index ?? 0,
      end: (m.index ?? 0) + m[0].length
    });
  }

  // 2. Phone Numbers (international and formatted)
  const phoneRegex = /(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b/g;
  for (const m of text.matchAll(phoneRegex)) {
    if (m[0].replace(/\D/g, "").length >= 10) {
      piiList.push({
        type: "PHONE",
        raw: m[0],
        token: "",
        start: m.index ?? 0,
        end: (m.index ?? 0) + m[0].length
      });
    }
  }

  // 3. IPv4 Addresses
  const ipv4Regex = /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g;
  for (const m of text.matchAll(ipv4Regex)) {
    piiList.push({
      type: "IPV4",
      raw: m[0],
      token: "",
      start: m.index ?? 0,
      end: (m.index ?? 0) + m[0].length
    });
  }

  // 4. Credit Cards with Linear ReDoS-Safe Regex + Luhn Validation
  const ccRegex = /\b\d[\d -]{11,22}\d\b/g;
  for (const m of text.matchAll(ccRegex)) {
    const rawDigits = m[0].replace(/[\s-]/g, "");
    if (rawDigits.length >= 13 && rawDigits.length <= 19 && validateLuhn(rawDigits)) {
      piiList.push({
        type: "CREDIT_CARD",
        raw: m[0],
        token: "",
        start: m.index ?? 0,
        end: (m.index ?? 0) + m[0].length
      });
    }
  }

  // 5. US SSN format
  const ssnRegex = /\b\d{3}-\d{2}-\d{4}\b/g;
  for (const m of text.matchAll(ssnRegex)) {
    piiList.push({
      type: "SSN",
      raw: m[0],
      token: "",
      start: m.index ?? 0,
      end: (m.index ?? 0) + m[0].length
    });
  }

  return piiList;
}
