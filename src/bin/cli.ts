#!/usr/bin/env node

import fs from "node:fs";
import path from "node:path";
import { ProxyServer } from "../server/proxy.js";
import { ShieldConfig } from "../types/index.js";

function loadConfigFile(): Partial<ShieldConfig> {
  const configPath = path.resolve(process.cwd(), "prompt-shield.config.json");
  if (fs.existsSync(configPath)) {
    try {
      const content = fs.readFileSync(configPath, "utf8");
      return JSON.parse(content);
    } catch (err: any) {
      console.warn(`⚠️ Warning: Failed to parse prompt-shield.config.json: ${err.message}`);
    }
  }
  return {};
}

function parseArgs(): Partial<ShieldConfig> {
  const args = process.argv.slice(2);
  const config: Partial<ShieldConfig> = {};

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg === "--port" || arg === "-p") {
      config.port = parseInt(args[++i], 10);
    } else if (arg === "--upstream" || arg === "-u") {
      config.upstreamUrl = args[++i];
    } else if (arg === "--strict") {
      config.strictMode = true;
    } else if (arg === "--no-pii") {
      config.anonymizePii = false;
    } else if (arg === "--no-secrets") {
      config.blockSecrets = false;
    } else if (arg === "--no-injections") {
      config.blockInjections = false;
    } else if (arg === "--max-body-size") {
      config.maxBodySize = parseInt(args[++i], 10);
    } else if (arg === "--help" || arg === "-h") {
      printHelp();
      process.exit(0);
    }
  }

  return config;
}

function printHelp(): void {
  console.log(`
🛡️  PromptShield CLI - Zero-Trust AI Security Gateway

Usage:
  npx prompt-shield [options]

Options:
  -p, --port <number>       Local port to listen on (default: 8080)
  -u, --upstream <url>      Upstream target LLM URL (default: https://api.openai.com)
  --strict                  Enable strict mode (reject requests on any PII)
  --no-pii                  Disable PII redaction
  --no-secrets              Disable secret leak detection
  --no-injections           Disable prompt injection guard
  --max-body-size <bytes>   Max request payload size in bytes (default: 10485760)
  -h, --help                Display this help screen
`);
}

async function main() {
  const fileConfig = loadConfigFile();
  const cliConfig = parseArgs();

  const mergedConfig: Partial<ShieldConfig> = {
    ...fileConfig,
    ...cliConfig
  };

  const port = mergedConfig.port || parseInt(process.env.PORT || "8080", 10);
  const upstreamUrl = mergedConfig.upstreamUrl || process.env.UPSTREAM_URL || "https://api.openai.com";

  console.log(`\x1b[36m
  ╔════════════════════════════════════════════════════════╗
  ║                PROMPT-SHIELD GATEWAY                   ║
  ║     Zero-Trust Security & Privacy for LLM APIs        ║
  ╚════════════════════════════════════════════════════════╝
  \x1b[0m`);

  const server = new ProxyServer({
    ...mergedConfig,
    port,
    upstreamUrl
  });

  await server.start();

  const shutdown = async () => {
    console.log("\n🛑 Stopping PromptShield Gateway...");
    await server.stop();
    process.exit(0);
  };

  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);
}

main().catch((err) => {
  console.error("Fatal error starting PromptShield:", err);
  process.exit(1);
});
