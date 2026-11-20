import http from "node:http";
import https from "node:https";
import { URL } from "node:url";
import { SecurityPipeline } from "../core/scanner.js";
import { ShieldConfig } from "../types/index.js";

export class ProxyServer {
  private pipeline: SecurityPipeline;
  private config: ShieldConfig;
  private server: http.Server | null = null;

  constructor(config: Partial<ShieldConfig> = {}) {
    this.config = {
      port: 8080,
      upstreamUrl: "https://api.openai.com",
      blockSecrets: true,
      anonymizePii: true,
      blockInjections: true,
      strictMode: false,
      entropyThreshold: 3.8,
      logLevel: "info",
      ...config
    };
    this.pipeline = new SecurityPipeline(this.config);
  }

  public start(): Promise<void> {
    return new Promise((resolve, reject) => {
      this.server = http.createServer((req, res) => this.handleRequest(req, res));

      this.server.listen(this.config.port, () => {
        console.log(`🛡️  PromptShield active on http://localhost:${this.config.port}`);
        console.log(`↪ Upstream Target: ${this.config.upstreamUrl}`);
        resolve();
      });

      this.server.on("error", reject);
    });
  }

  public stop(): Promise<void> {
    return new Promise((resolve) => {
      if (this.server) {
        this.server.close(() => resolve());
      } else {
        resolve();
      }
    });
  }

  private handleRequest(clientReq: http.IncomingMessage, clientRes: http.ServerResponse): void {
    const upstreamParsed = new URL(this.config.upstreamUrl);
    const targetUrl = new URL(clientReq.url || "/", upstreamParsed);

    const isSecure = upstreamParsed.protocol === "https:";
    const requester = isSecure ? https.request : http.request;

    // Buffer incoming request body
    const bodyChunks: Buffer[] = [];
    clientReq.on("data", (chunk) => bodyChunks.push(chunk));

    clientReq.on("end", () => {
      let finalBody = Buffer.concat(bodyChunks);

      // Inspect chat completion and embedding endpoints
      const contentType = clientReq.headers["content-type"] || "";
      if (contentType.includes("application/json") && finalBody.length > 0) {
        try {
          const jsonPayload = JSON.parse(finalBody.toString("utf8"));
          const inspection = this.inspectAndSanitizePayload(jsonPayload);

          if (!inspection.isSafe) {
            clientRes.writeHead(400, { "Content-Type": "application/json" });
            clientRes.end(JSON.stringify({
              error: {
                message: "Blocked by PromptShield: security policy violation detected in prompt.",
                type: "security_violation",
                violations: inspection.violations
              }
            }));
            return;
          }

          // Replace body with sanitized payload
          finalBody = Buffer.from(JSON.stringify(inspection.sanitizedPayload), "utf8");
        } catch {
          // If JSON parse fails, forward original body
        }
      }

      // Clone headers and update host & content-length
      const headers = { ...clientReq.headers };
      headers["host"] = upstreamParsed.host;
      headers["content-length"] = Buffer.byteLength(finalBody).toString();

      const upstreamReq = requester(targetUrl, {
        method: clientReq.method,
        headers
      }, (upstreamRes) => {
        clientRes.writeHead(upstreamRes.statusCode || 500, upstreamRes.headers);
        upstreamRes.pipe(clientRes);
      });

      upstreamReq.on("error", (err) => {
        clientRes.writeHead(502, { "Content-Type": "application/json" });
        clientRes.end(JSON.stringify({ error: { message: "PromptShield: upstream connection failed", details: err.message } }));
      });

      upstreamReq.write(finalBody);
      upstreamReq.end();
    });
  }

  private inspectAndSanitizePayload(payload: any): { isSafe: boolean; sanitizedPayload: any; violations: any[] } {
    const violations: any[] = [];
    let isSafe = true;

    // Handle standard chat completions format: { messages: [{ role, content }] }
    if (Array.isArray(payload.messages)) {
      for (const msg of payload.messages) {
        if (typeof msg.content === "string") {
          const report = this.pipeline.analyze(msg.content);
          if (!report.isSafe) {
            isSafe = false;
            if (report.secrets.length > 0) violations.push(...report.secrets);
            if (report.injections.length > 0) violations.push(...report.injections);
          }
          msg.content = report.sanitizedText;
        }
      }
    } else if (typeof payload.prompt === "string") {
      const report = this.pipeline.analyze(payload.prompt);
      if (!report.isSafe) {
        isSafe = false;
        if (report.secrets.length > 0) violations.push(...report.secrets);
        if (report.injections.length > 0) violations.push(...report.injections);
      }
      payload.prompt = report.sanitizedText;
    }

    return { isSafe, sanitizedPayload: payload, violations };
  }
}
