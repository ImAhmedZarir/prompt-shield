import http from "node:http";
import https from "node:https";
import { URL } from "node:url";
import zlib from "node:zlib";
import { SecurityPipeline } from "../core/scanner.js";
import { ShieldConfig } from "../types/index.js";

const CORS_HEADERS: Record<string, string> = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Requested-With, OpenAI-Beta, Anthropic-Version"
};

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
      maxBodySize: 10 * 1024 * 1024, // 10MB max body limit
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
    // 1. Handle CORS Preflight (OPTIONS)
    if (clientReq.method === "OPTIONS") {
      clientRes.writeHead(204, CORS_HEADERS);
      clientRes.end();
      return;
    }

    const upstreamParsed = new URL(this.config.upstreamUrl);
    
    // Support base paths and query parameters correctly
    const basePath = upstreamParsed.pathname.replace(/\/+$/, "");
    const clientPath = (clientReq.url || "/").replace(/^\/+/, "");
    const combinedPath = basePath ? `${basePath}/${clientPath}` : `/${clientPath}`;
    const targetUrl = new URL(combinedPath, upstreamParsed.origin);

    const isSecure = upstreamParsed.protocol === "https:";
    const requester = isSecure ? https.request : http.request;

    // 2. Buffer incoming request body with strict size boundary to prevent DoS memory exhaustion
    const bodyChunks: Buffer[] = [];
    let receivedBytes = 0;
    let isPayloadTooLarge = false;

    clientReq.on("data", (chunk: Buffer) => {
      receivedBytes += chunk.length;
      if (receivedBytes > this.config.maxBodySize) {
        isPayloadTooLarge = true;
        clientReq.destroy();
        if (!clientRes.headersSent) {
          clientRes.writeHead(413, {
            "Content-Type": "application/json",
            ...CORS_HEADERS
          });
          clientRes.end(JSON.stringify({
            error: {
              message: `Payload Too Large: Request body exceeds maximum allowed size of ${this.config.maxBodySize} bytes.`,
              type: "payload_too_large"
            }
          }));
        }
        return;
      }
      bodyChunks.push(chunk);
    });

    clientReq.on("end", () => {
      if (isPayloadTooLarge) return;

      let finalBody = Buffer.concat(bodyChunks);

      // Handle request decompression if client sent gzip/deflate
      const contentEncoding = (clientReq.headers["content-encoding"] || "").toLowerCase();
      let decompressedBody = finalBody;
      let wasCompressed = false;

      if (finalBody.length > 0) {
        try {
          if (contentEncoding === "gzip") {
            decompressedBody = zlib.gunzipSync(finalBody);
            wasCompressed = true;
          } else if (contentEncoding === "deflate") {
            decompressedBody = zlib.inflateSync(finalBody);
            wasCompressed = true;
          }
        } catch (err: any) {
          clientRes.writeHead(400, { "Content-Type": "application/json", ...CORS_HEADERS });
          clientRes.end(JSON.stringify({ error: { message: "Invalid compressed body", details: err.message } }));
          return;
        }
      }

      // Inspect chat completion and embedding endpoints
      const contentType = clientReq.headers["content-type"] || "";
      if (contentType.includes("application/json") && decompressedBody.length > 0) {
        try {
          const jsonPayload = JSON.parse(decompressedBody.toString("utf8"));
          const inspection = this.inspectAndSanitizePayload(jsonPayload);

          if (!inspection.isSafe) {
            clientRes.writeHead(400, {
              "Content-Type": "application/json",
              ...CORS_HEADERS
            });
            clientRes.end(JSON.stringify({
              error: {
                message: "Blocked by PromptShield: security policy violation detected in prompt.",
                type: "security_violation",
                violations: inspection.violations
              }
            }));
            return;
          }

          // Replace body with sanitized payload (re-compressing if original was compressed)
          const sanitizedJsonBuf = Buffer.from(JSON.stringify(inspection.sanitizedPayload), "utf8");
          if (wasCompressed && contentEncoding === "gzip") {
            finalBody = zlib.gzipSync(sanitizedJsonBuf);
          } else if (wasCompressed && contentEncoding === "deflate") {
            finalBody = zlib.deflateSync(sanitizedJsonBuf);
          } else {
            finalBody = sanitizedJsonBuf;
          }
        } catch {
          // If JSON parse fails, forward original body safely
        }
      }

      // Clone headers and update host & content-length (RFC 7230: strip transfer-encoding when content-length is set)
      const headers = { ...clientReq.headers };
      headers["host"] = upstreamParsed.host;
      delete headers["transfer-encoding"];
      headers["content-length"] = Buffer.byteLength(finalBody).toString();

      const upstreamReq = requester(targetUrl, {
        method: clientReq.method,
        headers
      }, (upstreamRes) => {
        const responseHeaders = {
          ...upstreamRes.headers,
          ...CORS_HEADERS
        };
        clientRes.writeHead(upstreamRes.statusCode || 500, responseHeaders);
        upstreamRes.pipe(clientRes);
      });

      // 3. Client Abort / Socket Disconnect Handler: cancel upstream immediately to prevent token waste
      clientRes.on("close", () => {
        if (!clientRes.writableFinished) {
          upstreamReq.destroy();
        }
      });

      upstreamReq.on("error", (err) => {
        if (!clientRes.headersSent) {
          clientRes.writeHead(502, {
            "Content-Type": "application/json",
            ...CORS_HEADERS
          });
          clientRes.end(JSON.stringify({
            error: {
              message: "PromptShield: upstream connection failed",
              details: err.message
            }
          }));
        }
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
        // Handle standard string content
        if (typeof msg.content === "string") {
          const report = this.pipeline.analyze(msg.content);
          if (!report.isSafe) {
            isSafe = false;
            if (report.secrets.length > 0) violations.push(...report.secrets);
            if (report.injections.length > 0) violations.push(...report.injections);
          }
          msg.content = report.sanitizedText;
        } 
        // Handle multimodal array content format: [{ type: "text", text: "..." }]
        else if (Array.isArray(msg.content)) {
          for (const part of msg.content) {
            if (part && typeof part === "object" && part.type === "text" && typeof part.text === "string") {
              const report = this.pipeline.analyze(part.text);
              if (!report.isSafe) {
                isSafe = false;
                if (report.secrets.length > 0) violations.push(...report.secrets);
                if (report.injections.length > 0) violations.push(...report.injections);
              }
              part.text = report.sanitizedText;
            }
          }
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
