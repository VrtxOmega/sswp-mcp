// src/sswp/core/kimi-reasoner.ts
/** Calls Gravity Omega/Ollama Cloud (kimi-k2.5) for adversarial supply-chain reasoning */

import type { DependencyEntry, ProbeResult } from "./types.js";

const OLLAMA_CLOUD_ENDPOINT = "https://api.ollama.com/v1/chat/completions";
const KIMI_MODEL = "kimi-k2.5";
const TIMEOUT_MS = 10_000;

function buildPrompt(deps: DependencyEntry[]): string {
  const depList = deps
    .map((d, i) => {
      const integrityStr = d.integrity
        ? `Integrity: ${d.integrity}`
        : "Integrity: MISSING";
      return `${i + 1}. ${d.name}@${d.version} (${integrityStr}, Resolved: ${d.resolved})`;
    })
    .join("\n");

  return `You are a supply-chain security analyst. Analyze the following software dependencies for security and supply-chain risks.
Consider typosquatting, version pinning, missing integrity hashes, suspicious package names, and known attack patterns.
Return ONLY a single JSON object with no markdown formatting, no code fences, and no extra text.

Input dependencies:
${depList}

Required JSON schema:
{
  "risk": "LOW" | "MEDIUM" | "HIGH" | "CRITICAL",
  "packages": [
    {
      "name": "package-name",
      "risk": "LOW" | "MEDIUM" | "HIGH" | "CRITICAL",
      "reason": "specific reasoning for this package"
    }
  ],
  "summary": "concise overall assessment"
}`;
}

export async function kimiAnalyze(
  deps: DependencyEntry[]
): Promise<ProbeResult[]> {
  const apiKey =
    process.env.OLLAMA_CLOUD_API_KEY || process.env.OLLAMA_API_KEY;
  if (!apiKey) {
    return [
      {
        package: "system",
        probe: "KIMI_REASONING",
        result: "INCONCLUSIVE",
        detail:
          "OLLAMA_CLOUD_API_KEY is not set. Skipping Kimi adversarial analysis.",
      },
    ];
  }

  const prompt = buildPrompt(deps);
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), TIMEOUT_MS);

  try {
    const response = await fetch(OLLAMA_CLOUD_ENDPOINT, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${apiKey}`,
      },
      body: JSON.stringify({
        model: KIMI_MODEL,
        messages: [
          {
            role: "system",
            content:
              "You are a deterministic supply-chain security evaluator. Output must be valid JSON only.",
          },
          { role: "user", content: prompt },
        ],
        temperature: 0.2,
        max_tokens: 2048,
      }),
      signal: controller.signal,
    });

    clearTimeout(timeoutId);

    if (!response.ok) {
      return [
        {
          package: "system",
          probe: "KIMI_REASONING",
          result: "INCONCLUSIVE",
          detail: `Ollama Cloud API returned HTTP ${response.status}: ${response.statusText}`,
        },
      ];
    }

    const data = (await response.json()) as any;
    const content = data?.choices?.[0]?.message?.content;
    if (!content || typeof content !== "string") {
      return [
        {
          package: "system",
          probe: "KIMI_REASONING",
          result: "INCONCLUSIVE",
          detail: "Unexpected response shape from Ollama Cloud API.",
        },
      ];
    }

    // Strip markdown fences if present
    const cleaned = content
      .replace(/```json\s*/g, "")
      .replace(/```\s*/g, "")
      .trim();

    let parsed: {
      risk?: string;
      packages?: Array<{
        name?: string;
        risk?: string;
        reason?: string;
      }>;
      summary?: string;
    };

    try {
      parsed = JSON.parse(cleaned);
    } catch (parseErr) {
      return [
        {
          package: "system",
          probe: "KIMI_REASONING",
          result: "INCONCLUSIVE",
          detail: `Failed to parse Kimi JSON response: ${(
            parseErr as Error
          ).message}`,
        },
      ];
    }

    const parsedPackages = parsed.packages || [];
    const results: ProbeResult[] = parsedPackages.map((pkg) => {
      const risk = (pkg.risk || "INCONCLUSIVE").toString().toUpperCase();
      const result: ProbeResult["result"] =
        risk === "CRITICAL"
          ? "CRITICAL"
          : risk === "HIGH"
          ? "WARN"
          : risk === "MEDIUM"
          ? "WARN"
          : risk === "LOW"
          ? "PASS"
          : "INCONCLUSIVE";

      return {
        package: pkg.name || "unknown",
        probe: "KIMI_REASONING",
        result,
        detail: pkg.reason || parsed.summary || "No detail provided",
      };
    });

    if (results.length === 0) {
      return [
        {
          package: "system",
          probe: "KIMI_REASONING",
          result: "INCONCLUSIVE",
          detail: parsed.summary || "Kimi returned empty package list.",
        },
      ];
    }

    return results;
  } catch (err: any) {
    clearTimeout(timeoutId);
    if (err.name === "AbortError") {
      return [
        {
          package: "system",
          probe: "KIMI_REASONING",
          result: "INCONCLUSIVE",
          detail: "Kimi adversarial probe timed out after 10s.",
        },
      ];
    }
    return [
      {
        package: "system",
        probe: "KIMI_REASONING",
        result: "INCONCLUSIVE",
        detail: `Kimi adversarial probe failed: ${err.message}`,
      },
    ];
  }
}
