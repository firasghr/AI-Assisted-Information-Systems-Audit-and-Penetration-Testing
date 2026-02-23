/**
 * ai_analyzer.js - AI-powered vulnerability analysis module.
 *
 * How AI improves traditional audit workflows:
 *   Traditional penetration testing relies on the analyst manually reviewing
 *   each finding, cross-referencing CVE databases, CVSS scores and threat
 *   intelligence feeds to determine which vulnerabilities to fix first.
 *   This process is:
 *   1. Time-consuming (hours to days for a large finding set)
 *   2. Inconsistent (varies with analyst experience and fatigue)
 *   3. Context-blind (ignores business context and asset criticality)
 *
 *   By sending normalised findings to a large language model (LLM), we can:
 *   - Obtain prioritised recommendations in seconds rather than hours
 *   - Incorporate business-context reasoning into risk scoring
 *   - Detect potential false positives based on configuration context
 *   - Generate plain-English remediation guidance
 *   This dramatically reduces Time-To-Prioritise (TTP) and improves the
 *   signal-to-noise ratio for security teams.
 *
 * Limitations and risks of AI in cybersecurity:
 *   1. Hallucinations: LLMs may generate plausible-but-incorrect technical
 *      details. All AI output must be reviewed by a human analyst.
 *   2. Training data cutoff: The model may not know about vulnerabilities
 *      disclosed after its training cutoff.
 *   3. Context window limits: Very large finding sets must be chunked.
 *   4. Prompt injection: If attacker-controlled data reaches the prompt,
 *      the model's output could be manipulated. Sanitise all inputs.
 *   5. Confidentiality: Sending scan data to a third-party API raises data
 *      sovereignty concerns. Use on-premises LLMs for classified systems.
 *
 * Output:
 *   Per-vulnerability AI enrichment is merged back into the normalised data
 *   and saved to data/processed/ai_analysis_<timestamp>.json.
 */

"use strict";

const fs = require("fs");
const path = require("path");
const OpenAI = require("openai");

const logger = require("../utils/logger");
const config = require("../utils/config");

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------
// Maximum vulnerabilities per API call to stay within token limits
const CHUNK_SIZE = 10;

// ---------------------------------------------------------------------------
// OpenAI client (lazy-initialized to allow module import without API key)
// ---------------------------------------------------------------------------
let _openaiClient = null;
function getOpenAIClient() {
  if (!_openaiClient) {
    if (!config.openai.apiKey) {
      throw new Error(
        "OPENAI_API_KEY is not set. Configure it in your .env file."
      );
    }
    _openaiClient = new OpenAI({ apiKey: config.openai.apiKey });
  }
  return _openaiClient;
}

// ---------------------------------------------------------------------------
// Build a structured prompt for the LLM
// ---------------------------------------------------------------------------
function buildPrompt(vulnerabilities) {
  const vulnList = vulnerabilities
    .map(
      (v, i) =>
        `${i + 1}. ID: ${v.id}
   Title: ${v.title}
   Severity: ${v.severity} (CVSS: ${v.cvss_score})
   Asset: ${v.affected_asset}
   Source: ${v.source}
   Confidence: ${v.confidence}
   Description: ${v.description.substring(0, 300)}`
    )
    .join("\n\n");

  return `You are a senior cybersecurity analyst performing a vulnerability risk assessment.
Analyse the following ${vulnerabilities.length} security finding(s) and provide a structured JSON response.

FINDINGS:
${vulnList}

INSTRUCTIONS:
For each finding, provide:
1. priority_rank: integer (1 = highest priority to fix first)
2. exploitability_score: float 0.0-10.0 (likelihood of real-world exploitation)
3. business_impact: string (concise description of potential business damage)
4. remediation: string (specific, actionable remediation steps)
5. false_positive_probability: float 0.0-1.0 (probability this is a false positive)
6. false_positive_reason: string (explanation if false_positive_probability > 0.3)
7. severity_justification: string (why you assigned this priority ranking)
8. ai_risk_score: float 0.0-10.0 (composite AI risk score considering exploitability,
   business impact, and confidence)

REQUIREMENTS:
- Base your analysis on real-world threat intelligence and exploit databases.
- Justify every score with concrete technical reasoning.
- Flag likely false positives explicitly.
- Do NOT invent CVE numbers — only reference ones you are certain about.
- Return a valid JSON object with key "analyses" containing an array of objects,
  each with the field "id" matching the finding ID and the fields listed above.

EXAMPLE RESPONSE FORMAT:
{
  "analyses": [
    {
      "id": "<finding-id>",
      "priority_rank": 1,
      "exploitability_score": 8.5,
      "business_impact": "...",
      "remediation": "...",
      "false_positive_probability": 0.05,
      "false_positive_reason": "",
      "severity_justification": "...",
      "ai_risk_score": 8.2
    }
  ]
}`;
}

// ---------------------------------------------------------------------------
// Call the LLM for a chunk of vulnerabilities
// ---------------------------------------------------------------------------
async function analyseChunk(vulnerabilities) {
  const client = getOpenAIClient();
  const prompt = buildPrompt(vulnerabilities);

  logger.info("Sending %d vulnerabilities to %s...", vulnerabilities.length, config.openai.model);

  const startTime = Date.now();
  const response = await client.chat.completions.create({
    model: config.openai.model,
    messages: [
      {
        role: "system",
        content:
          "You are an expert cybersecurity analyst. Respond only with valid JSON. " +
          "Do not include markdown code fences or any text outside the JSON object.",
      },
      { role: "user", content: prompt },
    ],
    temperature: 0.2, // Low temperature for consistent, reproducible analysis
    response_format: { type: "json_object" },
  });

  const elapsed = Date.now() - startTime;
  const usage = response.usage;

  logger.info(
    "LLM response received | time=%dms tokens_in=%d tokens_out=%d",
    elapsed,
    usage?.prompt_tokens || 0,
    usage?.completion_tokens || 0
  );

  let parsed;
  try {
    parsed = JSON.parse(response.choices[0].message.content);
  } catch (err) {
    logger.error("Failed to parse LLM JSON response: %s", err.message);
    throw new Error(`LLM returned invalid JSON: ${err.message}`);
  }

  return {
    analyses: parsed.analyses || [],
    usage: {
      prompt_tokens: usage?.prompt_tokens || 0,
      completion_tokens: usage?.completion_tokens || 0,
      total_tokens: usage?.total_tokens || 0,
    },
    processing_time_ms: elapsed,
  };
}

// ---------------------------------------------------------------------------
// Main analysis function
// ---------------------------------------------------------------------------
async function analyzeVulnerabilities(vulnerabilities) {
  if (!vulnerabilities || vulnerabilities.length === 0) {
    logger.warn("No vulnerabilities to analyse.");
    return { enriched: [], metrics: { total_tokens: 0, processing_time_ms: 0 } };
  }

  logger.info("Starting AI analysis of %d vulnerabilities...", vulnerabilities.length);
  const overallStart = Date.now();

  // Build an index map for fast lookup by ID
  const vulnMap = new Map(vulnerabilities.map((v) => [v.id, { ...v }]));

  let totalTokens = 0;
  const chunks = [];
  for (let i = 0; i < vulnerabilities.length; i += CHUNK_SIZE) {
    chunks.push(vulnerabilities.slice(i, i + CHUNK_SIZE));
  }

  logger.info("Processing %d chunk(s) of up to %d findings each.", chunks.length, CHUNK_SIZE);

  for (const [idx, chunk] of chunks.entries()) {
    logger.info("Processing chunk %d/%d...", idx + 1, chunks.length);

    const result = await analyseChunk(chunk);
    totalTokens += result.usage.total_tokens;

    // Merge AI analysis back into vulnerability objects
    for (const analysis of result.analyses) {
      const vuln = vulnMap.get(analysis.id);
      if (vuln) {
        vuln.ai_analysis = {
          priority_rank: analysis.priority_rank,
          exploitability_score: analysis.exploitability_score,
          business_impact: analysis.business_impact,
          remediation: analysis.remediation,
          false_positive_probability: analysis.false_positive_probability,
          false_positive_reason: analysis.false_positive_reason || "",
          severity_justification: analysis.severity_justification,
          ai_risk_score: analysis.ai_risk_score,
        };
      } else {
        logger.warn("LLM returned analysis for unknown ID: %s", analysis.id);
      }
    }
  }

  // Ensure every vulnerability has an ai_analysis (fallback if LLM missed it)
  for (const vuln of vulnMap.values()) {
    if (!vuln.ai_analysis) {
      logger.warn("No AI analysis for %s (%s) — using defaults.", vuln.id, vuln.title);
      vuln.ai_analysis = {
        priority_rank: 99,
        exploitability_score: vuln.cvss_score,
        business_impact: "Not assessed by AI.",
        remediation: "Manual review required.",
        false_positive_probability: 0.0,
        false_positive_reason: "",
        severity_justification: "AI analysis unavailable.",
        ai_risk_score: vuln.cvss_score,
      };
    }
  }

  // Re-sort by AI priority rank
  const enriched = Array.from(vulnMap.values()).sort(
    (a, b) => (a.ai_analysis.priority_rank || 99) - (b.ai_analysis.priority_rank || 99)
  );

  const metrics = {
    total_tokens: totalTokens,
    processing_time_ms: Date.now() - overallStart,
    vulnerabilities_analysed: enriched.length,
    model: config.openai.model,
  };

  logger.info(
    "AI analysis complete | findings=%d tokens=%d time=%dms",
    enriched.length,
    metrics.total_tokens,
    metrics.processing_time_ms
  );

  return { enriched, metrics };
}

// ---------------------------------------------------------------------------
// Read latest normalised data
// ---------------------------------------------------------------------------
function readLatestNormalisedData() {
  const dir = config.paths.processedDir;
  if (!fs.existsSync(dir)) return null;
  const files = fs
    .readdirSync(dir)
    .filter((f) => f.startsWith("normalised_") && f.endsWith(".json"))
    .sort()
    .reverse();
  if (!files.length) return null;
  return JSON.parse(fs.readFileSync(path.join(dir, files[0]), "utf8"));
}

// ---------------------------------------------------------------------------
// CLI entry point
// ---------------------------------------------------------------------------
async function main() {
  const data = readLatestNormalisedData();
  if (!data) {
    logger.error("No normalised data found. Run the normalizer first.");
    process.exit(1);
  }

  const { enriched, metrics } = await analyzeVulnerabilities(data.vulnerabilities);

  const output = {
    generated_at: new Date().toISOString(),
    metrics,
    total_vulnerabilities: enriched.length,
    vulnerabilities: enriched,
  };

  if (!fs.existsSync(config.paths.processedDir)) {
    fs.mkdirSync(config.paths.processedDir, { recursive: true });
  }

  const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
  const outFile = path.join(config.paths.processedDir, `ai_analysis_${timestamp}.json`);
  fs.writeFileSync(outFile, JSON.stringify(output, null, 2));
  logger.info("AI analysis saved to %s", outFile);

  return output;
}

if (require.main === module) {
  main().catch((err) => {
    logger.error("AI analyzer failed:", err);
    process.exit(1);
  });
}

module.exports = { analyzeVulnerabilities, buildPrompt };
