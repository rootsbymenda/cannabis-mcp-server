import { McpAgent } from "agents/mcp";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";

interface Env {
  DB: D1Database;
  MCP_OBJECT: DurableObjectNamespace;
}

export class CannabisMCP extends McpAgent<Env> {
  server = new McpServer({
    name: "twohalves-cannabis-regulatory",
    version: "1.0.0",
  });

  async init() {
    // Tool 1: check_cannabis_testing — Look up testing limits by state
    this.server.tool(
      "check_cannabis_testing",
      "Look up cannabis testing limits (pesticides, heavy metals, microbials, solvents, mycotoxins, potency) by US state and optionally by test category or analyte. Returns action levels, units, product types, and regulation references.",
      {
        state: z
          .string()
          .describe(
            "US state name (e.g. 'California', 'Colorado', 'Oregon')"
          ),
        test_category: z
          .string()
          .optional()
          .describe(
            "Optional test category filter: pesticide, heavy_metal, microbial, solvent, mycotoxin, potency, moisture"
          ),
        analyte: z
          .string()
          .optional()
          .describe(
            "Optional specific analyte name (e.g. 'lead', 'arsenic', 'Salmonella', 'butane')"
          ),
      },
      async ({ state, test_category, analyte }) => {
        let sql = `SELECT * FROM cannabis_testing_limits WHERE state LIKE ? COLLATE NOCASE`;
        const params: string[] = [`%${state.trim()}%`];

        if (test_category) {
          sql += ` AND test_category LIKE ? COLLATE NOCASE`;
          params.push(`%${test_category.trim()}%`);
        }
        if (analyte) {
          sql += ` AND analyte_name LIKE ? COLLATE NOCASE`;
          params.push(`%${analyte.trim()}%`);
        }
        sql += ` ORDER BY test_category, analyte_name LIMIT 100`;

        const { results } = await this.env.DB.prepare(sql)
          .bind(...params)
          .all();

        if (!results || results.length === 0) {
          return {
            content: [
              {
                type: "text" as const,
                text: `No cannabis testing limits found for state "${state}"${test_category ? `, category "${test_category}"` : ""}${analyte ? `, analyte "${analyte}"` : ""}. Try a different state or broader search.`,
              },
            ],
          };
        }

        const grouped: Record<string, any[]> = {};
        for (const r of results) {
          const cat = (r.test_category as string) || "other";
          if (!grouped[cat]) grouped[cat] = [];
          grouped[cat].push(r);
        }

        let text = `## Cannabis Testing Limits — ${state}\n\n`;
        for (const [cat, items] of Object.entries(grouped)) {
          text += `### ${cat.toUpperCase()}\n`;
          for (const item of items) {
            text += `- **${item.analyte_name}**: ${item.action_level || "N/A"} ${item.units || ""} (${item.product_type || "all products"})`;
            if (item.regulation_reference)
              text += ` — ${item.regulation_reference}`;
            text += `\n`;
          }
          text += `\n`;
        }
        text += `\n*${results.length} limits found*`;

        return { content: [{ type: "text" as const, text }] };
      }
    );

    // Tool 2: check_controlled_substance — Check scheduling status
    this.server.tool(
      "check_controlled_substance",
      "Check if a substance is a controlled/scheduled substance under international (UN INCB) or regional frameworks. Returns scheduling information, synonyms, and regulatory status.",
      {
        query: z
          .string()
          .describe(
            "Substance name or CAS number (e.g. 'morphine', 'cannabis', '64-17-5')"
          ),
      },
      async ({ query }) => {
        const q = query.trim();

        // Check INCB Yellow List (narcotic drugs)
        const incb = await this.env.DB.prepare(
          `SELECT * FROM incb_yellow_list
           WHERE substance_name LIKE ? COLLATE NOCASE
              OR synonyms LIKE ? COLLATE NOCASE
              OR cas_number = ?
           LIMIT 5`
        )
          .bind(`%${q}%`, `%${q}%`, q)
          .all();

        // Check EU Drug Precursors
        const precursor = await this.env.DB.prepare(
          `SELECT * FROM eu_drug_precursors
           WHERE substance_name LIKE ? COLLATE NOCASE
              OR cas_number = ?
           LIMIT 5`
        )
          .bind(`%${q}%`, q)
          .all();

        // Check EMCDDA NPS
        const nps = await this.env.DB.prepare(
          `SELECT * FROM emcdda_nps
           WHERE substance_name LIKE ? COLLATE NOCASE
           LIMIT 5`
        )
          .bind(`%${q}%`)
          .all();

        const hasResults =
          (incb.results?.length || 0) > 0 ||
          (precursor.results?.length || 0) > 0 ||
          (nps.results?.length || 0) > 0;

        if (!hasResults) {
          return {
            content: [
              {
                type: "text" as const,
                text: `No controlled substance records found for "${query}". The substance may not be internationally scheduled, or try alternative names/CAS numbers.`,
              },
            ],
          };
        }

        let text = `## Controlled Substance Check: "${query}"\n\n`;

        if (incb.results && incb.results.length > 0) {
          text += `### UN INCB Scheduling (Yellow List — Narcotic Drugs)\n`;
          for (const r of incb.results) {
            text += `- **${r.substance_name}** — Schedule ${r.schedule}\n`;
            if (r.cas_number) text += `  - CAS: ${r.cas_number}\n`;
            if (r.synonyms) text += `  - Synonyms: ${r.synonyms}\n`;
            if (r.formula) text += `  - Formula: ${r.formula}\n`;
            if (r.conversion_ratio)
              text += `  - Conversion ratio: ${r.conversion_ratio}\n`;
            if (r.notes) text += `  - Notes: ${r.notes}\n`;
          }
          text += `\n`;
        }

        if (precursor.results && precursor.results.length > 0) {
          text += `### EU Drug Precursors\n`;
          for (const r of precursor.results) {
            text += `- **${r.substance_name}** — Category ${r.category || "N/A"}\n`;
            if (r.cas_number) text += `  - CAS: ${r.cas_number}\n`;
            if (r.cn_code) text += `  - CN Code: ${r.cn_code}\n`;
            if (r.threshold_quantity_for_reporting)
              text += `  - Threshold: ${r.threshold_quantity_for_reporting}\n`;
            if (r.license_registration_requirements)
              text += `  - Requirements: ${r.license_registration_requirements}\n`;
          }
          text += `\n`;
        }

        if (nps.results && nps.results.length > 0) {
          text += `### EU Novel Psychoactive Substances (EMCDDA/EUDA)\n`;
          for (const r of nps.results) {
            text += `- **${r.substance_name}** — ${r.control_status || "monitored"}\n`;
            if (r.chemical_class)
              text += `  - Class: ${r.chemical_class}\n`;
            if (r.risk_assessment_year)
              text += `  - Risk assessed: ${r.risk_assessment_year}\n`;
            if (r.scheduling_control_decision_notes)
              text += `  - Decision: ${r.scheduling_control_decision_notes}\n`;
          }
          text += `\n`;
        }

        return { content: [{ type: "text" as const, text }] };
      }
    );

    // Tool 3: check_cannabis_compliance — Check product compliance across jurisdictions
    this.server.tool(
      "check_cannabis_compliance",
      "Check cannabis product compliance requirements across jurisdictions. Compare testing requirements between US states, or check Health Canada cannabis regulations for a specific product class.",
      {
        jurisdiction: z
          .string()
          .describe(
            "Jurisdiction: a US state name (e.g. 'California') or 'Canada' for Health Canada regulations"
          ),
        product_class: z
          .string()
          .optional()
          .describe(
            "Optional product class: flower, concentrate, edible, topical, extract, oil, dried_cannabis"
          ),
      },
      async ({ jurisdiction, product_class }) => {
        const j = jurisdiction.trim();
        let text = `## Cannabis Compliance — ${j}\n\n`;

        if (j.toLowerCase() === "canada") {
          let sql = `SELECT * FROM health_canada_cannabis WHERE 1=1`;
          const params: string[] = [];
          if (product_class) {
            sql += ` AND (product_class LIKE ? COLLATE NOCASE OR category LIKE ? COLLATE NOCASE)`;
            params.push(`%${product_class}%`, `%${product_class}%`);
          }
          sql += ` ORDER BY category, analyte_or_parameter LIMIT 100`;

          const { results } = await this.env.DB.prepare(sql)
            .bind(...params)
            .all();

          if (!results || results.length === 0) {
            return {
              content: [
                {
                  type: "text" as const,
                  text: `No Health Canada cannabis regulations found${product_class ? ` for product class "${product_class}"` : ""}. Try: flower, concentrate, edible, oil, extract.`,
                },
              ],
            };
          }

          const grouped: Record<string, any[]> = {};
          for (const r of results) {
            const cat = (r.category as string) || "other";
            if (!grouped[cat]) grouped[cat] = [];
            grouped[cat].push(r);
          }

          for (const [cat, items] of Object.entries(grouped)) {
            text += `### ${cat}\n`;
            for (const item of items) {
              text += `- **${item.analyte_or_parameter}**: ${item.limit_value || "N/A"} ${item.units || ""}`;
              if (item.product_class) text += ` (${item.product_class})`;
              if (item.regulation_section)
                text += ` — ${item.regulation_section}`;
              text += `\n`;
            }
            text += `\n`;
          }
          text += `*${results.length} regulations found*`;
        } else {
          // US State
          let sql = `SELECT * FROM cannabis_testing_limits WHERE state LIKE ? COLLATE NOCASE`;
          const params: string[] = [`%${j}%`];
          if (product_class) {
            sql += ` AND product_type LIKE ? COLLATE NOCASE`;
            params.push(`%${product_class}%`);
          }
          sql += ` ORDER BY test_category, analyte_name LIMIT 150`;

          const { results } = await this.env.DB.prepare(sql)
            .bind(...params)
            .all();

          if (!results || results.length === 0) {
            return {
              content: [
                {
                  type: "text" as const,
                  text: `No cannabis testing requirements found for "${j}". This state may not have legalized cannabis, or try the full state name.`,
                },
              ],
            };
          }

          // Summary by category
          const categories: Record<string, number> = {};
          for (const r of results) {
            const cat = (r.test_category as string) || "other";
            categories[cat] = (categories[cat] || 0) + 1;
          }

          text += `**Testing categories:** ${Object.entries(categories)
            .map(([k, v]) => `${k} (${v})`)
            .join(", ")}\n\n`;

          const grouped: Record<string, any[]> = {};
          for (const r of results) {
            const cat = (r.test_category as string) || "other";
            if (!grouped[cat]) grouped[cat] = [];
            grouped[cat].push(r);
          }

          for (const [cat, items] of Object.entries(grouped)) {
            text += `### ${cat.toUpperCase()}\n`;
            for (const item of items) {
              text += `- **${item.analyte_name}**: ${item.action_level || "N/A"} ${item.units || ""}`;
              if (item.product_type) text += ` (${item.product_type})`;
              text += `\n`;
            }
            text += `\n`;
          }
          text += `*${results.length} testing requirements found*`;
        }

        return { content: [{ type: "text" as const, text }] };
      }
    );

    // Tool 4: search_cannabis_regulations — Full-text search across all cannabis data
    this.server.tool(
      "search_cannabis_regulations",
      "Search across all cannabis and controlled substance regulatory data. Searches testing limits, scheduling lists, precursor controls, and Health Canada regulations.",
      {
        query: z
          .string()
          .describe(
            "Search term (e.g. 'THC', 'pesticide', 'heavy metal', 'Salmonella', 'morphine', 'pseudoephedrine')"
          ),
      },
      async ({ query }) => {
        const q = query.trim();
        let text = `## Search Results: "${query}"\n\n`;
        let totalResults = 0;

        // Search cannabis testing limits
        const testing = await this.env.DB.prepare(
          `SELECT * FROM cannabis_testing_limits
           WHERE analyte_name LIKE ? COLLATE NOCASE
              OR test_category LIKE ? COLLATE NOCASE
              OR notes LIKE ? COLLATE NOCASE
           ORDER BY state, test_category LIMIT 50`
        )
          .bind(`%${q}%`, `%${q}%`, `%${q}%`)
          .all();

        if (testing.results && testing.results.length > 0) {
          text += `### Cannabis Testing Limits (${testing.results.length} matches)\n`;
          const byState: Record<string, any[]> = {};
          for (const r of testing.results) {
            const s = (r.state as string) || "Unknown";
            if (!byState[s]) byState[s] = [];
            byState[s].push(r);
          }
          for (const [state, items] of Object.entries(byState)) {
            text += `**${state}:** `;
            text += items
              .map(
                (i) =>
                  `${i.analyte_name} ${i.action_level || ""} ${i.units || ""}`
              )
              .join(", ");
            text += `\n`;
          }
          text += `\n`;
          totalResults += testing.results.length;
        }

        // Search INCB
        const incb = await this.env.DB.prepare(
          `SELECT * FROM incb_yellow_list
           WHERE substance_name LIKE ? COLLATE NOCASE
              OR synonyms LIKE ? COLLATE NOCASE
           LIMIT 20`
        )
          .bind(`%${q}%`, `%${q}%`)
          .all();

        if (incb.results && incb.results.length > 0) {
          text += `### UN INCB Scheduled Substances (${incb.results.length} matches)\n`;
          for (const r of incb.results) {
            text += `- **${r.substance_name}** — Schedule ${r.schedule}${r.cas_number ? ` (CAS: ${r.cas_number})` : ""}\n`;
          }
          text += `\n`;
          totalResults += incb.results.length;
        }

        // Search Health Canada
        const hc = await this.env.DB.prepare(
          `SELECT * FROM health_canada_cannabis
           WHERE analyte_or_parameter LIKE ? COLLATE NOCASE
              OR category LIKE ? COLLATE NOCASE
           LIMIT 20`
        )
          .bind(`%${q}%`, `%${q}%`)
          .all();

        if (hc.results && hc.results.length > 0) {
          text += `### Health Canada Cannabis (${hc.results.length} matches)\n`;
          for (const r of hc.results) {
            text += `- **${r.analyte_or_parameter}**: ${r.limit_value || "N/A"} ${r.units || ""} (${r.product_class || "all"})\n`;
          }
          text += `\n`;
          totalResults += hc.results.length;
        }

        // Search precursors
        const prec = await this.env.DB.prepare(
          `SELECT * FROM eu_drug_precursors
           WHERE substance_name LIKE ? COLLATE NOCASE
           LIMIT 10`
        )
          .bind(`%${q}%`)
          .all();

        if (prec.results && prec.results.length > 0) {
          text += `### EU Drug Precursors (${prec.results.length} matches)\n`;
          for (const r of prec.results) {
            text += `- **${r.substance_name}** — Category ${r.category || "N/A"}${r.cas_number ? ` (CAS: ${r.cas_number})` : ""}\n`;
          }
          text += `\n`;
          totalResults += prec.results.length;
        }

        if (totalResults === 0) {
          return {
            content: [
              {
                type: "text" as const,
                text: `No results found for "${query}" across cannabis testing limits, controlled substance schedules, precursor lists, or Health Canada regulations. Try alternative terms or broader searches.`,
              },
            ],
          };
        }

        text += `---\n*${totalResults} total results across all databases*`;
        return { content: [{ type: "text" as const, text }] };
      }
    );
  }
}

export default {
  fetch(request: Request, env: Env, ctx: ExecutionContext) {
    const url = new URL(request.url);

    if (url.pathname === "/mcp" || url.pathname === "/mcp/") {
      const id = env.MCP_OBJECT.idFromName("cannabis-mcp");
      const stub = env.MCP_OBJECT.get(id);
      return stub.fetch(request);
    }

    return new Response(
      JSON.stringify({
        name: "Two Halves — Cannabis & Controlled Substances Regulatory Intelligence",
        version: "1.0.0",
        description:
          "Cannabis testing limits (18+ US states), UN controlled substance scheduling, EU drug precursors, Health Canada cannabis regulations, and novel psychoactive substance monitoring. Query state-by-state testing requirements, check substance scheduling status, and verify cannabis product compliance across jurisdictions.",
        mcp_endpoint: "/mcp",
        tools: [
          "check_cannabis_testing",
          "check_controlled_substance",
          "check_cannabis_compliance",
          "search_cannabis_regulations",
        ],
        data: {
          cannabis_testing_limits: "1,942 state-level testing requirements",
          incb_yellow_list: "154 UN scheduled narcotic drugs",
          eu_drug_precursors: "46 EU controlled precursor chemicals",
          emcdda_nps: "41 risk-assessed novel psychoactive substances",
          health_canada_cannabis: "383 Canadian cannabis regulations",
        },
      }),
      {
        headers: { "Content-Type": "application/json" },
      }
    );
  },
};
