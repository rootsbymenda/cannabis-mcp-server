# Roots by Benda — Cannabis Regulatory Intelligence MCP Server

**Cannabis testing requirements, controlled substance scheduling, and compliance data in one MCP.** Check US state-level testing limits (pesticides, heavy metals, microbials, solvents, potency), UN/EU controlled substance schedules, Health Canada cannabis rules, and novel psychoactive substance monitoring — all source-linked and free.

No equivalent consolidated cross-jurisdiction cannabis compliance MCP exists. This is the first.

**Live endpoint:** `https://cannabis-mcp-server.rootsbybenda.workers.dev/mcp`
**SSE fallback:** `https://cannabis-mcp-server.rootsbybenda.workers.dev/sse`

## Tools

### `check_cannabis_testing`
Look up cannabis testing limits by US state, test category, product type, or analyte. Returns pesticide, heavy metal, microbial, solvent, mycotoxin, potency, moisture, action-level, unit, and regulation-reference data.

```
state: "California", test_category: "heavy_metal"
→ Arsenic: 0.2 µg/g (inhalable), 1.5 µg/g (non-inhalable) — CA DCC 4 CCR §15723
  Cadmium: 0.2 µg/g (inhalable), 0.5 µg/g (non-inhalable)
  Lead: 0.5 µg/g (both categories)
  Mercury: 0.1 µg/g (inhalable), 3.0 µg/g (non-inhalable)
  8 limits found, all regulation-referenced
```

### `check_controlled_substance`
Check whether a substance is controlled or scheduled under UN INCB narcotic schedules, EU drug-precursor controls, or EMCDDA/EUDA novel psychoactive-substance monitoring. Returns schedules, categories, synonyms, CAS numbers, and regulatory notes.

```
query: "psilocybin"
→ UN Schedule I (1971 Convention); CAS 520-52-5; Category: indole alkaloid;
  Status: no accepted medical use (UN), breakthrough therapy (FDA, 2018)
```

### `check_cannabis_compliance`
Check cannabis product compliance requirements for a US state or Health Canada product class. Returns jurisdiction-specific testing categories, analyte limits, product classes, units, and regulation sections.

```
jurisdiction: "Colorado", product_class: "concentrate"
→ Testing required: potency, residual solvents, heavy metals, microbials, mycotoxins
  Per-analyte limits with regulation references (1 CCR 212-3)
```

### `search_cannabis_regulations`
Search cannabis and controlled-substance regulatory data by keyword. Use for broad discovery across state testing limits, Health Canada cannabis rules, UN scheduling, EU precursors, and novel psychoactive substances.

```
query: "heavy metal"
→ matches across CA, CO, OR, WA state testing limits for Lead, Cadmium, Arsenic, Mercury
  with action levels, units, and product-type distinctions per jurisdiction
```

## Data

| Dataset | Records |
|---------|---------|
| US state cannabis testing requirements | 1,942 |
| Health Canada cannabis rules | 383 |
| UN INCB scheduled narcotic drugs | 154 |
| EU controlled precursor chemicals | 46 |
| EMCDDA/EUDA novel psychoactive substances | 41 |

**100% source-traceability:** every record links to state regulatory code, UN conventions, EU regulations, or Health Canada primary sources.

**Sources:** US state cannabis regulatory codes (CA BCC, CO MED, OR OLCC, WA LCB, and others), Health Canada Cannabis Regulations (SOR/2018-144), UN Single Convention on Narcotic Drugs (1961), UN Convention on Psychotropic Substances (1971), EU Regulation 273/2004 (drug precursors), EMCDDA Early Warning System.

## Quick Start

### Claude Desktop / Claude Code
Add to your MCP config:
```json
{
  "mcpServers": {
    "roots-cannabis-regulatory": {
      "url": "https://cannabis-mcp-server.rootsbybenda.workers.dev/sse"
    }
  }
}
```

### Cursor / Windsurf / Zed
Use the Streamable HTTP endpoint:
```
https://cannabis-mcp-server.rootsbybenda.workers.dev/mcp
```

## Rate Limits

Every caller receives full data; a 60 requests/minute abuse-prevention limit applies per IP.

## Built With

- [Cloudflare Workers](https://workers.cloudflare.com/) + [Agents SDK](https://developers.cloudflare.com/agents/)
- [Cloudflare D1](https://developers.cloudflare.com/d1/) (SQLite at the edge)
- [Durable Objects](https://developers.cloudflare.com/durable-objects/) (session-scoped rate limiting)
- [Model Context Protocol](https://modelcontextprotocol.io/) (MCP)

## Who Built This

**Roots by Benda** — regulatory intelligence platform built by Shahar Ben-David with Claude. Cannabis regulatory database assembled from primary sources across US state regulators, Health Canada, UN INCB, and EMCDDA.

- Website: [rootsbybenda.com](https://rootsbybenda.com)
- LinkedIn: [Shahar Ben-David](https://www.linkedin.com/in/shahar-ben-david-25549a3a8/)

## License

MIT
