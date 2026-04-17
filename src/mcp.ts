import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod';
import * as fs from 'fs';
import { checkUnprotectedMutableAccount } from './rules/unprotectedMutableAccount';
import { checkUnconstrainedPDA } from './rules/unconstrainedPDA';
import { checkUnsafeCPITarget } from './rules/unsafeCPITarget';
import { checkAccountConfusion } from './rules/accountConfusion';
import { checkTokenAccountOwnerNotVerified } from './rules/tokenAccountOwnerNotVerified';
import { buildJsonReport } from './reporter';
import { normalizeIDL } from './utils/idlNormalizer';

const server = new McpServer({
  name: 'solsentry',
  version: '1.0.0',
});

function runAllRules(idl: any) {
  return [
    ...checkUnprotectedMutableAccount(idl),
    ...checkUnconstrainedPDA(idl),
    ...checkUnsafeCPITarget(idl),
    ...checkAccountConfusion(idl),
    ...checkTokenAccountOwnerNotVerified(idl),
  ];
}

server.tool(
  'analyze_idl_file',
  'Analyze an Anchor IDL JSON file for security vulnerabilities',
  { idl_path: z.string().describe('Absolute path to the Anchor IDL JSON file') },
  async ({ idl_path }) => {
    try {
      const idl = normalizeIDL(JSON.parse(fs.readFileSync(idl_path, 'utf-8')));
      const findings = runAllRules(idl);
      const report = buildJsonReport(idl.name, findings);
      return { content: [{ type: 'text', text: JSON.stringify(report, null, 2) }] };
    } catch (err: any) {
      return { content: [{ type: 'text', text: `Error: ${err.message}` }], isError: true };
    }
  }
);

server.tool(
  'analyze_idl_json',
  'Analyze a raw Anchor IDL JSON string for security vulnerabilities',
  { idl_json: z.string().describe('Raw Anchor IDL JSON content as a string') },
  async ({ idl_json }) => {
    try {
      const idl = normalizeIDL(JSON.parse(idl_json));
      const findings = runAllRules(idl);
      const report = buildJsonReport(idl.name, findings);
      return { content: [{ type: 'text', text: JSON.stringify(report, null, 2) }] };
    } catch (err: any) {
      return { content: [{ type: 'text', text: `Error: ${err.message}` }], isError: true };
    }
  }
);

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error('SolSentry MCP server running');
}

main();