import { registerTool } from '../toolRegistry.js';
import { graphPost } from '../apiClient.js';

export function registerHuntingTools() {
  registerTool({
    name: 'FetchAdvancedHuntingTablesOverview',
    description: 'List available advanced hunting tables. Essential for understanding data sources before writing KQL queries',
    inputSchema: {
      type: 'object',
      properties: {
        tableNames: { type: 'array', items: { type: 'string' }, description: 'Filter by specific table names. If omitted, returns all tables' },
      },
    },
    handler: async () => {
      const kql = 'search * | distinct $table | sort by $table asc';
      return graphPost('/security/runHuntingQuery', { Query: kql, Timespan: 'P1D' });
    },
  });

  registerTool({
    name: 'FetchAdvancedHuntingTablesDetailedSchema',
    description: 'Retrieve column schemas for specified advanced hunting tables. Use before RunAdvancedHuntingQuery for error-free KQL',
    inputSchema: {
      type: 'object',
      properties: {
        tableNames: { type: 'array', items: { type: 'string' }, description: 'Table names to get schema for' },
      },
      required: ['tableNames'],
    },
    handler: async (params) => {
      const tables = params.tableNames as string[];
      const kql = tables.map((t) => `${t} | getschema`).join(' | union ');
      return graphPost('/security/runHuntingQuery', { Query: kql });
    },
  });

  registerTool({
    name: 'RunAdvancedHuntingQuery',
    description: 'Run a KQL hunting query across Microsoft Defender tables. First use FetchAdvancedHuntingTablesOverview then FetchAdvancedHuntingTablesDetailedSchema',
    inputSchema: {
      type: 'object',
      properties: {
        kqlQuery: { type: 'string', description: 'KQL query to execute' },
        timespan: { type: 'string', description: 'ISO 8601 duration (e.g., P7D for 7 days)' },
      },
      required: ['kqlQuery'],
    },
    handler: async (params) => {
      const body: Record<string, string> = { Query: params.kqlQuery as string };
      if (params.timespan) body.Timespan = params.timespan as string;
      return graphPost('/security/runHuntingQuery', body);
    },
  });
}
