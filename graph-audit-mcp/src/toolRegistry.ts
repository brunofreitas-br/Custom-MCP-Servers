export interface ToolDefinition {
  name: string;
  description: string;
  inputSchema: Record<string, unknown>;
  handler: (args: Record<string, unknown>) => Promise<unknown>;
}

const tools = new Map<string, ToolDefinition>();

export function registerTool(tool: ToolDefinition): void {
  if (tools.has(tool.name)) throw new Error(`Duplicate tool: ${tool.name}`);
  tools.set(tool.name, tool);
}

export function listTools(): Array<Omit<ToolDefinition, 'handler'>> {
  return [...tools.values()].map(({ name, description, inputSchema }) => ({ name, description, inputSchema }));
}

export function getTool(name: string): ToolDefinition | undefined {
  return tools.get(name);
}
