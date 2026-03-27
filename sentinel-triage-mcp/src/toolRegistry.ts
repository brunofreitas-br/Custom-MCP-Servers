export interface ToolDefinition {
  name: string;
  description: string;
  inputSchema: Record<string, unknown>;
  handler: (params: Record<string, unknown>) => Promise<unknown>;
}

const tools = new Map<string, ToolDefinition>();

export function registerTool(tool: ToolDefinition): void {
  tools.set(tool.name, tool);
}

export function listTools(): Array<{ name: string; description: string; inputSchema: Record<string, unknown> }> {
  return Array.from(tools.values()).map((t) => ({
    name: t.name,
    description: t.description,
    inputSchema: t.inputSchema,
  }));
}

export function getTool(name: string): ToolDefinition | undefined {
  return tools.get(name);
}
