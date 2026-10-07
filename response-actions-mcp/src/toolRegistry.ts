export type ToolCollection = "identity" | "devices";

export interface ToolDefinition {
  name: string;
  description: string;
  collection: ToolCollection;
  inputSchema: {
    type: "object";
    properties: Record<string, unknown>;
    required?: string[];
    additionalProperties?: boolean;
  };
  handler: (args: Record<string, unknown>, token: string) => Promise<unknown>;
}

const tools = new Map<string, ToolDefinition>();

export function registerTool(tool: ToolDefinition): void {
  tools.set(tool.name, tool);
}

export function getTool(name: string, collection?: ToolCollection): ToolDefinition | undefined {
  const tool = tools.get(name);
  if (!tool) return undefined;
  if (collection && tool.collection !== collection) return undefined;
  return tool;
}

export function listTools(collection?: ToolCollection): { name: string; description: string; inputSchema: unknown }[] {
  return Array.from(tools.values())
    .filter((t) => !collection || t.collection === collection)
    .map((t) => ({
      name: t.name,
      description: t.description,
      inputSchema: t.inputSchema,
    }));
}
