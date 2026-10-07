export function validateArguments(args: Record<string, unknown>, allowedFields: string[]): void {
  if (typeof args !== "object" || args === null || Array.isArray(args)) {
    throw new Error("Tool arguments must be an object");
  }
  for (const name of Object.keys(args)) {
    if (!allowedFields.includes(name)) {
      throw new Error(`Unsupported argument: ${name}`);
    }
  }
}

export function requireString(value: unknown, name: string): string {
  if (typeof value !== "string" || value.trim().length === 0) {
    throw new Error(`${name} must be a non-empty string`);
  }
  return value;
}

export function requireHex(value: unknown, length: number, name: string): string {
  const text = requireString(value, name);
  if (!new RegExp(`^[a-fA-F0-9]{${length}}$`).test(text)) {
    throw new Error(`${name} must contain exactly ${length} hexadecimal characters`);
  }
  return text;
}
