const MAX_ID_LENGTH = 256;

export function validateArguments(args: Record<string, unknown>, allowed: readonly string[]): void {
  if (typeof args !== 'object' || args === null || Array.isArray(args)) {
    throw new Error('Tool arguments must be an object');
  }
  for (const key of Object.keys(args)) {
    if (!allowed.includes(key)) throw new Error(`Unsupported argument: ${key}`);
  }
}

export function optionalString(value: unknown, name: string, maxLength = 256): string | undefined {
  if (value === undefined) return undefined;
  if (typeof value !== 'string' || value.trim() === '' || value.length > maxLength || /[\u0000-\u001f\u007f]/u.test(value)) {
    throw new Error(`${name} must be a non-empty string of at most ${maxLength} characters without control characters`);
  }
  return value;
}

export function requireId(value: unknown, name = 'id'): string {
  const id = optionalString(value, name, MAX_ID_LENGTH);
  if (!id || id === '.' || id === '..' || id.includes('/') || id.includes('\\')) {
    throw new Error(`${name} must be a valid Microsoft Graph resource ID`);
  }
  return id;
}

export function optionalInteger(
  value: unknown,
  name: string,
  minimum: number,
  maximum: number,
  defaultValue: number,
): number {
  if (value === undefined) return defaultValue;
  if (!Number.isInteger(value) || (value as number) < minimum || (value as number) > maximum) {
    throw new Error(`${name} must be an integer between ${minimum} and ${maximum}`);
  }
  return value as number;
}

export function optionalEnum<T extends string>(
  value: unknown,
  name: string,
  allowed: readonly T[],
): T | undefined {
  if (value === undefined) return undefined;
  if (typeof value !== 'string' || !allowed.includes(value as T)) {
    throw new Error(`${name} must be one of: ${allowed.join(', ')}`);
  }
  return value as T;
}

export function optionalTimestamp(value: unknown, name: string): string | undefined {
  if (value === undefined) return undefined;
  const text = typeof value === 'string' ? value : undefined;
  const match = text
    ? /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d{1,7})?Z$/u.exec(text)
    : null;
  if (!text || !match) {
    throw new Error(`${name} must be an ISO 8601 UTC timestamp ending in Z`);
  }
  const parsed = Date.parse(text);
  const date = new Date(parsed);
  const expected = match.slice(1, 7).map(Number);
  const actual = [
    date.getUTCFullYear(),
    date.getUTCMonth() + 1,
    date.getUTCDate(),
    date.getUTCHours(),
    date.getUTCMinutes(),
    date.getUTCSeconds(),
  ];
  if (!Number.isFinite(parsed) || expected.some((part, index) => part !== actual[index])) {
    throw new Error(`${name} must be a valid timestamp`);
  }
  return text;
}

export function validateTimeRange(from: string | undefined, to: string | undefined): void {
  if (from && to && Date.parse(from) > Date.parse(to)) {
    throw new Error('startDateTime must not be later than endDateTime');
  }
}

export function escapeODataString(value: string): string {
  return value.replaceAll("'", "''");
}

export function equalsFilter(field: string, value: string | undefined): string | undefined {
  return value === undefined ? undefined : `${field} eq '${escapeODataString(value)}'`;
}

export function combineFilters(parts: Array<string | undefined>): string | undefined {
  const values = parts.filter((part): part is string => part !== undefined);
  return values.length === 0 ? undefined : values.join(' and ');
}
