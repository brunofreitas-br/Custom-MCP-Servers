export interface UpdateProperty {
  type: 'string' | 'array' | 'object' | ['string', 'null'];
  description: string;
  enum?: string[];
  minLength?: number;
  items?: { type: 'string'; minLength: number };
  additionalProperties?: { type: 'string' };
}

export const commonUpdateProperties: Record<string, UpdateProperty> = {
  assignedTo: {
    type: ['string', 'null'],
    description: 'Assigned analyst. Use null to remove the assignment',
    minLength: 1,
  },
  classification: {
    type: 'string',
    enum: ['unknown', 'truePositive', 'falsePositive', 'informationalExpectedActivity'],
    description: 'Analyst classification; never inferred automatically when closing',
  },
  determination: {
    type: 'string',
    minLength: 1,
    description: 'Microsoft Graph determination value, such as malware or phishing',
  },
};

export function buildUpdate(
  params: Record<string, unknown>,
  idField: string,
  properties: Record<string, UpdateProperty>,
): { id: string; body: Record<string, unknown> } {
  if (typeof params !== 'object' || params === null || Array.isArray(params)) {
    throw new Error('Tool arguments must be an object');
  }

  const id = params[idField];
  if (typeof id !== 'string' || id.trim().length === 0) {
    throw new Error(`${idField} must be a non-empty string`);
  }

  const body: Record<string, unknown> = {};
  for (const [name, value] of Object.entries(params)) {
    if (name === idField) continue;
    if (!Object.hasOwn(properties, name)) {
      throw new Error(`Unsupported update field: ${name}`);
    }
    const property = properties[name];

    if (Array.isArray(property.type)) {
      if (value !== null && (typeof value !== 'string' || value.trim().length === 0)) {
        throw new Error(`${name} must be a non-empty string or null`);
      }
    } else if (property.type === 'array') {
      if (!Array.isArray(value) || value.some((item) => typeof item !== 'string' || item.trim().length === 0)) {
        throw new Error(`${name} must be an array of non-empty strings`);
      }
    } else if (property.type === 'object') {
      if (typeof value !== 'object' || value === null || Array.isArray(value) ||
          Object.values(value).some((item) => typeof item !== 'string')) {
        throw new Error(`${name} must be an object with string values`);
      }
    } else {
      if (typeof value !== 'string' || (property.minLength && value.trim().length < property.minLength)) {
        throw new Error(`${name} must be ${property.minLength ? 'a non-empty string' : 'a string'}`);
      }
      if (property.enum && !property.enum.includes(value)) {
        throw new Error(`${name} must be one of: ${property.enum.join(', ')}`);
      }
    }
    body[name] = value;
  }

  if (Object.keys(body).length === 0) {
    throw new Error('Provide at least one field to update');
  }
  return { id, body };
}
