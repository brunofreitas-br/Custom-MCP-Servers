import { graphErrorDiagnostics } from './apiClient.js';
import { CaseEnrichmentError, CaseFallbackError } from './caseManagement.js';

export function toolErrorDetails(error: unknown, tool: string, args: Record<string, unknown>) {
  const target: Record<string, string> = {};
  if (typeof args === 'object' && args !== null && !Array.isArray(args)) {
    for (const key of ['caseId', 'incidentId', 'alertId', 'referenceType', 'referenceId']) {
      if (typeof args[key] === 'string') target[key] = args[key];
    }
  }
  const failure = error instanceof CaseEnrichmentError ? error.cause
    : error instanceof CaseFallbackError ? error.fallbackError : error;
  return {
    error: error instanceof Error ? error.message : String(error),
    diagnostics: {
      ...graphErrorDiagnostics(failure),
      tool,
      target,
      ...(error instanceof CaseFallbackError ? {
        operation: error.operation,
        routingReason: error.reason,
        attempts: [
          { stage: 'cases', error: error.primaryError.message, ...graphErrorDiagnostics(error.primaryError) },
          { stage: 'incidents', error: error.fallbackError instanceof Error ? error.fallbackError.message : String(error.fallbackError), ...graphErrorDiagnostics(error.fallbackError) },
        ],
      } : {}),
      ...(error instanceof CaseEnrichmentError ? { stage: 'alert-enrichment', resourceFound: true } : {}),
    },
    ...(error instanceof CaseEnrichmentError ? { partialResult: error.partialResult } : {}),
  };
}
