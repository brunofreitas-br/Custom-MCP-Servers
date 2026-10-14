import { registerIncidentTools } from './incidents.js';
import { registerAlertTools } from './alerts.js';
import { registerHuntingTools } from './hunting.js';
import { registerCaseTools } from './cases.js';

export function registerAllTools(): void {
  registerIncidentTools();
  registerAlertTools();
  registerHuntingTools();
  registerCaseTools();
}
