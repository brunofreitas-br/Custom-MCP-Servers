import { registerIncidentTools } from './incidents.js';
import { registerAlertTools } from './alerts.js';
import { registerHuntingTools } from './hunting.js';

export function registerAllTools(): void {
  registerIncidentTools();
  registerAlertTools();
  registerHuntingTools();
}
