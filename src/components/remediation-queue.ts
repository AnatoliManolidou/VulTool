import { Threat } from '../types';

export function generateRemediationQueue(threats: Threat[]): Threat[] {
  return [...threats].sort((a, b) => b.priorityScore - a.priorityScore);
}
