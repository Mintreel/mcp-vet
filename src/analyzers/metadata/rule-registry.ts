import type { RuleFunction, RuleDefinition } from '../../types.js';

interface RegisteredRule {
  definition: RuleDefinition;
  run: RuleFunction;
}

const rules: Map<string, RegisteredRule> = new Map();

export function registerRule(definition: RuleDefinition, run: RuleFunction): void {
  rules.set(definition.id, { definition, run });
}

export function getRule(id: string): RegisteredRule | undefined {
  return rules.get(id);
}

export function getAllRules(): RegisteredRule[] {
  return Array.from(rules.values());
}

export function getRuleDefinitions(): RuleDefinition[] {
  return Array.from(rules.values()).map((r) => r.definition);
}
