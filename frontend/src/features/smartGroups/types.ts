/** The operator classes the backend assigns. Mirrors app/mdm/jamf/group_cost.py — and
 *  `unknown` is a real member, not a fallback: an operator Jamf added that LoonInspect
 *  does not recognise is reported as such rather than assumed cheap. */
export type OperatorClass = "regex" | "substring" | "unknown" | "dependent" | "exact" | "none";

export interface SmartGroupCriterion {
  name: string;
  priority: number;
  conjunction: string;
  /** Jamf's own searchType, verbatim. Shown next to the class we made of it. */
  operator: string;
  operatorClass: OperatorClass;
  value: string;
  openingParen: boolean;
  closingParen: boolean;
  depth: number;
  extensionAttribute: boolean;
}

export interface SmartGroupCost {
  id: string;
  name: string | null;
  mdmConnectionId: number;
  band: OperatorClass;
  classCounts: Partial<Record<OperatorClass, number>>;
  criteriaCount: number;
  dependentCount: number;
  maxDepth: number;
  criteria: SmartGroupCriterion[];
  firstObservedAt: string;
  lastObservedAt: string;
}

export interface SmartGroupCostResponse {
  items: SmartGroupCost[];
  total: number;
  ranking: string;
  advisory: string;
}
