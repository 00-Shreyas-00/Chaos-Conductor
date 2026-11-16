// Types mirroring the control-plane API (api/openapi/openapi.yaml).

export type FaultType = 'PodKill';
export type MetricName = 'available_replicas' | 'ready_ratio' | 'recovery_time' | 'http_error_rate' | 'http_latency_p99';
export type Operator = 'lt' | 'le' | 'gt' | 'ge' | 'eq';

export interface Target {
  namespace: string;
  selector: Record<string, string>;
}

export interface Step {
  fault?: { type: FaultType; target: Target; podKill?: { count: number; gracePeriodSeconds?: number } };
  wait?: { duration: string };
}

export interface Criterion {
  metric: MetricName;
  operator: Operator;
  value: string;
  weight?: number;
}

export interface CreateExperimentRequest {
  description: string;
  maxDuration: string;
  steps: Step[];
  successCriteria?: Criterion[];
  confirm: boolean;
}

export interface PodRef {
  namespace: string;
  name: string;
  uid: string;
}

export interface StepStatus {
  phase: string;
  startedAt?: string;
  finishedAt?: string;
  targets?: PodRef[];
  readyBefore?: number;
  recoveryMillis?: number;
  message?: string;
}

export interface CriterionResult {
  metric: MetricName;
  operator: Operator;
  expected: string;
  observed?: string;
  passed: boolean;
  weight: number;
  message?: string;
}

export interface ExperimentStatus {
  phase?: string;
  message?: string;
  startedAt?: string;
  completedAt?: string;
  steps?: StepStatus[];
  result?: string;
  score?: number;
  criteria?: CriterionResult[];
}

export interface Experiment {
  id: string;
  name: string;
  clusterId: string;
  requesterIssuer: string;
  requesterSubject: string;
  requesterName?: string;
  description: string;
  spec: { clusterID: string; maxDuration: string; steps: Step[]; successCriteria?: Criterion[] };
  risk: string;
  state: string;
  phase: string;
  result?: string;
  score?: number;
  status?: ExperimentStatus;
  cancelRequested: boolean;
  createdAt: string;
}

export interface TimelineEvent {
  id: number;
  occurredAt: string;
  type: string;
  message: string;
}

export interface FaultInfo {
  type: FaultType;
  description: string;
  risk: string;
  parameters: { name: string; type: string; min: number; max: number; default?: number; description: string }[];
}

export interface Scenario {
  id: string;
  name: string;
  description: string;
  maxDuration: string;
  steps: Step[];
  successCriteria: Criterion[];
}

export interface ClusterSummary {
  id: string;
  environment?: string;
  locked: boolean;
  policy: null | {
    allowedFaults: FaultType[];
    allowedNamespaces: string[];
    limits: { maxPodKillCount: number; maxDuration: string; maxConcurrentExperiments: number; minReadyReplicas?: number };
    approvalRequired: string;
    prometheus: boolean;
  };
}

export interface LockState {
  locked: boolean;
  locks: { name: string; reason: string; engagedBy: string; since: string }[];
}

export interface AuditRecord {
  seq: number;
  id: string;
  occurredAt: string;
  action: string;
  actorSubject?: string;
  actorName?: string;
  decision?: string;
  decisionReasons?: string[];
  result?: string;
  experimentId?: string;
  namespace?: string;
  faultType?: string;
  sourceIp?: string;
  hash: string;
}

/** Problem details returned by the API (RFC 9457 + code/reasons). */
export interface ApiProblem {
  title: string;
  status: number;
  code?: string;
  reasons?: string[];
  detail?: string;
}
