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
  state: 'Submitting' | 'Submitted' | 'SubmitFailed' | 'PendingApproval' | 'ApprovalRejected' | 'ApprovalExpired';
  approvalRequestId?: string;
  scheduleId?: string;
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

export type Weekday = 'Mon' | 'Tue' | 'Wed' | 'Thu' | 'Fri' | 'Sat' | 'Sun';

export interface ScheduleWindow {
  days: Weekday[];
  from: string;
  to: string;
  timeZone: string;
}

export interface ScheduleTemplate {
  maxDuration: string;
  steps: Step[];
  successCriteria?: Criterion[];
}

export interface CreateScheduleRequest {
  name: string;
  description: string;
  template: ScheduleTemplate;
  minInterval: string;
  meanInterval: string;
  window: ScheduleWindow;
  expiresAt: string;
  maxRuns: number;
  confirm: boolean;
}

export interface Schedule {
  id: string;
  name: string;
  clusterId: string;
  ownerIssuer: string;
  ownerSubject: string;
  ownerName?: string;
  description: string;
  template: ScheduleTemplate;
  risk: string;
  minIntervalSeconds: number;
  meanIntervalSeconds: number;
  window: ScheduleWindow;
  expiresAt: string;
  maxRuns: number;
  runs: number;
  consecutiveDenials: number;
  state: 'Active' | 'Paused' | 'Finished' | 'Deleted';
  stateReason?: string;
  nextRunAt?: string;
  lastRunAt?: string;
  lastExperimentId?: string;
  createdAt: string;
}

export interface ScheduleRun {
  id: number;
  occurredAt: string;
  outcome: 'Started' | 'Skipped' | 'Denied' | 'Failed';
  experimentId?: string;
  reason?: string;
}
