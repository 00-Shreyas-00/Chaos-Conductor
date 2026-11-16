import { HttpClient } from '@angular/common/http';
import { Injectable, InjectionToken, inject } from '@angular/core';
import { Observable, map } from 'rxjs';
import {
  AuditRecord,
  ClusterSummary,
  CreateExperimentRequest,
  Experiment,
  FaultInfo,
  LockState,
  Scenario,
  TimelineEvent,
} from './api.types';

/** Factory for EventSource so live updates are testable. */
export const EVENT_SOURCE = new InjectionToken<(url: string) => EventSource>('EVENT_SOURCE', {
  factory: () => (url: string) => new EventSource(url, { withCredentials: true }),
});

export type LiveMessage =
  | { type: 'experiment'; data: Experiment }
  | { type: 'timeline'; data: TimelineEvent }
  | { type: 'resync'; data: unknown };

/** Thin client for the control-plane API. All authorization happens server-side. */
@Injectable({ providedIn: 'root' })
export class ExperimentsService {
  private readonly http = inject(HttpClient);
  private readonly eventSource = inject(EVENT_SOURCE);

  list(): Observable<Experiment[]> {
    return this.http.get<{ items: Experiment[] }>('/api/v1/experiments').pipe(map((r) => r.items));
  }

  get(id: string): Observable<{ experiment: Experiment; timeline: TimelineEvent[] }> {
    return this.http.get<{ experiment: Experiment; timeline: TimelineEvent[] }>(`/api/v1/experiments/${encodeURIComponent(id)}`);
  }

  create(req: CreateExperimentRequest): Observable<Experiment> {
    return this.http.post<Experiment>('/api/v1/experiments', req);
  }

  cancel(id: string): Observable<Experiment> {
    return this.http.post<Experiment>(`/api/v1/experiments/${encodeURIComponent(id)}/cancel`, null);
  }

  faults(): Observable<FaultInfo[]> {
    return this.http.get<{ items: FaultInfo[] }>('/api/v1/faults').pipe(map((r) => r.items));
  }

  scenarios(): Observable<Scenario[]> {
    return this.http.get<{ items: Scenario[] }>('/api/v1/scenarios').pipe(map((r) => r.items));
  }

  clusters(): Observable<ClusterSummary[]> {
    return this.http.get<{ items: ClusterSummary[] }>('/api/v1/clusters').pipe(map((r) => r.items));
  }

  lock(): Observable<LockState> {
    return this.http.get<LockState>('/api/v1/system/lock');
  }

  engageLock(reason: string): Observable<{ locked: boolean; lock: string }> {
    return this.http.post<{ locked: boolean; lock: string }>('/api/v1/admin/lock', { reason });
  }

  audit(before?: number): Observable<AuditRecord[]> {
    const q = before ? `?limit=100&before=${before}` : '?limit=100';
    return this.http.get<{ items: AuditRecord[] }>(`/api/v1/audit${q}`).pipe(map((r) => r.items));
  }

  verifyAudit(): Observable<{ events: number; head: string }> {
    return this.http.get<{ events: number; head: string }>('/api/v1/audit/verify');
  }

  /** Live updates over Server-Sent Events (the session cookie authenticates the stream). */
  live(id: string): Observable<LiveMessage> {
    return new Observable<LiveMessage>((subscriber) => {
      const es = this.eventSource(`/api/v1/experiments/${encodeURIComponent(id)}/events`);
      const on = (type: LiveMessage['type']) => (ev: MessageEvent) => {
        try {
          subscriber.next({ type, data: JSON.parse(ev.data) } as LiveMessage);
        } catch {
          /* ignore malformed frames */
        }
      };
      const handlers: [string, (ev: MessageEvent) => void][] = [
        ['experiment', on('experiment')],
        ['timeline', on('timeline')],
        ['resync', on('resync')],
      ];
      handlers.forEach(([t, h]) => es.addEventListener(t, h as EventListener));
      return () => {
        handlers.forEach(([t, h]) => es.removeEventListener(t, h as EventListener));
        es.close();
      };
    });
  }
}
