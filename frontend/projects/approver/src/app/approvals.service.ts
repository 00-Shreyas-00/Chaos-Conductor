import { DOCUMENT } from '@angular/common';
import { HttpClient, HttpInterceptorFn } from '@angular/common/http';
import { Injectable, InjectionToken, inject, signal } from '@angular/core';
import { Observable } from 'rxjs';

export interface Approver {
  subject: string;
  issuer: string;
  displayName?: string;
  groups: string[];
  authTime?: string;
  csrfToken: string;
}

export interface Decision {
  approverSubject: string;
  approverName: string;
  decision: 'approve' | 'reject';
  comment: string;
  decidedAt: string;
}

export interface FaultStep {
  type: string;
  target: { namespace: string; selector: Record<string, string> };
  podKill?: { count: number; gracePeriodSeconds?: number };
}

export interface ApprovalRequest {
  id: string;
  experimentId: string;
  clusterId: string;
  environment: string;
  namespaces: string[];
  approverGroup: string;
  spec: { maxDuration: string; steps: { fault?: FaultStep; wait?: { duration: string } }[] };
  specSha256: string;
  risk: string;
  requesterSubject: string;
  requesterName: string;
  minApprovals: number;
  state: 'Pending' | 'Approved' | 'Rejected' | 'Expired';
  createdAt: string;
  expiresAt: string;
  decisions: Decision[];
}

export const CSRF_HEADER = 'X-KubeChaos-CSRF';

/** Indirection over window.location so navigation is testable. */
export const BROWSER_LOCATION = new InjectionToken<Pick<Location, 'assign'>>('BROWSER_LOCATION', {
  factory: () => inject(DOCUMENT).location,
});

/**
 * The approver's session and the approval API. Every rule (group membership, no
 * self-approval, step-up, single decision) is enforced by the approval service; the UI
 * only presents and asks.
 */
@Injectable({ providedIn: 'root' })
export class ApprovalsService {
  private readonly http = inject(HttpClient);
  private readonly location = inject(BROWSER_LOCATION);
  readonly me = signal<Approver | null>(null);

  loadMe(): Observable<Approver> {
    return this.http.get<Approver>('/api/v1/me');
  }

  list(): Observable<{ items: ApprovalRequest[] }> {
    return this.http.get<{ items: ApprovalRequest[] }>('/api/v1/requests');
  }

  decide(id: string, approve: boolean, comment: string): Observable<ApprovalRequest> {
    return this.http.post<ApprovalRequest>(
      `/api/v1/requests/${encodeURIComponent(id)}/${approve ? 'approve' : 'reject'}`,
      { comment },
    );
  }

  login(stepUp = false): void {
    this.location.assign('/auth/login?returnTo=%2F' + (stepUp ? '&stepUp=1' : ''));
  }
}

const SAFE = new Set(['GET', 'HEAD', 'OPTIONS']);

/** Adds the CSRF token to same-origin, state-changing requests only. */
export const csrfInterceptor: HttpInterceptorFn = (req, next) => {
  const token = inject(ApprovalsService).me()?.csrfToken;
  const sameOrigin = req.url.startsWith('/') && !req.url.startsWith('//');
  if (SAFE.has(req.method) || !sameOrigin || !token) {
    return next(req);
  }
  return next(req.clone({ setHeaders: { [CSRF_HEADER]: token } }));
};
