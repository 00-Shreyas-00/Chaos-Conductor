import { HttpClient, HttpErrorResponse } from '@angular/common/http';
import { Injectable, inject, signal } from '@angular/core';

export type ApiReadiness = 'checking' | 'ready' | 'unavailable';
export type SessionState = 'checking' | 'anonymous' | 'authenticated' | 'error';

/**
 * Reports control-plane readiness and whether the browser has a session.
 *
 * Presentation only: the SPA never decides what a user may do. Every security decision is
 * made (again) by the control plane and the operator.
 */
@Injectable({ providedIn: 'root' })
export class ApiStatusService {
  private readonly http = inject(HttpClient);

  readonly readiness = signal<ApiReadiness>('checking');
  readonly session = signal<SessionState>('checking');

  refresh(): void {
    this.readiness.set('checking');
    this.session.set('checking');

    this.http.get('/readyz').subscribe({
      next: () => this.readiness.set('ready'),
      error: () => this.readiness.set('unavailable'),
    });

    this.http.get('/api/v1/me').subscribe({
      next: () => this.session.set('authenticated'),
      error: (err: HttpErrorResponse) => this.session.set(err.status === 401 ? 'anonymous' : 'error'),
    });
  }
}
