import { HttpClient } from '@angular/common/http';
import { Injectable, inject, signal } from '@angular/core';

export type ApiReadiness = 'checking' | 'ready' | 'unavailable';

/** Reports control-plane readiness (presentation only). */
@Injectable({ providedIn: 'root' })
export class ApiStatusService {
  private readonly http = inject(HttpClient);

  readonly readiness = signal<ApiReadiness>('checking');

  refresh(): void {
    this.readiness.set('checking');
    this.http.get('/readyz').subscribe({
      next: () => this.readiness.set('ready'),
      error: () => this.readiness.set('unavailable'),
    });
  }
}
