import { DOCUMENT } from '@angular/common';
import { HttpClient, HttpErrorResponse } from '@angular/common/http';
import { Injectable, InjectionToken, computed, inject, signal } from '@angular/core';

export type Role = 'viewer' | 'experimenter' | 'approver' | 'admin' | 'auditor';

export interface CurrentUser {
  subject: string;
  issuer: string;
  displayName?: string;
  roles: Role[];
  authLevel: string;
  csrfToken: string;
}

export type SessionState = 'checking' | 'anonymous' | 'authenticated' | 'error';

/** Indirection over window.location so navigation is testable. */
export const BROWSER_LOCATION = new InjectionToken<Pick<Location, 'assign' | 'pathname' | 'search'>>(
  'BROWSER_LOCATION',
  { factory: () => inject(DOCUMENT).location },
);

/**
 * Session state for the UI. The browser never sees OIDC tokens: login and logout are
 * full-page navigations to the control plane, which keeps tokens server-side and sets an
 * HttpOnly cookie. Roles here drive presentation only — the API authorizes every request.
 */
@Injectable({ providedIn: 'root' })
export class AuthService {
  private readonly http = inject(HttpClient);
  private readonly location = inject(BROWSER_LOCATION);

  readonly state = signal<SessionState>('checking');
  readonly user = signal<CurrentUser | null>(null);
  readonly csrfToken = computed(() => this.user()?.csrfToken ?? null);

  load(): void {
    this.state.set('checking');
    this.http.get<CurrentUser>('/api/v1/me').subscribe({
      next: (u) => {
        this.user.set(u);
        this.state.set('authenticated');
      },
      error: (err: HttpErrorResponse) => {
        this.user.set(null);
        this.state.set(err.status === 401 ? 'anonymous' : 'error');
      },
    });
  }

  login(): void {
    const here = this.location.pathname + this.location.search;
    this.location.assign('/auth/login?returnTo=' + encodeURIComponent(here));
  }

  logout(): void {
    this.http.post<{ logoutUrl: string }>('/auth/logout', null).subscribe({
      next: ({ logoutUrl }) => this.finishLogout(logoutUrl),
      error: () => this.finishLogout('/'),
    });
  }

  private finishLogout(target: string): void {
    this.user.set(null);
    this.state.set('anonymous');
    // Only follow the IdP logout URL the server returned if it is an absolute http(s) URL or
    // an app-relative path; never a javascript: or protocol-relative URL.
    const safe = /^https?:\/\//.test(target) || (target.startsWith('/') && !target.startsWith('//'));
    this.location.assign(safe ? target : '/');
  }
}
