import { HttpInterceptorFn } from '@angular/common/http';
import { inject } from '@angular/core';
import { AuthService } from './auth.service';

export const CSRF_HEADER = 'X-KubeChaos-CSRF';

const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);

/**
 * Adds the session CSRF token to state-changing requests — but only for same-origin,
 * app-relative URLs, so the token can never leak to another host.
 */
export const csrfInterceptor: HttpInterceptorFn = (req, next) => {
  const sameOrigin = req.url.startsWith('/') && !req.url.startsWith('//');
  const token = inject(AuthService).csrfToken();
  if (SAFE_METHODS.has(req.method) || !sameOrigin || !token) {
    return next(req);
  }
  return next(req.clone({ setHeaders: { [CSRF_HEADER]: token } }));
};
