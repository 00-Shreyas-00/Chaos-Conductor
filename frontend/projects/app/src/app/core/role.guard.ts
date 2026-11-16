import { inject } from '@angular/core';
import { toObservable } from '@angular/core/rxjs-interop';
import { CanActivateFn, Router } from '@angular/router';
import { filter, map, take } from 'rxjs';
import { AuthService, Role } from './auth.service';

/**
 * UX-only guard: hides pages a user cannot use. It is NOT a security control — every API call
 * is authorized by the control plane regardless of what the browser shows.
 */
export function roleGuard(...roles: Role[]): CanActivateFn {
  return () => {
    const auth = inject(AuthService);
    const router = inject(Router);
    if (auth.state() === 'checking') {
      auth.load();
    }
    return toObservable(auth.state).pipe(
      filter((s) => s !== 'checking'),
      take(1),
      map(() => {
        const user = auth.user();
        return user && user.roles.some((r) => roles.includes(r)) ? true : router.parseUrl('/');
      }),
    );
  };
}
