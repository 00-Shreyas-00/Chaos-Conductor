import { provideHttpClient, withFetch, withInterceptors } from '@angular/common/http';
import { ApplicationConfig, provideBrowserGlobalErrorListeners } from '@angular/core';
import { csrfInterceptor } from './approvals.service';

export const appConfig: ApplicationConfig = {
  providers: [
    provideBrowserGlobalErrorListeners(),
    // Same-origin only: the approval service's session cookie is HttpOnly and never visible to JS.
    provideHttpClient(withFetch(), withInterceptors([csrfInterceptor])),
  ],
};
