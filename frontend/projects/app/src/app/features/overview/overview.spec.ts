import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { TestBed } from '@angular/core/testing';
import { AuthService } from '../../core/auth.service';
import { Overview } from './overview';

describe('Overview', () => {
  function setup() {
    TestBed.configureTestingModule({
      imports: [Overview],
      providers: [provideHttpClient(), provideHttpClientTesting()],
    });
    const fixture = TestBed.createComponent(Overview);
    const http = TestBed.inject(HttpTestingController);
    return { fixture, http, el: fixture.nativeElement as HTMLElement };
  }

  it('shows readiness and anonymous session', async () => {
    const { fixture, http, el } = setup();
    fixture.detectChanges();
    TestBed.inject(AuthService).load();
    http.expectOne('/readyz').flush({ status: 'ready' });
    http.expectOne('/api/v1/me').flush({}, { status: 401, statusText: 'Unauthorized' });
    await fixture.whenStable();
    fixture.detectChanges();
    expect(el.querySelector('[data-testid=readiness]')?.textContent).toContain('Ready');
    expect(el.querySelector('[data-testid=session]')?.textContent).toContain('Not signed in');
    expect(el.querySelector('[data-testid=login-error]')).toBeNull();
    http.verify();
  });

  it('shows the signed-in user and roles', async () => {
    const { fixture, http, el } = setup();
    fixture.detectChanges();
    TestBed.inject(AuthService).load();
    http.expectOne('/readyz').flush({ status: 'ready' });
    http.expectOne('/api/v1/me').flush({
      subject: 's', issuer: 'i', displayName: 'Carol Admin', roles: ['admin'], authLevel: '1', csrfToken: 'x'.repeat(43),
    });
    await fixture.whenStable();
    fixture.detectChanges();
    expect(el.querySelector('[data-testid=session]')?.textContent).toContain('Carol Admin');
    expect(el.querySelector('[data-testid=roles]')?.textContent).toContain('admin');
    http.verify();
  });

  it('shows a login error banner from the query parameter', async () => {
    const { fixture, http, el } = setup();
    fixture.componentRef.setInput('loginError', '1');
    fixture.detectChanges();
    http.expectOne('/readyz').flush({ status: 'ready' });
    await fixture.whenStable();
    expect(el.querySelector('[data-testid=login-error]')?.textContent).toContain('Sign-in failed');
  });
});
