import { provideHttpClient, withInterceptors } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { TestBed } from '@angular/core/testing';
import { App } from './app';
import { ApprovalRequest, BROWSER_LOCATION, CSRF_HEADER, csrfInterceptor } from './approvals.service';

const csrf = 'c'.repeat(43);
const me = { subject: 'bob', issuer: 'i', displayName: 'Bob', groups: ['/teams/demo/head-developers'], csrfToken: csrf };

function request(over: Partial<ApprovalRequest> = {}): ApprovalRequest {
  return {
    id: 'r1', experimentId: 'e1', clusterId: 'dev-kind-01', environment: 'development', namespaces: ['demo'],
    approverGroup: '/teams/demo/head-developers', specSha256: 'a'.repeat(64), risk: 'High', requesterSubject: 'alice',
    requesterName: 'Alice', minApprovals: 1, state: 'Pending', createdAt: '2026-11-16T10:00:00Z', expiresAt: '2026-11-17T10:00:00Z',
    decisions: [],
    spec: { maxDuration: '2m', steps: [{ fault: { type: 'PodKill', target: { namespace: 'demo', selector: { app: 'web' } }, podKill: { count: 2 } } }] },
    ...over,
  };
}

describe('Approver App', () => {
  let assign: ReturnType<typeof vi.fn>;

  async function render(items: ApprovalRequest[], meStatus = 200) {
    assign = vi.fn();
    await TestBed.configureTestingModule({
      imports: [App],
      providers: [
        provideHttpClient(withInterceptors([csrfInterceptor])),
        provideHttpClientTesting(),
        { provide: BROWSER_LOCATION, useValue: { assign } },
      ],
    }).compileComponents();
    const fixture = TestBed.createComponent(App);
    fixture.detectChanges();
    const http = TestBed.inject(HttpTestingController);
    http.expectOne('/api/v1/me').flush(meStatus === 200 ? me : {}, { status: meStatus, statusText: 'x' });
    if (meStatus === 200) {
      http.expectOne('/api/v1/requests').flush({ items });
    }
    await fixture.whenStable();
    fixture.detectChanges();
    return { fixture, http, el: fixture.nativeElement as HTMLElement };
  }

  it('offers sign-in when anonymous', async () => {
    const { el } = await render([], 401);
    (el.querySelector('[data-testid=login]') as HTMLButtonElement).click();
    expect(assign).toHaveBeenCalledWith('/auth/login?returnTo=%2F');
  });

  it('lists pending requests with their blast radius', async () => {
    const { el } = await render([request(), request({ id: 'r2', state: 'Approved' })]);
    expect(el.querySelectorAll('[data-testid=request]').length).toBe(1);
    expect(el.textContent).toContain('PodKill ×2 in demo (app=web)');
    expect(el.textContent).toContain('Alice');
    expect(el.querySelectorAll('[data-testid=decided]').length).toBe(1);
  });

  it('approves with the CSRF token and the comment', async () => {
    const { el, http, fixture } = await render([request()]);
    (el.querySelector('[data-testid=approve]') as HTMLButtonElement).click();
    const req = http.expectOne('/api/v1/requests/r1/approve');
    expect(req.request.method).toBe('POST');
    expect(req.request.headers.get(CSRF_HEADER), 'CSRF header').toBe(csrf);
    req.flush(request({ state: 'Approved' }));
    await fixture.whenStable();
    fixture.detectChanges();
    expect(el.querySelectorAll('[data-testid=request]').length).toBe(0);
  });

  it('sends the approver to a step-up login when the service requires it', async () => {
    const { el, http } = await render([request()]);
    (el.querySelector('[data-testid=reject]') as HTMLButtonElement).click();
    http.expectOne('/api/v1/requests/r1/reject').flush({ code: 'step_up_required' }, { status: 403, statusText: 'Forbidden' });
    expect(assign).toHaveBeenCalledWith('/auth/login?returnTo=%2F&stepUp=1');
  });

  it('never offers a decision on your own request', async () => {
    const { el } = await render([request({ requesterSubject: 'bob' })]);
    expect(el.querySelector('[data-testid=own]')).not.toBeNull();
    expect(el.querySelector('[data-testid=approve]')).toBeNull();
  });

  it('shows the service reason on a forbidden decision', async () => {
    const { el, http, fixture } = await render([request()]);
    (el.querySelector('[data-testid=approve]') as HTMLButtonElement).click();
    http.expectOne('/api/v1/requests/r1/approve').flush({ code: 'forbidden', reasons: ['only members may decide'] }, { status: 403, statusText: 'Forbidden' });
    await fixture.whenStable();
    fixture.detectChanges();
    expect(el.querySelector('[data-testid=error]')?.textContent).toContain('only members may decide');
  });
});
