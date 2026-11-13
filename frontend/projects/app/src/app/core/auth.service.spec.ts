import { HttpClient, provideHttpClient, withInterceptors } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { TestBed } from '@angular/core/testing';
import { AuthService, BROWSER_LOCATION, CurrentUser } from './auth.service';
import { CSRF_HEADER, csrfInterceptor } from './csrf.interceptor';

const alice: CurrentUser = {
  subject: 'sub-alice',
  issuer: 'http://localhost:8180/realms/kubechaos',
  displayName: 'Alice Experimenter',
  roles: ['experimenter'],
  authLevel: '1',
  csrfToken: 'T'.repeat(43),
};

describe('AuthService + csrfInterceptor', () => {
  let auth: AuthService;
  let http: HttpTestingController;
  let client: HttpClient;
  let assigned: string[];

  beforeEach(() => {
    assigned = [];
    TestBed.configureTestingModule({
      providers: [
        provideHttpClient(withInterceptors([csrfInterceptor])),
        provideHttpClientTesting(),
        {
          provide: BROWSER_LOCATION,
          useValue: { pathname: '/experiments', search: '?tab=mine', assign: (u: string) => assigned.push(u) },
        },
      ],
    });
    auth = TestBed.inject(AuthService);
    http = TestBed.inject(HttpTestingController);
    client = TestBed.inject(HttpClient);
  });

  afterEach(() => http.verify());

  function signIn(): void {
    auth.load();
    http.expectOne('/api/v1/me').flush(alice);
  }

  it('becomes authenticated from /api/v1/me', () => {
    signIn();
    expect(auth.state()).toBe('authenticated');
    expect(auth.user()?.roles).toEqual(['experimenter']);
  });

  it('treats 401 as anonymous and other failures as error', () => {
    auth.load();
    http.expectOne('/api/v1/me').flush(null, { status: 401, statusText: 'Unauthorized' });
    expect(auth.state()).toBe('anonymous');
    auth.load();
    http.expectOne('/api/v1/me').flush(null, { status: 503, statusText: 'Unavailable' });
    expect(auth.state()).toBe('error');
  });

  it('login navigates to /auth/login with the current path as returnTo', () => {
    auth.login();
    expect(assigned).toEqual(['/auth/login?returnTo=%2Fexperiments%3Ftab%3Dmine']);
  });

  it('adds the CSRF header only to same-origin unsafe requests', () => {
    signIn();
    client.post('/api/v1/experiments', {}).subscribe();
    expect(http.expectOne('/api/v1/experiments').request.headers.get(CSRF_HEADER)).toBe(alice.csrfToken);

    client.get('/api/v1/experiments').subscribe();
    expect(http.expectOne((r) => r.method === 'GET' && r.url === '/api/v1/experiments').request.headers.has(CSRF_HEADER)).toBe(false);

    client.post('https://evil.example/collect', {}).subscribe();
    expect(http.expectOne('https://evil.example/collect').request.headers.has(CSRF_HEADER)).toBe(false);

    client.post('//evil.example/collect', {}).subscribe();
    expect(http.expectOne('//evil.example/collect').request.headers.has(CSRF_HEADER)).toBe(false);
    http.match(() => true).forEach((r) => r.flush({}));
  });

  it('logout posts with CSRF, clears state and follows the IdP logout URL', () => {
    signIn();
    auth.logout();
    const req = http.expectOne('/auth/logout');
    expect(req.request.method).toBe('POST');
    expect(req.request.headers.get(CSRF_HEADER)).toBe(alice.csrfToken);
    req.flush({ logoutUrl: 'http://localhost:8180/realms/kubechaos/protocol/openid-connect/logout?client_id=kubechaos-api' });
    expect(auth.state()).toBe('anonymous');
    expect(auth.user()).toBeNull();
    expect(assigned).toEqual(['http://localhost:8180/realms/kubechaos/protocol/openid-connect/logout?client_id=kubechaos-api']);
  });

  it('refuses to navigate to a dangerous logout URL', () => {
    signIn();
    auth.logout();
    http.expectOne('/auth/logout').flush({ logoutUrl: 'javascript:alert(1)' });
    expect(assigned).toEqual(['/']);
  });
});
