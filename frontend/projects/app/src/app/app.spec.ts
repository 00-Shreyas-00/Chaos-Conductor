import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { App } from './app';

describe('App', () => {
  async function render(me: { status: number; body: object }) {
    await TestBed.configureTestingModule({
      imports: [App],
      providers: [provideRouter([]), provideHttpClient(), provideHttpClientTesting()],
    }).compileComponents();
    const fixture = TestBed.createComponent(App);
    fixture.detectChanges();
    TestBed.inject(HttpTestingController)
      .expectOne('/api/v1/me')
      .flush(me.body, { status: me.status, statusText: me.status === 200 ? 'OK' : 'Unauthorized' });
    await fixture.whenStable();
    fixture.detectChanges();
    return fixture.nativeElement as HTMLElement;
  }

  it('renders brand, navigation and a sign-in button when anonymous', async () => {
    const el = await render({ status: 401, body: {} });
    expect(el.querySelector('.brand')?.textContent).toContain('KubeChaos');
    expect(el.querySelector('nav a')?.textContent).toContain('Overview');
    expect(el.querySelector('[data-testid=login]')).not.toBeNull();
    expect(el.querySelector('[data-testid=logout]')).toBeNull();
  });

  it('shows the user, roles and sign-out when authenticated', async () => {
    const el = await render({
      status: 200,
      body: { subject: 's', issuer: 'i', displayName: 'Bob Approver', roles: ['approver'], authLevel: '1', csrfToken: 'x'.repeat(43) },
    });
    expect(el.querySelector('[data-testid=user]')?.textContent).toContain('Bob Approver');
    expect(el.querySelector('[data-testid=user]')?.textContent).toContain('approver');
    expect(el.querySelector('[data-testid=logout]')).not.toBeNull();
  });
});
