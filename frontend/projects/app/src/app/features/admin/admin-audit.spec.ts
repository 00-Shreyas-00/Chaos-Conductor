import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { TestBed } from '@angular/core/testing';
import { Audit } from '../audit/audit';
import { Admin } from './admin';

describe('Admin (emergency stop)', () => {
  it('engages the lock with a reason and shows that unlocking is CLI-only', () => {
    TestBed.configureTestingModule({ imports: [Admin], providers: [provideHttpClient(), provideHttpClientTesting()] });
    const fixture = TestBed.createComponent(Admin);
    fixture.detectChanges();
    const http = TestBed.inject(HttpTestingController);
    http.expectOne('/api/v1/system/lock').flush({ locked: false, locks: [] });
    fixture.detectChanges();
    const el = fixture.nativeElement as HTMLElement;
    expect(el.querySelector('[data-testid=unlocked]')).not.toBeNull();

    fixture.componentInstance.reason.setValue('incident 42');
    fixture.componentInstance.engage();
    const post = http.expectOne((r) => r.url === '/api/v1/admin/lock' && r.method === 'POST');
    expect(post.request.body).toEqual({ reason: 'incident 42' });
    post.flush({ locked: true, lock: 'web-emergency-stop-1' });
    http.expectOne('/api/v1/system/lock').flush({ locked: true, locks: [{ name: 'l1', reason: 'incident 42', engagedBy: 'web:carol', since: '2026-11-16T12:00:00Z' }] });
    fixture.detectChanges();
    expect(el.querySelector('[data-testid=locked]')?.textContent).toContain('kubechaosctl unlock');
    http.verify();
  });

  it('does not submit without a reason', () => {
    TestBed.configureTestingModule({ imports: [Admin], providers: [provideHttpClient(), provideHttpClientTesting()] });
    const fixture = TestBed.createComponent(Admin);
    fixture.detectChanges();
    const http = TestBed.inject(HttpTestingController);
    http.expectOne('/api/v1/system/lock').flush({ locked: false, locks: [] });
    fixture.componentInstance.engage();
    http.expectNone('/api/v1/admin/lock');
  });
});

describe('Audit', () => {
  it('lists events and reports a broken chain', () => {
    TestBed.configureTestingModule({ imports: [Audit], providers: [provideHttpClient(), provideHttpClientTesting()] });
    const fixture = TestBed.createComponent(Audit);
    fixture.detectChanges();
    const http = TestBed.inject(HttpTestingController);
    http.expectOne('/api/v1/audit?limit=100').flush({ items: [{ seq: 2, id: 'a', occurredAt: '2026-11-16T12:00:00Z', action: 'experiment.create', actorSubject: 'alice', decision: 'allow', hash: 'h' }] });
    fixture.detectChanges();
    const el = fixture.nativeElement as HTMLElement;
    expect(el.querySelectorAll('[data-testid=audit-row]').length).toBe(1);

    fixture.componentInstance.verify();
    http.expectOne('/api/v1/audit/verify').flush({ title: 'failed', status: 409, reasons: ['hash mismatch at seq 2'] }, { status: 409, statusText: 'Conflict' });
    fixture.detectChanges();
    expect(el.textContent).toContain('Verification FAILED: hash mismatch at seq 2');
  });
});
