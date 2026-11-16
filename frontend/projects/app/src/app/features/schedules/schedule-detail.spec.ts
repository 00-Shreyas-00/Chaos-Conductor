import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { Schedule } from '../../core/api.types';
import { AuthService } from '../../core/auth.service';
import { ScheduleDetail, describeWindow } from './schedule-detail';

const sched: Schedule = {
  id: 's1', name: 'web-monkey', clusterId: 'dev-kind-01', ownerIssuer: 'https://idp', ownerSubject: 'alice', ownerName: 'Alice',
  description: 'web pods', risk: 'Low', minIntervalSeconds: 3600, meanIntervalSeconds: 21600,
  window: { days: ['Mon', 'Tue'], from: '10:00', to: '16:00', timeZone: 'UTC' }, expiresAt: '2026-12-16T12:00:00Z', maxRuns: 0,
  runs: 1, consecutiveDenials: 0, state: 'Active', nextRunAt: '2026-11-17T11:00:00Z', createdAt: '2026-11-16T12:00:00Z',
  template: { maxDuration: '2m', steps: [{ fault: { type: 'PodKill', target: { namespace: 'demo', selector: { app: 'web' } }, podKill: { count: 1 } } }] },
};

describe('ScheduleDetail', () => {
  function setup(user: { subject: string; roles: string[] }, s: Schedule = sched) {
    TestBed.configureTestingModule({ imports: [ScheduleDetail], providers: [provideHttpClient(), provideHttpClientTesting(), provideRouter([])] });
    TestBed.inject(AuthService).user.set({ subject: user.subject, issuer: 'https://idp', roles: user.roles as never, authLevel: '1', csrfToken: 'x' });
    const fixture = TestBed.createComponent(ScheduleDetail);
    fixture.componentRef.setInput('id', 's1');
    fixture.detectChanges();
    const http = TestBed.inject(HttpTestingController);
    http.expectOne('/api/v1/schedules/s1').flush({ schedule: s, runs: [
      { id: 2, occurredAt: '2026-11-16T13:00:00Z', outcome: 'Skipped', reason: 'emergency stop engaged' },
      { id: 1, occurredAt: '2026-11-16T12:00:00Z', outcome: 'Started', experimentId: 'e1' },
    ] });
    fixture.detectChanges();
    return { fixture, http, el: fixture.nativeElement as HTMLElement };
  }

  it('describes the window and lists runs', () => {
    const { el } = setup({ subject: 'eve', roles: ['viewer'] });
    expect(describeWindow(sched)).toBe('Mon Tue 10:00–16:00 UTC · every ~6h (≥ 1h)');
    expect(el.querySelectorAll('[data-testid=run]').length).toBe(2);
    expect(el.textContent).toContain('emergency stop engaged');
    expect(el.querySelector('[data-testid=pause]')).toBeNull(); // viewers cannot pause
  });

  it('lets an approver pause, and reloads', () => {
    const { el, http, fixture } = setup({ subject: 'bob', roles: ['approver'] });
    (el.querySelector('[data-testid=pause]') as HTMLButtonElement).click();
    const req = http.expectOne('/api/v1/schedules/s1/pause');
    expect(req.request.method).toBe('POST');
    req.flush({ ...sched, state: 'Paused' });
    http.expectOne('/api/v1/schedules/s1').flush({ schedule: { ...sched, state: 'Paused', nextRunAt: undefined }, runs: [] });
    fixture.detectChanges();
    expect(el.querySelector('[data-testid=state]')?.textContent).toContain('Paused');
    expect(el.querySelector('[data-testid=resume]')).toBeNull(); // only the owner resumes
  });

  it('lets the owner resume and shows step-up when required', () => {
    const { el, http, fixture } = setup({ subject: 'alice', roles: ['experimenter'] }, { ...sched, state: 'Paused', stateReason: 'paused by bob' });
    expect(el.querySelector('[data-testid=reason]')?.textContent).toContain('paused by bob');
    (el.querySelector('[data-testid=resume]') as HTMLButtonElement).click();
    http.expectOne('/api/v1/schedules/s1/resume').flush({ code: 'step_up_required', title: 'Step-up', reasons: ['sign in again'] }, { status: 403, statusText: 'Forbidden' });
    fixture.detectChanges();
    expect(el.querySelector('[data-testid=stepup]')).not.toBeNull();
  });

  it('deletes with the DELETE method', () => {
    const { el, http } = setup({ subject: 'alice', roles: ['experimenter'] });
    (el.querySelector('[data-testid=delete]') as HTMLButtonElement).click();
    expect(http.expectOne('/api/v1/schedules/s1').request.method).toBe('DELETE');
  });
});
