import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { TestBed } from '@angular/core/testing';
import { provideRouter, Router } from '@angular/router';
import { BROWSER_LOCATION } from '../../core/auth.service';
import { ExperimentForm, parseSelector } from './experiment-form';

describe('parseSelector', () => {
  it('parses key=value pairs', () => {
    expect(parseSelector('app=web, tier=frontend')).toEqual({ app: 'web', tier: 'frontend' });
    expect(parseSelector('app.kubernetes.io/name=api')).toEqual({ 'app.kubernetes.io/name': 'api' });
  });
  it('rejects malformed or unsafe input', () => {
    for (const bad of ['', 'app', 'app=web=x', '=web', 'a b=c', 'app=we b', 'x=1,'.repeat(11), 'app=$(rm -rf /)']) {
      expect(parseSelector(bad), bad).toBeNull();
    }
  });
});

describe('ExperimentForm', () => {
  let assigned: string[];

  function setup() {
    assigned = [];
    sessionStorage.clear();
    TestBed.configureTestingModule({
      imports: [ExperimentForm],
      providers: [
        provideHttpClient(),
        provideHttpClientTesting(),
        provideRouter([]),
        { provide: BROWSER_LOCATION, useValue: { pathname: '/', search: '', assign: (u: string) => assigned.push(u) } },
      ],
    });
    const fixture = TestBed.createComponent(ExperimentForm);
    fixture.detectChanges();
    const http = TestBed.inject(HttpTestingController);
    http.expectOne('/api/v1/scenarios').flush({ items: [] });
    http.expectOne('/api/v1/clusters').flush({ items: [{ id: 'dev-kind-01', environment: 'development', locked: false, policy: null }] });
    return { fixture, http, form: fixture.componentInstance };
  }

  it('builds a request without identity or cluster fields', () => {
    const { form } = setup();
    form.steps.at(0).patchValue({ namespace: 'demo', selector: 'app=web', count: 2, grace: 5 });
    form.addWait();
    form.addCriterion({ metric: 'recovery_time', operator: 'lt', value: '30s', weight: 2 });
    const req = form.buildRequest();
    expect(req.steps[0].fault?.target).toEqual({ namespace: 'demo', selector: { app: 'web' } });
    expect(req.steps[0].fault?.podKill).toEqual({ count: 2, gracePeriodSeconds: 5 });
    expect(req.steps[1].wait?.duration).toBe('30s');
    expect(req.successCriteria?.[0]).toEqual({ metric: 'recovery_time', operator: 'lt', value: '30s', weight: 2 });
    expect(Object.keys(req)).not.toContain('requestedBy');
    expect(Object.keys(req)).not.toContain('clusterID');
  });

  it('requires typing the target namespace before submitting', () => {
    const { form, http } = setup();
    form.submit();
    http.expectNone('/api/v1/experiments');
    form.form.controls.confirmation.setValue('demo');
    expect(form.confirmationMatches()).toBe(true);
    form.submit();
    const req = http.expectOne('/api/v1/experiments');
    expect(req.request.body.confirm).toBe(true);
  });

  it('rejects invalid input client-side (the server enforces it anyway)', () => {
    const { form, http } = setup();
    form.steps.at(0).patchValue({ count: 50, selector: 'not a selector' });
    form.form.controls.confirmation.setValue('demo');
    form.submit();
    http.expectNone('/api/v1/experiments');
    expect(form.form.invalid).toBe(true);
  });

  it('shows policy errors and offers step-up re-authentication, saving the draft', () => {
    const { fixture, form, http } = setup();
    form.form.controls.confirmation.setValue('demo');
    form.submit();
    http.expectOne('/api/v1/experiments').flush(
      { title: 'Step-up authentication required', status: 403, code: 'step_up_required', reasons: ['sign in again'] },
      { status: 403, statusText: 'Forbidden' },
    );
    fixture.detectChanges();
    const el = fixture.nativeElement as HTMLElement;
    expect(el.querySelector('[data-testid=problem]')?.textContent).toContain('sign in again');
    (el.querySelector('[data-testid=stepup]') as HTMLButtonElement).click();
    expect(assigned[0]).toBe('/auth/login?stepUp=1&returnTo=%2Fexperiments%2Fnew');
    expect(JSON.parse(sessionStorage.getItem('kubechaos.experimentDraft') ?? '{}').steps.length).toBe(1);
  });

  it('navigates to the experiment after a successful submission', () => {
    const { form, http } = setup();
    const router = TestBed.inject(Router);
    const nav = vi.spyOn(router, 'navigate').mockResolvedValue(true);
    form.form.controls.confirmation.setValue('demo');
    form.submit();
    http.expectOne('/api/v1/experiments').flush({ id: 'abc', name: 'exp-1' });
    expect(nav).toHaveBeenCalledWith(['/experiments', 'abc']);
  });
});

describe('ExperimentForm schedule mode', () => {
  function setup() {
    sessionStorage.clear();
    TestBed.configureTestingModule({
      imports: [ExperimentForm],
      providers: [
        provideHttpClient(),
        provideHttpClientTesting(),
        provideRouter([]),
        { provide: BROWSER_LOCATION, useValue: { pathname: '/', search: '', assign: () => undefined } },
      ],
    });
    const fixture = TestBed.createComponent(ExperimentForm);
    fixture.detectChanges();
    const http = TestBed.inject(HttpTestingController);
    http.expectOne('/api/v1/scenarios').flush({ items: [] });
    http.expectOne('/api/v1/clusters').flush({ items: [] });
    return { fixture, http, form: fixture.componentInstance };
  }

  it('builds a schedule around the same template', () => {
    const { form } = setup();
    form.mode.set('schedule');
    form.schedule.patchValue({ name: 'web-monkey', minInterval: '1h', meanInterval: '6h', days: ['Mon', 'Wed'], from: '09:30',
      to: '15:00', timeZone: 'Europe/London', expiresInDays: 14, maxRuns: 10 });
    const now = new Date('2026-11-16T12:00:00Z');
    const req = form.buildScheduleRequest(now);
    expect(req.template.steps[0].fault?.target.namespace).toBe('demo');
    expect(req.window).toEqual({ days: ['Mon', 'Wed'], from: '09:30', to: '15:00', timeZone: 'Europe/London' });
    expect(req.expiresAt).toBe('2026-11-30T12:00:00.000Z');
    expect([req.minInterval, req.meanInterval, req.maxRuns, req.confirm]).toEqual(['1h', '6h', 10, true]);
    expect(Object.keys(req)).not.toContain('owner');
  });

  it('posts to /schedules, and not before the schedule fields are valid', () => {
    const { form, http } = setup();
    form.mode.set('schedule');
    form.form.controls.confirmation.setValue('demo');
    form.submit(); // name missing
    http.expectNone('/api/v1/schedules');
    http.expectNone('/api/v1/experiments');
    form.schedule.controls.name.setValue('web-monkey');
    form.submit();
    const req = http.expectOne('/api/v1/schedules');
    expect(req.request.method).toBe('POST');
    expect(req.request.body.name).toBe('web-monkey');
    http.expectNone('/api/v1/experiments');
  });
});
