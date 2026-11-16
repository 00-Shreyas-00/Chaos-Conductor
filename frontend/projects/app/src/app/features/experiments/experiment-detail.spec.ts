import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { Experiment } from '../../core/api.types';
import { AuthService } from '../../core/auth.service';
import { EVENT_SOURCE } from '../../core/experiments.service';
import { ExperimentDetail } from './experiment-detail';

/** Minimal EventSource stand-in that tests can push events into. */
class FakeEventSource {
  listeners: Record<string, ((e: MessageEvent) => void)[]> = {};
  closed = false;
  constructor(readonly url: string) {}
  addEventListener(t: string, h: (e: MessageEvent) => void) {
    (this.listeners[t] ??= []).push(h);
  }
  removeEventListener() {}
  close() {
    this.closed = true;
  }
  emit(type: string, data: unknown) {
    this.listeners[type]?.forEach((h) => h(new MessageEvent(type, { data: JSON.stringify(data) })));
  }
}

const base: Experiment = {
  id: 'e1', name: 'exp-0123456789ab', clusterId: 'dev-kind-01', requesterIssuer: 'https://idp', requesterSubject: 'alice',
  description: 'kill one', risk: 'Medium', state: 'Submitted', phase: 'Running', cancelRequested: false, createdAt: '2026-11-16T12:00:00Z',
  spec: { clusterID: 'dev-kind-01', maxDuration: '2m', steps: [{ fault: { type: 'PodKill', target: { namespace: 'demo', selector: { app: 'web' } }, podKill: { count: 1 } } }] },
  status: { phase: 'Running', steps: [{ phase: 'Observing' }] },
};

describe('ExperimentDetail', () => {
  let source: FakeEventSource;

  function setup(user: { subject: string; roles: string[] }) {
    TestBed.configureTestingModule({
      imports: [ExperimentDetail],
      providers: [
        provideHttpClient(),
        provideHttpClientTesting(),
        provideRouter([]),
        { provide: EVENT_SOURCE, useValue: (url: string) => (source = new FakeEventSource(url)) },
      ],
    });
    const auth = TestBed.inject(AuthService);
    auth.user.set({ subject: user.subject, issuer: 'https://idp', roles: user.roles as never, authLevel: '1', csrfToken: 'x' });
    auth.state.set('authenticated');
    const fixture = TestBed.createComponent(ExperimentDetail);
    fixture.componentRef.setInput('id', 'e1');
    fixture.detectChanges();
    const http = TestBed.inject(HttpTestingController);
    http.expectOne('/api/v1/experiments/e1').flush({ experiment: base, timeline: [{ id: 1, occurredAt: '2026-11-16T12:00:01Z', type: 'Started', message: 'Experiment started' }] });
    fixture.detectChanges();
    return { fixture, http, el: fixture.nativeElement as HTMLElement };
  }

  it('applies live timeline and state updates, then stops streaming when finished', () => {
    const { fixture, el } = setup({ subject: 'alice', roles: ['experimenter'] });
    expect(source.url).toBe('/api/v1/experiments/e1/events');
    expect(el.querySelector('[data-testid=live]')).not.toBeNull();

    source.emit('timeline', { id: 2, occurredAt: '2026-11-16T12:00:02Z', type: 'PodTerminated', message: 'pod terminated' });
    source.emit('timeline', { id: 2, occurredAt: '2026-11-16T12:00:02Z', type: 'PodTerminated', message: 'pod terminated' }); // duplicate
    source.emit('experiment', { ...base, phase: 'Completed', status: { phase: 'Completed', result: 'Passed', score: 100, criteria: [
      { metric: 'available_replicas', operator: 'ge', expected: '3', observed: '3', passed: true, weight: 1 }] } });
    fixture.detectChanges();

    expect(el.querySelectorAll('[data-testid=timeline] li').length).toBe(2);
    expect(el.querySelector('[data-testid=phase]')?.textContent).toContain('Completed');
    expect(el.querySelector('[data-testid=score]')?.textContent).toContain('100/100');
    expect(source.closed).toBe(true);
    expect(el.querySelector('[data-testid=cancel]')).toBeNull();
  });

  it('lets the requester cancel and hides cancel from other experimenters', () => {
    const owner = setup({ subject: 'alice', roles: ['experimenter'] });
    (owner.el.querySelector('[data-testid=cancel]') as HTMLButtonElement).click();
    owner.http.expectOne((r) => r.url === '/api/v1/experiments/e1/cancel' && r.method === 'POST').flush({ ...base, cancelRequested: true });
    owner.fixture.detectChanges();
    expect(owner.el.querySelector('[data-testid=cancelling]')).not.toBeNull();
  });

  it('hides cancel from a different experimenter (UX; the API enforces it)', () => {
    TestBed.resetTestingModule();
    const other = setup({ subject: 'bob', roles: ['experimenter'] });
    expect(other.el.querySelector('[data-testid=cancel]')).toBeNull();
  });
});
