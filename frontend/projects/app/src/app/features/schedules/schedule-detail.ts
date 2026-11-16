import { DatePipe } from '@angular/common';
import { HttpErrorResponse } from '@angular/common/http';
import { Component, OnInit, computed, inject, input, signal } from '@angular/core';
import { MatButtonModule } from '@angular/material/button';
import { RouterLink } from '@angular/router';
import { ApiProblem, Schedule, ScheduleRun } from '../../core/api.types';
import { AuthService, BROWSER_LOCATION } from '../../core/auth.service';
import { ExperimentsService } from '../../core/experiments.service';

/** "Mon–Fri 10:00–16:00 Europe/London · every ~12h (≥ 4h)" */
export function describeWindow(s: Schedule): string {
  const dur = (sec: number) => (sec % 3600 === 0 ? `${sec / 3600}h` : sec % 60 === 0 ? `${sec / 60}m` : `${sec}s`);
  return `${s.window.days.join(' ')} ${s.window.from}–${s.window.to} ${s.window.timeZone} · every ~${dur(s.meanIntervalSeconds)} (≥ ${dur(s.minIntervalSeconds)})`;
}

@Component({
  selector: 'kc-schedule-detail',
  imports: [MatButtonModule, RouterLink, DatePipe],
  template: `
    <a routerLink="/schedules">← Schedules</a>
    @if (problem(); as p) {
      <div class="problem" role="alert" data-testid="problem">
        <strong>{{ p.title }}</strong>
        @for (r of p.reasons ?? []; track r) { <div>{{ r }}</div> }
        @if (p.code === 'step_up_required') {
          <button mat-flat-button type="button" (click)="stepUp()" data-testid="stepup">Sign in again to confirm</button>
        }
      </div>
    }
    @if (schedule(); as s) {
      <div class="header">
        <h1>{{ s.name }}</h1>
        <span class="state" data-testid="state">{{ s.state }}</span>
        <span class="spacer"></span>
        @if (s.state === 'Active' && canPause()) {
          <button mat-stroked-button type="button" (click)="act('pause')" data-testid="pause">Pause</button>
        }
        @if (s.state === 'Paused' && isOwner()) {
          <button mat-flat-button type="button" (click)="act('resume')" data-testid="resume">Resume</button>
        }
        @if (s.state !== 'Deleted' && canPause()) {
          <button mat-button type="button" (click)="act('delete')" data-testid="delete">Delete</button>
        }
      </div>
      @if (s.stateReason) { <p class="muted" data-testid="reason">{{ s.stateReason }}</p> }
      <p>{{ s.description || 'No description' }}</p>
      <ul class="facts">
        <li>{{ window() }}</li>
        <li>Owner {{ s.ownerName || s.ownerSubject }} · risk {{ s.risk }} · max duration {{ s.template.maxDuration }}</li>
        <li>{{ s.runs }} run(s){{ s.maxRuns ? ' of ' + s.maxRuns : '' }} · expires {{ s.expiresAt | date: 'medium' }}</li>
        @if (s.nextRunAt) { <li data-testid="next">Next run (randomised) {{ s.nextRunAt | date: 'medium' }}</li> }
      </ul>
      <h2>Runs</h2>
      @for (r of runs(); track r.id) {
        <div class="run" data-testid="run">
          <span class="outcome" [attr.data-outcome]="r.outcome">{{ r.outcome }}</span>
          <span class="muted">{{ r.occurredAt | date: 'medium' }}</span>
          @if (r.experimentId) { <a [routerLink]="['/experiments', r.experimentId]">experiment</a> }
          @if (r.reason) { <span>{{ r.reason }}</span> }
        </div>
      } @empty {
        <p class="muted" data-testid="no-runs">No runs yet.</p>
      }
    }
  `,
  styles: `
    .header { display: flex; align-items: center; gap: 12px; flex-wrap: wrap; }
    .spacer { flex: 1; }
    .state, .outcome { font-size: 12px; padding: 2px 8px; border-radius: 8px; background: var(--mat-sys-surface-container-high); }
    .outcome[data-outcome='Denied'], .outcome[data-outcome='Failed'] { background: var(--mat-sys-error-container); }
    .run { display: flex; gap: 12px; flex-wrap: wrap; padding: 6px 0; border-bottom: 1px solid var(--mat-sys-outline-variant); }
    .muted { color: var(--mat-sys-on-surface-variant); }
    .problem { padding: 12px 16px; border-radius: 8px; background: var(--mat-sys-error-container); margin: 8px 0; }
  `,
})
export class ScheduleDetail implements OnInit {
  readonly id = input.required<string>();
  private readonly api = inject(ExperimentsService);
  private readonly auth = inject(AuthService);
  private readonly location = inject(BROWSER_LOCATION);
  protected readonly schedule = signal<Schedule | null>(null);
  protected readonly runs = signal<ScheduleRun[]>([]);
  protected readonly problem = signal<ApiProblem | null>(null);
  protected readonly window = computed(() => (this.schedule() ? describeWindow(this.schedule()!) : ''));

  ngOnInit(): void {
    this.load();
  }

  private load(): void {
    this.api.schedule(this.id()).subscribe({
      next: ({ schedule, runs }) => {
        this.schedule.set(schedule);
        this.runs.set(runs);
      },
      error: (e: HttpErrorResponse) => this.problem.set({ title: e.status === 404 ? 'Schedule not found' : 'Could not load the schedule', status: e.status }),
    });
  }

  protected isOwner(): boolean {
    const u = this.auth.user();
    const s = this.schedule();
    return !!u && !!s && u.subject === s.ownerSubject && u.issuer === s.ownerIssuer;
  }

  /** Owners, approvers and admins may stop a schedule (stopping is cheap to allow). */
  protected canPause(): boolean {
    return this.isOwner() || (this.auth.user()?.roles.some((r) => r === 'approver' || r === 'admin') ?? false);
  }

  protected act(action: 'pause' | 'resume' | 'delete'): void {
    this.problem.set(null);
    this.api.scheduleAction(this.id(), action).subscribe({
      next: () => this.load(),
      error: (e: HttpErrorResponse) =>
        this.problem.set(typeof e.error === 'object' && e.error ? e.error : { title: 'Request failed', status: e.status }),
    });
  }

  protected stepUp(): void {
    this.location.assign('/auth/login?stepUp=1&returnTo=' + encodeURIComponent(`/schedules/${this.id()}`));
  }
}
