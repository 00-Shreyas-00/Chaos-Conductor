import { DatePipe } from '@angular/common';
import { Component, OnInit, inject, signal } from '@angular/core';
import { MatButtonModule } from '@angular/material/button';
import { RouterLink } from '@angular/router';
import { Schedule } from '../../core/api.types';
import { AuthService } from '../../core/auth.service';
import { ExperimentsService } from '../../core/experiments.service';
import { describeWindow } from './schedule-detail';

@Component({
  selector: 'kc-schedule-list',
  imports: [MatButtonModule, RouterLink, DatePipe],
  template: `
    <div class="header">
      <h1>Schedules</h1>
      @if (canCreate()) {
        <a mat-flat-button routerLink="/experiments/new" data-testid="new">New schedule</a>
      }
    </div>
    <p class="hint">Scheduled chaos runs an experiment at random times inside a weekly window, so resilience is tested continuously.</p>
    @if (error()) {
      <p class="error" role="alert">{{ error() }}</p>
    }
    @for (s of items(); track s.id) {
      <a class="card" [routerLink]="['/schedules', s.id]" data-testid="schedule">
        <strong>{{ s.name }}</strong>
        <span class="state" [attr.data-state]="s.state">{{ s.state }}</span>
        <span class="muted">{{ describe(s) }}</span>
        <span class="muted">
          {{ s.runs }} run(s) · owner {{ s.ownerName || s.ownerSubject }}
          @if (s.nextRunAt) { · next {{ s.nextRunAt | date: 'short' }} }
        </span>
      </a>
    } @empty {
      @if (!error()) { <p data-testid="empty">No schedules yet.</p> }
    }
  `,
  styles: `
    .header { display: flex; justify-content: space-between; align-items: center; }
    .card { display: flex; flex-wrap: wrap; gap: 4px 12px; padding: 12px 16px; margin-bottom: 8px; text-decoration: none; color: inherit;
      border: 1px solid var(--mat-sys-outline-variant); border-radius: 12px; }
    .state { font-size: 12px; padding: 2px 8px; border-radius: 8px; background: var(--mat-sys-surface-container-high); }
    .state[data-state='Active'] { background: var(--mat-sys-primary-container); }
    .muted, .hint { color: var(--mat-sys-on-surface-variant); }
    .error { color: var(--mat-sys-error); }
  `,
})
export class ScheduleList implements OnInit {
  private readonly api = inject(ExperimentsService);
  private readonly auth = inject(AuthService);
  protected readonly items = signal<Schedule[]>([]);
  protected readonly error = signal('');
  protected readonly describe = describeWindow;

  ngOnInit(): void {
    this.api.schedules().subscribe({ next: (s) => this.items.set(s), error: () => this.error.set('Could not load schedules.') });
  }

  protected canCreate(): boolean {
    return this.auth.user()?.roles.includes('experimenter') ?? false;
  }
}
