import { DatePipe } from '@angular/common';
import { Component, OnDestroy, OnInit, computed, inject, input, signal } from '@angular/core';
import { MatButtonModule } from '@angular/material/button';
import { MatCardModule } from '@angular/material/card';
import { RouterLink } from '@angular/router';
import { Subscription } from 'rxjs';
import { Experiment, TimelineEvent } from '../../core/api.types';
import { AuthService } from '../../core/auth.service';
import { ExperimentsService } from '../../core/experiments.service';

const TERMINAL = ['Completed', 'Failed', 'Aborted', 'Rejected'];

@Component({
  selector: 'kc-experiment-detail',
  imports: [MatCardModule, MatButtonModule, RouterLink, DatePipe],
  templateUrl: './experiment-detail.html',
  styleUrl: './experiment-detail.scss',
})
export class ExperimentDetail implements OnInit, OnDestroy {
  /** Route parameter (component input binding). */
  readonly id = input.required<string>();

  private readonly api = inject(ExperimentsService);
  private readonly auth = inject(AuthService);
  private sub?: Subscription;

  protected readonly experiment = signal<Experiment | null>(null);
  protected readonly timeline = signal<TimelineEvent[]>([]);
  protected readonly error = signal<string | null>(null);
  protected readonly live = signal(false);
  protected readonly terminal = computed(() => TERMINAL.includes(this.experiment()?.phase ?? ''));
  protected readonly canCancel = computed(() => {
    const e = this.experiment();
    const u = this.auth.user();
    if (!e || !u || this.terminal() || e.cancelRequested || e.state !== 'Submitted') return false;
    if (u.roles.includes('admin') || u.roles.includes('approver')) return true;
    return u.roles.includes('experimenter') && u.subject === e.requesterSubject && u.issuer === e.requesterIssuer;
  });

  ngOnInit(): void {
    this.api.get(this.id()).subscribe({
      next: ({ experiment, timeline }) => {
        this.experiment.set(experiment);
        this.timeline.set(timeline);
        if (!this.terminal()) this.subscribeLive();
      },
      error: (e) => this.error.set(e.status === 404 ? 'Experiment not found.' : 'Could not load the experiment.'),
    });
  }

  private subscribeLive(): void {
    this.live.set(true);
    this.sub = this.api.live(this.id()).subscribe((m) => {
      if (m.type === 'experiment') {
        this.experiment.set(m.data);
        if (this.terminal()) {
          this.live.set(false);
          this.sub?.unsubscribe();
        }
      } else if (m.type === 'timeline') {
        this.timeline.update((t) => (t.some((x) => x.id === m.data.id) ? t : [...t, m.data]));
      } else {
        this.reload();
      }
    });
  }

  private reload(): void {
    this.api.get(this.id()).subscribe(({ experiment, timeline }) => {
      this.experiment.set(experiment);
      this.timeline.set(timeline);
    });
  }

  protected selectorText(sel: Record<string, string>): string {
    return Object.entries(sel)
      .map(([k, v]) => `${k}=${v}`)
      .join(',');
  }

  cancel(): void {
    this.api.cancel(this.id()).subscribe({
      next: (e) => this.experiment.update((cur) => (cur ? { ...cur, cancelRequested: e.cancelRequested } : cur)),
      error: () => this.error.set('Cancellation failed.'),
    });
  }

  ngOnDestroy(): void {
    this.sub?.unsubscribe();
  }
}
