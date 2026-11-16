import { DatePipe } from '@angular/common';
import { HttpErrorResponse } from '@angular/common/http';
import { Component, OnInit, computed, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { MatButtonModule } from '@angular/material/button';
import { MatToolbarModule } from '@angular/material/toolbar';
import { ApprovalRequest, ApprovalsService } from './approvals.service';

type View = 'checking' | 'anonymous' | 'ready' | 'error';

@Component({
  selector: 'ka-root',
  imports: [DatePipe, FormsModule, MatButtonModule, MatToolbarModule],
  templateUrl: './app.html',
  styleUrl: './app.scss',
})
export class App implements OnInit {
  protected readonly api = inject(ApprovalsService);
  protected readonly view = signal<View>('checking');
  protected readonly requests = signal<ApprovalRequest[]>([]);
  protected readonly pending = computed(() => this.requests().filter((r) => r.state === 'Pending'));
  protected readonly decided = computed(() => this.requests().filter((r) => r.state !== 'Pending'));
  protected readonly comments: Record<string, string> = {};
  protected readonly errors = signal<Record<string, string>>({});
  protected readonly busy = signal<string | null>(null);

  ngOnInit(): void {
    this.api.loadMe().subscribe({
      next: (me) => {
        this.api.me.set(me);
        this.view.set('ready');
        this.refresh();
      },
      error: (e: HttpErrorResponse) => this.view.set(e.status === 401 ? 'anonymous' : 'error'),
    });
  }

  protected refresh(): void {
    this.api.list().subscribe({ next: (r) => this.requests.set(r.items), error: () => this.view.set('error') });
  }

  protected isOwn(r: ApprovalRequest): boolean {
    return r.requesterSubject === this.api.me()?.subject;
  }

  protected faults(r: ApprovalRequest): string[] {
    return r.spec.steps.map((s) =>
      s.fault
        ? `${s.fault.type} ×${s.fault.podKill?.count ?? 1} in ${s.fault.target.namespace} (${Object.entries(s.fault.target.selector)
            .map(([k, v]) => `${k}=${v}`)
            .join(', ')})`
        : `wait ${s.wait?.duration}`,
    );
  }

  protected decide(r: ApprovalRequest, approve: boolean): void {
    this.busy.set(r.id);
    this.api.decide(r.id, approve, this.comments[r.id] ?? '').subscribe({
      next: (updated) => {
        this.busy.set(null);
        this.requests.update((all) => all.map((x) => (x.id === updated.id ? updated : x)));
      },
      error: (e: HttpErrorResponse) => {
        this.busy.set(null);
        if (e.status === 403 && e.error?.code === 'step_up_required') {
          // Decisions need a fresh interactive login (step-up); come back here afterwards.
          this.api.login(true);
          return;
        }
        const reason = e.error?.reasons?.[0] ?? e.error?.title ?? 'Request failed';
        this.errors.update((m) => ({ ...m, [r.id]: reason }));
      },
    });
  }
}
