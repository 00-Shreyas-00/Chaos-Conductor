import { DatePipe } from '@angular/common';
import { Component, OnInit, inject, signal } from '@angular/core';
import { FormControl, ReactiveFormsModule, Validators } from '@angular/forms';
import { MatButtonModule } from '@angular/material/button';
import { MatCardModule } from '@angular/material/card';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatInputModule } from '@angular/material/input';
import { LockState } from '../../core/api.types';
import { ExperimentsService } from '../../core/experiments.service';

/** Emergency stop (admin). Engaging is allowed from the web; unlocking is CLI-only (D8). */
@Component({
  selector: 'kc-admin',
  imports: [ReactiveFormsModule, MatFormFieldModule, MatInputModule, MatButtonModule, MatCardModule, DatePipe],
  template: `
    <h1>Emergency stop</h1>
    @if (state(); as s) {
      @if (s.locked) {
        <mat-card appearance="outlined" class="locked" data-testid="locked">
          <mat-card-content>
            <strong>The emergency stop is engaged.</strong> No experiment can start; running ones were aborted.
            @for (l of s.locks; track l.name) {
              <div>{{ l.name }} — {{ l.reason }} (by {{ l.engagedBy }}, {{ l.since | date: 'medium' }})</div>
            }
            <p class="hint">Unlocking is only possible on the control node: <code>kubechaosctl unlock --yes</code></p>
          </mat-card-content>
        </mat-card>
      } @else {
        <p data-testid="unlocked">Experiments may run (subject to cluster policy).</p>
      }
      <form (ngSubmit)="engage()" class="form">
        <mat-form-field appearance="outline" class="reason">
          <mat-label>Reason</mat-label>
          <input matInput [formControl]="reason" maxlength="512" data-testid="reason" />
        </mat-form-field>
        <button mat-flat-button color="warn" type="submit" [disabled]="reason.invalid || busy()" data-testid="engage">Stop all experiments</button>
      </form>
    }
    @if (error()) { <p class="error" role="alert">{{ error() }}</p> }
  `,
  styles: `
    .locked { border-color: var(--mat-sys-error); margin-bottom: 16px; }
    .form { display: flex; gap: 8px; align-items: baseline; flex-wrap: wrap; }
    .reason { flex: 1 1 320px; }
    .hint { color: var(--mat-sys-on-surface-variant); }
    .error { color: var(--mat-sys-error); }
  `,
})
export class Admin implements OnInit {
  private readonly api = inject(ExperimentsService);
  protected readonly state = signal<LockState | null>(null);
  protected readonly error = signal<string | null>(null);
  protected readonly busy = signal(false);
  readonly reason = new FormControl('', { nonNullable: true, validators: [Validators.required, Validators.minLength(3), Validators.maxLength(512)] });

  ngOnInit(): void {
    this.refresh();
  }

  refresh(): void {
    this.api.lock().subscribe({ next: (s) => this.state.set(s), error: () => this.error.set('Could not load lock state.') });
  }

  engage(): void {
    if (this.reason.invalid) return;
    this.busy.set(true);
    this.api.engageLock(this.reason.value).subscribe({
      next: () => {
        this.busy.set(false);
        this.reason.reset();
        this.refresh();
      },
      error: () => {
        this.busy.set(false);
        this.error.set('Could not engage the emergency stop. Use kubechaosctl emergency-stop on the control node.');
      },
    });
  }
}
