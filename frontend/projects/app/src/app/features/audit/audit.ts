import { DatePipe } from '@angular/common';
import { Component, OnInit, inject, signal } from '@angular/core';
import { MatButtonModule } from '@angular/material/button';
import { MatTableModule } from '@angular/material/table';
import { AuditRecord } from '../../core/api.types';
import { ExperimentsService } from '../../core/experiments.service';

/** Read-only audit log (auditor). There is no API to modify or delete audit records. */
@Component({
  selector: 'kc-audit',
  imports: [MatTableModule, MatButtonModule, DatePipe],
  template: `
    <div class="header">
      <h1>Audit log</h1>
      <button mat-stroked-button type="button" (click)="verify()" data-testid="verify">Verify hash chain</button>
    </div>
    @if (verification()) { <p class="ok" data-testid="verified">{{ verification() }}</p> }
    @if (error()) { <p class="error" role="alert">{{ error() }}</p> }
    <table mat-table [dataSource]="records()" class="table">
      <ng-container matColumnDef="seq"><th mat-header-cell *matHeaderCellDef>#</th><td mat-cell *matCellDef="let r">{{ r.seq }}</td></ng-container>
      <ng-container matColumnDef="time"><th mat-header-cell *matHeaderCellDef>Time</th><td mat-cell *matCellDef="let r">{{ r.occurredAt | date: 'medium' }}</td></ng-container>
      <ng-container matColumnDef="action"><th mat-header-cell *matHeaderCellDef>Action</th><td mat-cell *matCellDef="let r">{{ r.action }}</td></ng-container>
      <ng-container matColumnDef="actor"><th mat-header-cell *matHeaderCellDef>Actor</th><td mat-cell *matCellDef="let r">{{ r.actorName || r.actorSubject || '—' }}</td></ng-container>
      <ng-container matColumnDef="decision"><th mat-header-cell *matHeaderCellDef>Decision</th><td mat-cell *matCellDef="let r">{{ r.decision || '—' }}</td></ng-container>
      <ng-container matColumnDef="detail"><th mat-header-cell *matHeaderCellDef>Detail</th>
        <td mat-cell *matCellDef="let r">{{ r.result || '' }} {{ (r.decisionReasons || []).join('; ') }}</td></ng-container>
      <tr mat-header-row *matHeaderRowDef="columns"></tr>
      <tr mat-row *matRowDef="let row; columns: columns" data-testid="audit-row"></tr>
    </table>
    @if (records().length >= 100) {
      <button mat-button type="button" (click)="more()">Older events</button>
    }
  `,
  styles: `
    .header { display: flex; justify-content: space-between; align-items: center; }
    .table { width: 100%; }
    .ok { color: var(--mat-sys-primary); }
    .error { color: var(--mat-sys-error); }
  `,
})
export class Audit implements OnInit {
  private readonly api = inject(ExperimentsService);
  protected readonly records = signal<AuditRecord[]>([]);
  protected readonly verification = signal<string | null>(null);
  protected readonly error = signal<string | null>(null);
  protected readonly columns = ['seq', 'time', 'action', 'actor', 'decision', 'detail'];

  ngOnInit(): void {
    this.api.audit().subscribe({ next: (r) => this.records.set(r), error: () => this.error.set('Could not load the audit log.') });
  }

  more(): void {
    const last = this.records().at(-1);
    if (!last) return;
    this.api.audit(last.seq).subscribe((r) => this.records.update((cur) => [...cur, ...r]));
  }

  verify(): void {
    this.verification.set(null);
    this.error.set(null);
    this.api.verifyAudit().subscribe({
      next: (v) => this.verification.set(`Chain intact: ${v.events} events, head ${v.head.slice(0, 16)}…`),
      error: (e) => this.error.set('Verification FAILED: ' + (e.error?.reasons?.[0] ?? 'unknown error')),
    });
  }
}
