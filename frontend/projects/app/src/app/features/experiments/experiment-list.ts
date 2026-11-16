import { DatePipe } from '@angular/common';
import { Component, OnInit, inject, signal } from '@angular/core';
import { MatButtonModule } from '@angular/material/button';
import { MatTableModule } from '@angular/material/table';
import { RouterLink } from '@angular/router';
import { Experiment } from '../../core/api.types';
import { AuthService } from '../../core/auth.service';
import { ExperimentsService } from '../../core/experiments.service';

@Component({
  selector: 'kc-experiment-list',
  imports: [MatTableModule, MatButtonModule, RouterLink, DatePipe],
  template: `
    <div class="header">
      <h1>Experiments</h1>
      @if (canCreate()) {
        <a mat-flat-button routerLink="/experiments/new" data-testid="new">New experiment</a>
      }
    </div>
    @if (error()) {
      <p class="error" role="alert">{{ error() }}</p>
    }
    @if (items().length === 0 && !error()) {
      <p data-testid="empty">No experiments yet.</p>
    } @else {
      <table mat-table [dataSource]="items()" class="table">
        <ng-container matColumnDef="name">
          <th mat-header-cell *matHeaderCellDef>Name</th>
          <td mat-cell *matCellDef="let e"><a [routerLink]="['/experiments', e.id]">{{ e.name }}</a></td>
        </ng-container>
        <ng-container matColumnDef="description">
          <th mat-header-cell *matHeaderCellDef>Description</th>
          <td mat-cell *matCellDef="let e">{{ e.description || '—' }}</td>
        </ng-container>
        <ng-container matColumnDef="requester">
          <th mat-header-cell *matHeaderCellDef>Requested by</th>
          <td mat-cell *matCellDef="let e">{{ e.requesterName || e.requesterSubject }}</td>
        </ng-container>
        <ng-container matColumnDef="phase">
          <th mat-header-cell *matHeaderCellDef>Phase</th>
          <td mat-cell *matCellDef="let e"><span class="phase" [attr.data-phase]="e.phase">{{ e.phase || e.state }}</span></td>
        </ng-container>
        <ng-container matColumnDef="result">
          <th mat-header-cell *matHeaderCellDef>Result</th>
          <td mat-cell *matCellDef="let e">{{ e.result || '—' }}@if (e.score !== undefined && e.score !== null) { ({{ e.score }}/100) }</td>
        </ng-container>
        <ng-container matColumnDef="created">
          <th mat-header-cell *matHeaderCellDef>Created</th>
          <td mat-cell *matCellDef="let e">{{ e.createdAt | date: 'medium' }}</td>
        </ng-container>
        <tr mat-header-row *matHeaderRowDef="columns"></tr>
        <tr mat-row *matRowDef="let row; columns: columns" data-testid="row"></tr>
      </table>
    }
  `,
  styles: `
    .header { display: flex; justify-content: space-between; align-items: center; }
    .table { width: 100%; }
    .error { color: var(--mat-sys-error); }
    .phase[data-phase='Completed'] { color: var(--mat-sys-primary); }
    .phase[data-phase='Failed'], .phase[data-phase='Rejected'], .phase[data-phase='Aborted'] { color: var(--mat-sys-error); }
  `,
})
export class ExperimentList implements OnInit {
  private readonly api = inject(ExperimentsService);
  private readonly auth = inject(AuthService);
  protected readonly items = signal<Experiment[]>([]);
  protected readonly error = signal<string | null>(null);
  protected readonly columns = ['name', 'description', 'requester', 'phase', 'result', 'created'];
  protected readonly canCreate = () => this.auth.user()?.roles.includes('experimenter') ?? false;

  ngOnInit(): void {
    this.api.list().subscribe({
      next: (items) => this.items.set(items),
      error: () => this.error.set('Could not load experiments.'),
    });
  }
}
