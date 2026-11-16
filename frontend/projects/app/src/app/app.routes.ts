import { Routes } from '@angular/router';
import { roleGuard } from './core/role.guard';

// Guards are UX only (hide pages a role cannot use); the API authorizes every request.
export const routes: Routes = [
  { path: '', title: 'Overview · KubeChaos', loadComponent: () => import('./features/overview/overview').then((m) => m.Overview) },
  {
    path: 'experiments',
    title: 'Experiments · KubeChaos',
    canActivate: [roleGuard('viewer', 'experimenter', 'approver', 'admin')],
    loadComponent: () => import('./features/experiments/experiment-list').then((m) => m.ExperimentList),
  },
  {
    path: 'experiments/new',
    title: 'New experiment · KubeChaos',
    canActivate: [roleGuard('experimenter')],
    loadComponent: () => import('./features/experiments/experiment-form').then((m) => m.ExperimentForm),
  },
  {
    path: 'experiments/:id',
    title: 'Experiment · KubeChaos',
    canActivate: [roleGuard('viewer', 'experimenter', 'approver', 'admin')],
    loadComponent: () => import('./features/experiments/experiment-detail').then((m) => m.ExperimentDetail),
  },
  {
    path: 'admin',
    title: 'Emergency stop · KubeChaos',
    canActivate: [roleGuard('admin')],
    loadComponent: () => import('./features/admin/admin').then((m) => m.Admin),
  },
  {
    path: 'audit',
    title: 'Audit log · KubeChaos',
    canActivate: [roleGuard('auditor')],
    loadComponent: () => import('./features/audit/audit').then((m) => m.Audit),
  },
  { path: '**', title: 'Not found · KubeChaos', loadComponent: () => import('./features/not-found/not-found').then((m) => m.NotFound) },
];
