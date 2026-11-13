import { Routes } from '@angular/router';

// Route guards added later are UX only; the API enforces authorization independently.
export const routes: Routes = [
  { path: '', title: 'Overview · KubeChaos', loadComponent: () => import('./features/overview/overview').then((m) => m.Overview) },
  { path: '**', title: 'Not found · KubeChaos', loadComponent: () => import('./features/not-found/not-found').then((m) => m.NotFound) },
];
