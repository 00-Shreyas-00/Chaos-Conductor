import { Component, OnInit, effect, inject, signal } from '@angular/core';
import { MatButtonModule } from '@angular/material/button';
import { MatToolbarModule } from '@angular/material/toolbar';
import { RouterLink, RouterLinkActive, RouterOutlet } from '@angular/router';
import { AuthService, Role } from './core/auth.service';
import { ExperimentsService } from './core/experiments.service';

@Component({
  selector: 'kc-root',
  imports: [RouterOutlet, RouterLink, RouterLinkActive, MatToolbarModule, MatButtonModule],
  templateUrl: './app.html',
  styleUrl: './app.scss',
})
export class App implements OnInit {
  protected readonly auth = inject(AuthService);
  private readonly api = inject(ExperimentsService);
  protected readonly locked = signal(false);

  constructor() {
    // Show the emergency-stop banner to signed-in users who can see the system state.
    effect(() => {
      if (this.auth.state() === 'authenticated' && this.has('viewer', 'experimenter', 'approver', 'admin')) {
        this.api.lock().subscribe({ next: (s) => this.locked.set(s.locked), error: () => undefined });
      }
    });
  }

  ngOnInit(): void {
    this.auth.load();
  }

  protected has(...roles: Role[]): boolean {
    return this.auth.user()?.roles.some((r) => roles.includes(r)) ?? false;
  }
}
