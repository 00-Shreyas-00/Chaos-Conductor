import { Component, OnInit, inject, input } from '@angular/core';
import { MatButtonModule } from '@angular/material/button';
import { MatCardModule } from '@angular/material/card';
import { ApiStatusService } from '../../core/api-status.service';
import { AuthService } from '../../core/auth.service';

@Component({
  selector: 'kc-overview',
  imports: [MatCardModule, MatButtonModule],
  templateUrl: './overview.html',
  styleUrl: './overview.scss',
})
export class Overview implements OnInit {
  protected readonly status = inject(ApiStatusService);
  protected readonly auth = inject(AuthService);

  /** Bound from the `?loginError=1` query parameter set by the API on a failed login. */
  readonly loginError = input<string>();

  ngOnInit(): void {
    this.status.refresh();
  }

  refresh(): void {
    this.status.refresh();
    this.auth.load();
  }
}
