import { Component, OnInit, inject } from '@angular/core';
import { MatButtonModule } from '@angular/material/button';
import { MatCardModule } from '@angular/material/card';
import { ApiStatusService } from '../../core/api-status.service';

@Component({
  selector: 'kc-overview',
  imports: [MatCardModule, MatButtonModule],
  templateUrl: './overview.html',
  styleUrl: './overview.scss',
})
export class Overview implements OnInit {
  protected readonly status = inject(ApiStatusService);

  ngOnInit(): void {
    this.status.refresh();
  }
}
