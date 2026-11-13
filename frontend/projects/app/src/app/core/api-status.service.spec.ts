import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { TestBed } from '@angular/core/testing';
import { ApiStatusService } from './api-status.service';

describe('ApiStatusService', () => {
  let service: ApiStatusService;
  let http: HttpTestingController;

  beforeEach(() => {
    TestBed.configureTestingModule({ providers: [provideHttpClient(), provideHttpClientTesting()] });
    service = TestBed.inject(ApiStatusService);
    http = TestBed.inject(HttpTestingController);
  });

  afterEach(() => http.verify());

  it('reports ready and authenticated on 200s', () => {
    service.refresh();
    expect(service.readiness()).toBe('checking');
    http.expectOne('/readyz').flush({ status: 'ready' });
    http.expectOne('/api/v1/me').flush({ subject: 's' });
    expect(service.readiness()).toBe('ready');
    expect(service.session()).toBe('authenticated');
  });

  it('treats 401 from /api/v1/me as anonymous, not as an error', () => {
    service.refresh();
    http.expectOne('/readyz').flush({ status: 'ready' });
    http.expectOne('/api/v1/me').flush({ title: 'Unauthorized' }, { status: 401, statusText: 'Unauthorized' });
    expect(service.session()).toBe('anonymous');
  });

  it('reports unavailable and error on failures', () => {
    service.refresh();
    http.expectOne('/readyz').flush(null, { status: 503, statusText: 'Service Unavailable' });
    http.expectOne('/api/v1/me').flush(null, { status: 500, statusText: 'Internal Server Error' });
    expect(service.readiness()).toBe('unavailable');
    expect(service.session()).toBe('error');
  });
});
