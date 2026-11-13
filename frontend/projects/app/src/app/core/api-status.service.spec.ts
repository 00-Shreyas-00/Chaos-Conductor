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

  it('reports ready on 200', () => {
    service.refresh();
    expect(service.readiness()).toBe('checking');
    http.expectOne('/readyz').flush({ status: 'ready' });
    expect(service.readiness()).toBe('ready');
  });

  it('reports unavailable on failure', () => {
    service.refresh();
    http.expectOne('/readyz').flush(null, { status: 503, statusText: 'Service Unavailable' });
    expect(service.readiness()).toBe('unavailable');
  });
});
