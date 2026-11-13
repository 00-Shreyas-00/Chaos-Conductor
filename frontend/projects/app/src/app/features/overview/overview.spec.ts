import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { TestBed } from '@angular/core/testing';
import { Overview } from './overview';

describe('Overview', () => {
  it('shows readiness and anonymous session from the API', async () => {
    TestBed.configureTestingModule({
      imports: [Overview],
      providers: [provideHttpClient(), provideHttpClientTesting()],
    });
    const fixture = TestBed.createComponent(Overview);
    fixture.detectChanges();

    const http = TestBed.inject(HttpTestingController);
    http.expectOne('/readyz').flush({ status: 'ready' });
    http.expectOne('/api/v1/me').flush({}, { status: 401, statusText: 'Unauthorized' });
    await fixture.whenStable();
    fixture.detectChanges();

    const el = fixture.nativeElement as HTMLElement;
    expect(el.querySelector('[data-testid=readiness]')?.textContent).toContain('Ready');
    expect(el.querySelector('[data-testid=session]')?.textContent).toContain('Not signed in');
    http.verify();
  });
});
