import { HttpErrorResponse } from '@angular/common/http';
import { Component, OnInit, computed, inject, signal } from '@angular/core';
import {
  AbstractControl,
  FormArray,
  FormControl,
  FormGroup,
  NonNullableFormBuilder,
  ReactiveFormsModule,
  ValidationErrors,
  Validators,
} from '@angular/forms';
import { MatButtonModule } from '@angular/material/button';
import { MatCardModule } from '@angular/material/card';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatInputModule } from '@angular/material/input';
import { MatSelectModule } from '@angular/material/select';
import { Router } from '@angular/router';
import { ApiProblem, ClusterSummary, CreateExperimentRequest, Criterion, Scenario, Step } from '../../core/api.types';
import { BROWSER_LOCATION } from '../../core/auth.service';
import { ExperimentsService } from '../../core/experiments.service';

const DRAFT_KEY = 'kubechaos.experimentDraft';
const DURATION = /^([0-9]{1,4}(s|m|h)){1,3}$/;
const LABEL = /^[A-Za-z0-9]([-A-Za-z0-9_./]{0,251}[A-Za-z0-9])?$/;

/** "app=web, tier=frontend" -> {app: "web", tier: "frontend"}; null when malformed. */
export function parseSelector(text: string): Record<string, string> | null {
  const out: Record<string, string> = {};
  const parts = text.split(',').map((p) => p.trim()).filter(Boolean);
  if (parts.length === 0 || parts.length > 10) return null;
  for (const p of parts) {
    const [k, v, ...rest] = p.split('=');
    if (rest.length || !k || v === undefined || !LABEL.test(k.trim()) || (v.trim() !== '' && !LABEL.test(v.trim()))) return null;
    out[k.trim()] = v.trim();
  }
  return out;
}

function selectorValidator(c: AbstractControl): ValidationErrors | null {
  return parseSelector(c.value ?? '') ? null : { selector: true };
}

type StepForm = FormGroup<{
  kind: FormControl<'fault' | 'wait'>;
  namespace: FormControl<string>;
  selector: FormControl<string>;
  count: FormControl<number>;
  grace: FormControl<number>;
  duration: FormControl<string>;
}>;

type CriterionForm = FormGroup<{
  metric: FormControl<Criterion['metric']>;
  operator: FormControl<Criterion['operator']>;
  value: FormControl<string>;
  weight: FormControl<number>;
}>;

/**
 * Builds a constrained, declarative experiment. Client-side validation is for usability only;
 * the control plane and the operator enforce every limit independently.
 */
@Component({
  selector: 'kc-experiment-form',
  imports: [ReactiveFormsModule, MatFormFieldModule, MatInputModule, MatSelectModule, MatButtonModule, MatCardModule],
  templateUrl: './experiment-form.html',
  styleUrl: './experiment-form.scss',
})
export class ExperimentForm implements OnInit {
  private readonly api = inject(ExperimentsService);
  private readonly fb = inject(NonNullableFormBuilder);
  private readonly router = inject(Router);
  private readonly location = inject(BROWSER_LOCATION);

  protected readonly scenarios = signal<Scenario[]>([]);
  protected readonly cluster = signal<ClusterSummary | null>(null);
  protected readonly problem = signal<ApiProblem | null>(null);
  protected readonly submitting = signal(false);
  protected readonly metrics: Criterion['metric'][] = ['available_replicas', 'ready_ratio', 'recovery_time', 'http_error_rate', 'http_latency_p99'];
  protected readonly operators: Criterion['operator'][] = ['ge', 'gt', 'le', 'lt', 'eq'];

  readonly form = this.fb.group({
    description: this.fb.control('', [Validators.maxLength(500)]),
    maxDuration: this.fb.control('3m', [Validators.required, Validators.pattern(DURATION)]),
    steps: this.fb.array<StepForm>([]),
    criteria: this.fb.array<CriterionForm>([]),
    confirmation: this.fb.control(''),
  });

  /** The user must type the target namespace(s) to confirm: deliberate friction, not security. */
  protected readonly targets = signal<string[]>([]);
  protected readonly confirmed = computed(() => this.targets().length > 0);

  get steps(): FormArray<StepForm> {
    return this.form.controls.steps;
  }
  get criteria(): FormArray<CriterionForm> {
    return this.form.controls.criteria;
  }

  ngOnInit(): void {
    this.api.scenarios().subscribe({ next: (s) => this.scenarios.set(s), error: () => undefined });
    this.api.clusters().subscribe({ next: (c) => this.cluster.set(c[0] ?? null), error: () => undefined });
    const draft = this.readDraft();
    if (draft) {
      this.load(draft);
    } else {
      this.addFault();
    }
  }

  protected step(kind: 'fault' | 'wait'): StepForm {
    return this.fb.group({
      kind: this.fb.control<'fault' | 'wait'>(kind),
      namespace: this.fb.control('demo', kind === 'fault' ? [Validators.required, Validators.pattern(/^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/)] : []),
      selector: this.fb.control('app=web', kind === 'fault' ? [selectorValidator] : []),
      count: this.fb.control(1, kind === 'fault' ? [Validators.required, Validators.min(1), Validators.max(10)] : []),
      grace: this.fb.control(0, kind === 'fault' ? [Validators.min(0), Validators.max(300)] : []),
      duration: this.fb.control('30s', kind === 'wait' ? [Validators.required, Validators.pattern(DURATION)] : []),
    });
  }

  addFault(): void {
    if (this.steps.length < 20) this.steps.push(this.step('fault'));
  }
  addWait(): void {
    if (this.steps.length < 20) this.steps.push(this.step('wait'));
  }
  removeStep(i: number): void {
    this.steps.removeAt(i);
  }
  addCriterion(c?: Criterion): void {
    if (this.criteria.length >= 10) return;
    this.criteria.push(
      this.fb.group({
        metric: this.fb.control<Criterion['metric']>(c?.metric ?? 'available_replicas'),
        operator: this.fb.control<Criterion['operator']>(c?.operator ?? 'ge'),
        value: this.fb.control(c?.value ?? '1', [Validators.required, Validators.maxLength(16)]),
        weight: this.fb.control(c?.weight ?? 1, [Validators.min(1), Validators.max(100)]),
      }),
    );
  }
  removeCriterion(i: number): void {
    this.criteria.removeAt(i);
  }

  applyScenario(id: string): void {
    const s = this.scenarios().find((x) => x.id === id);
    if (!s) return;
    this.load({ description: s.description, maxDuration: s.maxDuration, steps: s.steps, successCriteria: s.successCriteria, confirm: false });
  }

  private load(r: CreateExperimentRequest): void {
    this.form.patchValue({ description: r.description, maxDuration: r.maxDuration, confirmation: '' });
    this.steps.clear();
    for (const st of r.steps) {
      const g = this.step(st.fault ? 'fault' : 'wait');
      if (st.fault) {
        g.patchValue({
          namespace: st.fault.target.namespace,
          selector: Object.entries(st.fault.target.selector).map(([k, v]) => `${k}=${v}`).join(', '),
          count: st.fault.podKill?.count ?? 1,
          grace: st.fault.podKill?.gracePeriodSeconds ?? 0,
        });
      } else if (st.wait) {
        g.patchValue({ duration: st.wait.duration });
      }
      this.steps.push(g);
    }
    this.criteria.clear();
    (r.successCriteria ?? []).forEach((c) => this.addCriterion(c));
  }

  /** Builds the API request. Never includes identity or cluster: the server sets those. */
  buildRequest(): CreateExperimentRequest {
    const v = this.form.getRawValue();
    const steps: Step[] = v.steps.map((s) =>
      s.kind === 'wait'
        ? { wait: { duration: s.duration } }
        : {
            fault: {
              type: 'PodKill',
              target: { namespace: s.namespace, selector: parseSelector(s.selector) ?? {} },
              podKill: { count: Number(s.count), gracePeriodSeconds: Number(s.grace) },
            },
          },
    );
    const req: CreateExperimentRequest = { description: v.description, maxDuration: v.maxDuration, steps, confirm: true };
    if (v.criteria.length) {
      req.successCriteria = v.criteria.map((c) => ({ metric: c.metric, operator: c.operator, value: c.value, weight: Number(c.weight) }));
    }
    return req;
  }

  /** Namespaces the user must type to confirm. */
  targetNamespaces(): string[] {
    return [...new Set(this.form.getRawValue().steps.filter((s) => s.kind === 'fault').map((s) => s.namespace))];
  }

  confirmationMatches(): boolean {
    return this.form.controls.confirmation.value.trim() === this.targetNamespaces().join(',');
  }

  submit(): void {
    this.problem.set(null);
    if (this.form.invalid || !this.steps.controls.some((s) => s.controls.kind.value === 'fault') || !this.confirmationMatches()) {
      this.form.markAllAsTouched();
      return;
    }
    this.submitting.set(true);
    this.api.create(this.buildRequest()).subscribe({
      next: (exp) => {
        this.clearDraft();
        void this.router.navigate(['/experiments', exp.id]);
      },
      error: (err: HttpErrorResponse) => {
        this.submitting.set(false);
        const p: ApiProblem = typeof err.error === 'object' && err.error ? err.error : { title: 'Request failed', status: err.status };
        this.problem.set(p);
      },
    });
  }

  /** Step-up: save the draft, sign in again (forced re-authentication), come back here. */
  reauthenticate(): void {
    this.saveDraft();
    this.location.assign('/auth/login?stepUp=1&returnTo=' + encodeURIComponent('/experiments/new'));
  }

  private saveDraft(): void {
    try {
      sessionStorage.setItem(DRAFT_KEY, JSON.stringify(this.buildRequest()));
    } catch {
      /* storage unavailable: the user re-enters the form */
    }
  }
  private readDraft(): CreateExperimentRequest | null {
    try {
      const raw = sessionStorage.getItem(DRAFT_KEY);
      return raw ? (JSON.parse(raw) as CreateExperimentRequest) : null;
    } catch {
      return null;
    }
  }
  private clearDraft(): void {
    try {
      sessionStorage.removeItem(DRAFT_KEY);
    } catch {
      /* ignore */
    }
  }
}
