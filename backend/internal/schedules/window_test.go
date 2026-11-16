package schedules

import (
	"testing"
	"time"
)

func mustCompile(t *testing.T, w Window) compiled {
	t.Helper()
	c, err := w.compile()
	if err != nil {
		t.Fatal(err)
	}
	return c
}

var workdays = Window{Days: []string{"Mon", "Tue", "Wed", "Thu", "Fri"}, From: "10:00", To: "16:00", TimeZone: "Europe/London"}

func TestWindowValidation(t *testing.T) {
	bad := []Window{
		{Days: nil, From: "10:00", To: "16:00", TimeZone: "UTC"},
		{Days: []string{"Monday"}, From: "10:00", To: "16:00", TimeZone: "UTC"},
		{Days: []string{"Mon", "Mon"}, From: "10:00", To: "16:00", TimeZone: "UTC"},
		{Days: []string{"Mon"}, From: "16:00", To: "10:00", TimeZone: "UTC"}, // overnight
		{Days: []string{"Mon"}, From: "10:00", To: "10:15", TimeZone: "UTC"}, // < 30 min
		{Days: []string{"Mon"}, From: "25:00", To: "26:00", TimeZone: "UTC"},
		{Days: []string{"Mon"}, From: "10:00", To: "16:00", TimeZone: "Mars/Olympus"},
		{Days: []string{"Mon"}, From: "10:00", To: "16:00", TimeZone: ""},
	}
	for i, w := range bad {
		if _, err := w.compile(); err == nil {
			t.Errorf("case %d: %+v accepted", i, w)
		}
	}
	if _, err := (Window{Days: []string{"Sun"}, From: "00:00", To: "24:00", TimeZone: "UTC"}).compile(); err != nil {
		t.Fatalf("full day rejected: %v", err)
	}
}

func TestNextRunSpendsDelayOnlyInsideTheWindow(t *testing.T) {
	c := mustCompile(t, workdays)
	london, _ := time.LoadLocation("Europe/London")
	at := func(y int, m time.Month, d, h, min int) time.Time { return time.Date(y, m, d, h, min, 0, 0, london) }

	cases := []struct {
		name  string
		from  time.Time
		delay time.Duration
		want  time.Time
	}{
		{"inside the window", at(2026, 11, 16, 11, 0), time.Hour, at(2026, 11, 16, 12, 0)},
		{"before the window opens", at(2026, 11, 16, 7, 0), 30 * time.Minute, at(2026, 11, 16, 10, 30)},
		{"rolls into the next working day", at(2026, 11, 16, 15, 0), 2 * time.Hour, at(2026, 11, 17, 11, 0)},
		{"Friday evening skips the weekend", at(2026, 11, 20, 18, 0), time.Hour, at(2026, 11, 23, 11, 0)},
		{"one window-day exactly", at(2026, 11, 16, 10, 0), 6 * time.Hour, at(2026, 11, 17, 10, 0)},
		{"zero delay waits for the window", at(2026, 11, 21, 12, 0), 0, at(2026, 11, 23, 10, 0)},
		// UK clocks go back on 25 Oct 2026; the window is wall-clock time either side.
		{"across a DST change", at(2026, 10, 23, 15, 30), time.Hour, at(2026, 10, 26, 10, 30)},
	}
	for _, tc := range cases {
		got, ok := c.nextRun(tc.from, tc.delay)
		if !ok || !got.Equal(tc.want) {
			t.Errorf("%s: got %v (ok=%v), want %v", tc.name, got, ok, tc.want)
		}
		if !c.inWindow(got) {
			t.Errorf("%s: %v is outside the window", tc.name, got)
		}
	}
}

func TestSampleDelay(t *testing.T) {
	min, mean := time.Hour, 3*time.Hour
	if d := sampleDelay(min, mean, 1); d != min {
		t.Fatalf("u=1 must give the minimum, got %v", d)
	}
	if d := sampleDelay(min, mean, 1e-300); d != min+10*(mean-min) {
		t.Fatalf("tail must be capped, got %v", d)
	}
	if d := sampleDelay(time.Hour, time.Hour, 0.5); d != time.Hour {
		t.Fatalf("min == mean is deterministic, got %v", d)
	}
	// The empirical mean converges on `mean`.
	var sum time.Duration
	const n = 20000
	for i := 0; i < n; i++ {
		d := sampleDelay(min, mean, cryptoUniform())
		if d < min {
			t.Fatalf("delay %v below minimum", d)
		}
		sum += d
	}
	if avg := sum / n; avg < mean-10*time.Minute || avg > mean+10*time.Minute {
		t.Fatalf("average %v, want about %v", avg, mean)
	}
}
