package schedules

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"math"
	"time"
)

// Window is the weekly period in which scheduled runs may happen (Chaos Monkey's
// "business hours"). Intervals are measured in window time only: with a 10:00–16:00
// Mon–Fri window, a 6h interval is one working day.
type Window struct {
	Days     []string `json:"days"`     // Mon Tue Wed Thu Fri Sat Sun
	From     string   `json:"from"`     // HH:MM
	To       string   `json:"to"`       // HH:MM, after From; "24:00" allowed
	TimeZone string   `json:"timeZone"` // IANA name, e.g. Europe/London
}

type compiled struct {
	days     [7]bool // indexed by time.Weekday
	from, to int     // minutes since midnight
	loc      *time.Location
}

var dayIndex = map[string]time.Weekday{"Sun": time.Sunday, "Mon": time.Monday, "Tue": time.Tuesday,
	"Wed": time.Wednesday, "Thu": time.Thursday, "Fri": time.Friday, "Sat": time.Saturday}

func parseClock(s string) (int, error) {
	var h, m int
	if len(s) != 5 || s[2] != ':' {
		return 0, fmt.Errorf("%q is not HH:MM", s)
	}
	if _, err := fmt.Sscanf(s, "%02d:%02d", &h, &m); err != nil || h < 0 || m < 0 || m > 59 || h > 24 || (h == 24 && m != 0) {
		return 0, fmt.Errorf("%q is not a valid time of day", s)
	}
	return h*60 + m, nil
}

// compile validates the window.
func (w Window) compile() (compiled, error) {
	var c compiled
	if len(w.Days) == 0 || len(w.Days) > 7 {
		return c, fmt.Errorf("window.days: between 1 and 7 days required")
	}
	for _, d := range w.Days {
		i, ok := dayIndex[d]
		if !ok {
			return c, fmt.Errorf("window.days: unknown day %q (use Mon..Sun)", d)
		}
		if c.days[i] {
			return c, fmt.Errorf("window.days: %s listed twice", d)
		}
		c.days[i] = true
	}
	var err error
	if c.from, err = parseClock(w.From); err != nil {
		return c, fmt.Errorf("window.from: %v", err)
	}
	if c.to, err = parseClock(w.To); err != nil {
		return c, fmt.Errorf("window.to: %v", err)
	}
	if c.to-c.from < 30 {
		return c, fmt.Errorf("window: 'to' must be at least 30 minutes after 'from' (overnight windows are not supported)")
	}
	if w.TimeZone == "" || len(w.TimeZone) > 64 {
		return c, fmt.Errorf("window.timeZone: an IANA time zone is required")
	}
	if c.loc, err = time.LoadLocation(w.TimeZone); err != nil {
		return c, fmt.Errorf("window.timeZone: unknown time zone %q", w.TimeZone)
	}
	return c, nil
}

// nextRun walks forward from `from`, spending `delay` only inside the window, and returns
// the resulting instant. ok is false if the window never accommodates it within ~2 years.
func (c compiled) nextRun(from time.Time, delay time.Duration) (time.Time, bool) {
	t := from.In(c.loc)
	for i := 0; i < 800; i++ {
		y, m, d := t.Date()
		start := time.Date(y, m, d, c.from/60, c.from%60, 0, 0, c.loc)
		end := time.Date(y, m, d, c.to/60, c.to%60, 0, 0, c.loc) // 24:00 normalises to next midnight
		nextDay := time.Date(y, m, d+1, 0, 0, 0, 0, c.loc)
		if !c.days[t.Weekday()] || !t.Before(end) {
			t = nextDay
			continue
		}
		if t.Before(start) {
			t = start
		}
		avail := end.Sub(t)
		if delay < avail {
			return t.Add(delay), true
		}
		delay -= avail
		t = nextDay
	}
	return time.Time{}, false
}

// inWindow reports whether t is inside the window.
func (c compiled) inWindow(t time.Time) bool {
	t = t.In(c.loc)
	if !c.days[t.Weekday()] {
		return false
	}
	mins := t.Hour()*60 + t.Minute()
	return mins >= c.from && mins < c.to
}

// sampleDelay draws min + Exp(mean-min), so the average gap is `mean` and no gap is shorter
// than `min` (Chaos Monkey's mean/min time between kills). The tail is capped at
// min + 10·(mean-min). u must be uniform in (0, 1].
func sampleDelay(min, mean time.Duration, u float64) time.Duration {
	spread := float64(mean - min)
	if spread <= 0 {
		return min
	}
	x := -math.Log(u) * spread
	if x > 10*spread {
		x = 10 * spread
	}
	return min + time.Duration(x)
}

// cryptoUniform returns a uniform float64 in (0, 1] from crypto/rand.
func cryptoUniform() float64 {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 1 // fail safe: the shortest permitted delay is still >= min
	}
	return (float64(binary.BigEndian.Uint64(b[:])>>11) + 1) / (1 << 53)
}
