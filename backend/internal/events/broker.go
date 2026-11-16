// Package events fans experiment updates out to SSE subscribers. Delivery is best effort: a
// slow subscriber's buffer overflows and it is told to resync, never blocking publishers.
package events

import (
	"sync"
)

// Message is one update for an experiment.
type Message struct {
	Type string // "experiment" | "timeline" | "resync"
	Data any
}

// Broker is an in-process pub/sub keyed by experiment ID.
type Broker struct {
	mu         sync.Mutex
	subs       map[string]map[chan Message]struct{}
	perUser    map[string]int
	MaxPerUser int
}

// NewBroker returns a Broker allowing maxPerUser concurrent streams per user.
func NewBroker(maxPerUser int) *Broker {
	return &Broker{subs: map[string]map[chan Message]struct{}{}, perUser: map[string]int{}, MaxPerUser: maxPerUser}
}

// Subscribe registers a subscriber for experiment id on behalf of user. ok is false when the
// user already has MaxPerUser streams open (resource exhaustion, threat model T13).
func (b *Broker) Subscribe(id, user string) (ch <-chan Message, cancel func(), ok bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.perUser[user] >= b.MaxPerUser {
		return nil, func() {}, false
	}
	c := make(chan Message, 32)
	if b.subs[id] == nil {
		b.subs[id] = map[chan Message]struct{}{}
	}
	b.subs[id][c] = struct{}{}
	b.perUser[user]++
	var once sync.Once
	return c, func() {
		once.Do(func() {
			b.mu.Lock()
			defer b.mu.Unlock()
			delete(b.subs[id], c)
			if len(b.subs[id]) == 0 {
				delete(b.subs, id)
			}
			b.perUser[user]--
			if b.perUser[user] <= 0 {
				delete(b.perUser, user)
			}
			close(c)
		})
	}, true
}

// Publish delivers m to every subscriber of id without blocking.
func (b *Broker) Publish(id string, m Message) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for c := range b.subs[id] {
		select {
		case c <- m:
		default:
			// Buffer full: drop and ask the client to resync from the API.
			select {
			case c <- Message{Type: "resync"}:
			default:
			}
		}
	}
}

// Subscribers returns the number of subscribers for id (tests, metrics).
func (b *Broker) Subscribers(id string) int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.subs[id])
}
