package events

import "testing"

func TestBrokerDeliversAndLimits(t *testing.T) {
	b := NewBroker(2)
	c1, cancel1, ok1 := b.Subscribe("e1", "alice")
	_, cancel2, ok2 := b.Subscribe("e2", "alice")
	_, _, ok3 := b.Subscribe("e1", "alice")
	if !ok1 || !ok2 || ok3 {
		t.Fatalf("per-user limit not enforced: %v %v %v", ok1, ok2, ok3)
	}
	b.Publish("e1", Message{Type: "timeline", Data: "x"})
	if m := <-c1; m.Type != "timeline" {
		t.Fatalf("got %+v", m)
	}
	cancel1()
	cancel1() // idempotent
	cancel2()
	if _, _, ok := b.Subscribe("e1", "alice"); !ok {
		t.Fatal("slots must be released on cancel")
	}
	if b.Subscribers("e2") != 0 {
		t.Fatal("cancelled subscriber still registered")
	}
}

func TestBrokerNeverBlocks(t *testing.T) {
	b := NewBroker(1)
	c, cancel, _ := b.Subscribe("e1", "bob")
	defer cancel()
	for i := 0; i < 1000; i++ { // far more than the buffer
		b.Publish("e1", Message{Type: "timeline"})
	}
	if len(c) == 0 {
		t.Fatal("expected buffered messages")
	}
}
