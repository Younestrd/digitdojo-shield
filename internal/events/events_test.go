package events

import "testing"

func TestBusPublishesToSubscribers(t *testing.T) {
    bus := NewBus()
    received := make(chan Event, 1)
    bus.Subscribe(func(evt Event) {
        received <- evt
    })

    bus.Publish(Event{Type: "AttackDetected"})

    select {
    case evt := <-received:
        if evt.Type != "AttackDetected" {
            t.Fatalf("expected AttackDetected event")
        }
    default:
        t.Fatalf("expected event delivery")
    }
}
