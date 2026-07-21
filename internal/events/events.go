package events

import "sync"

// Event is a typed message emitted between subsystems.
type Event struct {
    Type    string
    Payload map[string]string
}

// Bus delivers events to subscribers.
type Bus struct {
    mu          sync.RWMutex
    subscribers []func(Event)
}

// NewBus creates a new event bus.
func NewBus() *Bus {
    return &Bus{}
}

// Subscribe registers a handler for incoming events.
func (b *Bus) Subscribe(fn func(Event)) {
    b.mu.Lock()
    defer b.mu.Unlock()
    b.subscribers = append(b.subscribers, fn)
}

// Publish emits an event to all subscribers.
func (b *Bus) Publish(event Event) {
    b.mu.RLock()
    subs := append([]func(Event){}, b.subscribers...)
    b.mu.RUnlock()

    for _, fn := range subs {
        fn(event)
    }
}
