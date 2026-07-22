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
	subscribers map[uint64]func(Event)
	nextID      uint64
}

// NewBus creates a new event bus.
func NewBus() *Bus {
	return &Bus{subscribers: make(map[uint64]func(Event))}
}

// Subscribe registers a handler for incoming events.
func (b *Bus) Subscribe(fn func(Event)) func() {
	if fn == nil {
		return func() {}
	}
	b.mu.Lock()
	id := b.nextID
	b.nextID++
	b.subscribers[id] = fn
	b.mu.Unlock()
	return func() {
		b.mu.Lock()
		delete(b.subscribers, id)
		b.mu.Unlock()
	}
}

// Publish emits an event to all subscribers.
func (b *Bus) Publish(event Event) {
	b.mu.RLock()
	subs := make([]func(Event), 0, len(b.subscribers))
	for _, subscriber := range b.subscribers {
		subs = append(subs, subscriber)
	}
	b.mu.RUnlock()

	for _, fn := range subs {
		fn(event)
	}
}
