"use client";
import { useEffect, useState } from "react";

export type ShieldEvent = { type: string; payload: Record<string, string>; receivedAt: string };

export function useShieldEvents() {
  const [events, setEvents] = useState<ShieldEvent[]>([]);
  const [connected, setConnected] = useState(false);
  useEffect(() => {
    const stream = new EventSource("/api/shield/events");
    stream.onopen = () => setConnected(true);
    stream.onerror = () => setConnected(false);
    const onEvent = (event: MessageEvent<string>) => { try { const data = JSON.parse(event.data) as Omit<ShieldEvent, "receivedAt">; setEvents((current) => [{ ...data, receivedAt: new Date().toISOString() }, ...current].slice(0, 20)); } catch { /* malformed upstream events are ignored */ } };
    ["RuntimeStarted", "RuntimeStopped", "SampleCollected", "AttackDetected", "AttackCleared", "RuntimeError"].forEach((name) => stream.addEventListener(name, onEvent));
    return () => stream.close();
  }, []);
  return { events, connected };
}
