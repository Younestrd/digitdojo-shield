"use client";

import { useQuery } from "@tanstack/react-query";
import { Activity, Ban, Gauge, Network, Radio, ShieldCheck, Zap } from "lucide-react";
import { shieldAPI } from "@/lib/api";
import { useShieldEvents } from "@/hooks/use-shield-events";

const metricLabels = [
  ["Blocked addresses", "blocked", Ban], ["Detector signals", "signals", Zap], ["Packets / second", "packets_per_second", Activity], ["Bandwidth", "bandwidth_mbps", Gauge],
] as const;

export function LiveStats() {
	const liveEvents = useShieldEvents();
  const query = useQuery({ queryKey: ["shield", "stats"], queryFn: shieldAPI.stats, refetchInterval: 5000 });
  if (query.isLoading) return <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">{metricLabels.map(([label]) => <div key={label} className="surface h-32 animate-pulse rounded-2xl"/>)}</div>;
  if (query.isError || !query.data) return <section className="surface rounded-2xl p-6"><h2 className="font-semibold">Live telemetry unavailable</h2><p className="mt-2 text-sm text-[var(--muted)]">{query.error instanceof Error ? query.error.message : "Unable to retrieve Shield statistics."}</p></section>;
  const stats = query.data;
  return <>
    <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">{metricLabels.map(([label, key, Icon]) => <article key={label} className="surface rounded-2xl p-5"><div className="flex items-start justify-between"><span className="text-sm text-[var(--muted)]">{label}</span><Icon size={18} className="text-[var(--accent)]"/></div><p className="mt-5 text-3xl font-semibold tracking-tight">{stats[key]}{key === "bandwidth_mbps" ? " Mbps" : ""}</p><p className="mt-1 text-xs text-[var(--muted)]">Current daemon snapshot</p></article>)}</div>
    <div className="mt-4 grid gap-4 lg:grid-cols-3"><article className="surface rounded-2xl p-5 lg:col-span-2"><div className="flex items-center justify-between"><div><p className="text-sm text-[var(--muted)]">Detection posture</p><h2 className="mt-1 text-xl font-semibold capitalize">{stats.attack_status.replaceAll("_", " ")}</h2></div><span className={`rounded-full px-3 py-1 text-sm font-medium ${stats.attack_status === "under_attack" ? "bg-[#ff718720] text-[var(--danger)]" : "bg-[#42d6a420] text-[var(--success)]"}`}>{stats.attack_status === "under_attack" ? "Active response" : "Monitoring"}</span></div><div className="mt-7 grid gap-3 sm:grid-cols-3"><Status label="Firewall backend" value={stats.firewall_backend || "unavailable"} icon={<ShieldCheck size={17}/>}/><Status label="Enforcement" value={stats.firewall_enforced ? "enabled" : "locked"} icon={<ShieldCheck size={17}/>}/><Status label="Event stream" value={liveEvents.connected ? "connected" : "reconnecting"} icon={<Radio size={17}/>}/></div></article><article className="surface rounded-2xl p-5"><p className="text-sm text-[var(--muted)]">Live events</p><div className="mt-3 max-h-28 space-y-2 overflow-auto">{liveEvents.events.length ? liveEvents.events.slice(0, 3).map((event, index) => <div key={`${event.receivedAt}-${index}`} className="rounded-lg border border-[var(--border)] bg-black/10 p-2 text-xs"><p className="font-medium">{event.type}</p><p className="mt-1 truncate text-[var(--muted)]">{Object.entries(event.payload).map(([key, value]) => `${key}: ${value}`).join(" · ") || "No event attributes"}</p></div>) : <p className="text-sm leading-6 text-[var(--muted)]">Waiting for real daemon events…</p>}</div></article></div>
  </>;
}
function Status({ label, value, icon }: { label: string; value: string; icon: React.ReactNode }) { return <div className="rounded-xl border border-[var(--border)] bg-black/10 p-3"><div className="flex items-center gap-2 text-xs text-[var(--muted)]">{icon}{label}</div><p className="mt-2 text-sm font-medium capitalize">{value}</p></div>; }
