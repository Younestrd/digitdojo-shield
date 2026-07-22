"use client";
import { useQuery } from "@tanstack/react-query";
import { ShieldAlert } from "lucide-react";
import { shieldAPI } from "@/lib/api";

export function AttackHistory() {
  const query = useQuery({ queryKey:["shield","attacks"], queryFn: () => shieldAPI.attacks() });
  if (query.isLoading) return <div className="surface h-48 animate-pulse rounded-2xl"/>;
  if (query.isError) return <p className="text-sm text-[var(--danger)]">{query.error.message}</p>;
  return <section className="surface overflow-hidden rounded-2xl"><div className="border-b border-[var(--border)] p-5"><h2 className="font-semibold">Observed attacks</h2><p className="mt-1 text-sm text-[var(--muted)]">{query.data?.total ?? 0} detector-derived lifecycle records.</p></div><div className="overflow-x-auto"><table className="w-full min-w-[680px] text-left text-sm"><thead className="bg-black/10 text-xs uppercase tracking-wide text-[var(--muted)]"><tr><th className="p-4">Type</th><th className="p-4">Severity</th><th className="p-4">Started</th><th className="p-4">Status</th><th className="p-4">Mitigation</th></tr></thead><tbody>{query.data?.items.length ? query.data.items.map((attack) => <tr key={attack.id} className="border-t border-[var(--border)]"><td className="p-4 font-medium"><span className="mr-2 inline-block text-[var(--danger)]"><ShieldAlert size={15}/></span>{attack.type.replaceAll("_"," ")}</td><td className="p-4 capitalize">{attack.severity}</td><td className="p-4 text-[var(--muted)]">{new Date(attack.started_at).toLocaleString()}</td><td className="p-4">{attack.resolved_at ? <span className="text-[var(--success)]">Resolved</span> : <span className="text-[var(--warning)]">Active</span>}</td><td className="p-4 text-[var(--muted)]">{attack.mitigation}</td></tr>) : <tr><td colSpan={5} className="p-8 text-center text-[var(--muted)]">No attack lifecycle has been observed by this daemon.</td></tr>}</tbody></table></div></section>;
}
