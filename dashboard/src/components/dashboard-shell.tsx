"use client";

import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { Activity, BarChart3, Bell, BookOpenText, ChevronDown, CircleHelp, FileText, Flame, LayoutDashboard, LogOut, Menu, MonitorCog, Network, Search, Settings, Shield, SlidersHorizontal, X } from "lucide-react";
import { useState } from "react";

const navigation = [
  ["Dashboard", "/", LayoutDashboard], ["Live Monitor", "/monitor", Activity], ["Attacks", "/attacks", Flame], ["Firewall", "/firewall", Shield], ["Analytics", "/analytics", BarChart3], ["Logs", "/logs", FileText], ["Audit Log", "/audit", BookOpenText], ["Alerts", "/alerts", Bell], ["Configuration", "/configuration", SlidersHorizontal], ["System", "/system", MonitorCog], ["Settings", "/settings", Settings],
] as const;

export function DashboardShell({ children }: { children: React.ReactNode }) {
  const pathname = usePathname(); const router = useRouter(); const [open, setOpen] = useState(false);
  async function logout() { await fetch("/api/session", { method: "DELETE" }); router.replace("/login"); router.refresh(); }
  return <div className="min-h-screen lg:grid lg:grid-cols-[264px_1fr]">
    <aside className={`fixed inset-y-0 left-0 z-40 flex w-64 flex-col border-r border-[var(--border)] bg-[#080e19ee] p-4 backdrop-blur-xl transition-transform lg:static lg:translate-x-0 ${open ? "translate-x-0" : "-translate-x-full"}`}>
      <div className="mb-8 flex items-center gap-3 px-2"><div className="grid h-9 w-9 place-items-center rounded-xl bg-[var(--accent)] text-[#06101e]"><Shield size={20} strokeWidth={2.8}/></div><div><p className="font-semibold tracking-tight">DigitDojo</p><p className="text-xs text-[var(--accent)]">SHIELD CONSOLE</p></div><button onClick={() => setOpen(false)} className="ml-auto lg:hidden"><X size={19}/></button></div>
      <nav className="space-y-1">{navigation.map(([label, href, Icon]) => <Link onClick={() => setOpen(false)} key={href} href={href} className={`flex items-center gap-3 rounded-xl px-3 py-2.5 text-sm transition ${pathname === href ? "bg-[#19364d] text-white shadow-[inset_0_0_0_1px_#4dd6ff33]" : "text-[#9aabc1] hover:bg-white/5 hover:text-white"}`}><Icon size={18}/>{label}</Link>)}</nav>
      <div className="mt-auto space-y-2 border-t border-[var(--border)] pt-4"><a className="flex items-center gap-3 px-3 py-2 text-sm text-[var(--muted)] hover:text-white" href="https://github.com" target="_blank" rel="noreferrer"><BookOpenText size={18}/>Documentation</a><button onClick={logout} className="flex w-full items-center gap-3 px-3 py-2 text-sm text-[var(--muted)] hover:text-white"><LogOut size={18}/>Sign out</button></div>
    </aside>
    {open && <button aria-label="Close navigation" onClick={() => setOpen(false)} className="fixed inset-0 z-30 bg-black/65 lg:hidden"/>}
    <main className="min-w-0"><header className="sticky top-0 z-20 flex h-16 items-center gap-3 border-b border-[var(--border)] bg-[#080e19bb] px-4 backdrop-blur-xl sm:px-7"><button onClick={() => setOpen(true)} className="rounded-lg p-2 hover:bg-white/5 lg:hidden"><Menu size={20}/></button><div className="relative hidden max-w-sm flex-1 md:block"><Search className="absolute left-3 top-1/2 -translate-y-1/2 text-[var(--muted)]" size={16}/><input aria-label="Search" placeholder="Search IPs, events, settings…" className="w-full rounded-lg border border-[var(--border)] bg-[#0c1422] py-2 pl-9 pr-3 text-sm outline-none placeholder:text-[#607089] focus:border-[var(--accent)]"/></div><div className="ml-auto flex items-center gap-2"><span className="hidden items-center gap-1.5 rounded-full border border-[#42d6a444] bg-[#42d6a410] px-2.5 py-1 text-xs text-[var(--success)] sm:flex"><span className="h-1.5 w-1.5 rounded-full bg-[var(--success)]"/>Connected</span><button aria-label="Notifications" className="rounded-lg p-2 text-[var(--muted)] hover:bg-white/5 hover:text-white"><Bell size={19}/></button><button className="flex items-center gap-1 rounded-lg p-2 text-sm hover:bg-white/5"><Network size={17}/><span className="hidden sm:inline">Local Shield</span><ChevronDown size={15}/></button></div></header><div className="mx-auto max-w-[1600px] p-4 sm:p-7">{children}</div></main>
  </div>;
}
