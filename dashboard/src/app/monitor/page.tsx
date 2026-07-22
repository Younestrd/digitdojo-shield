import { DashboardShell } from "@/components/dashboard-shell";
import { LiveStats } from "@/components/live-stats";
import { PageHeader } from "@/components/page-header";
export default function MonitorPage() { return <DashboardShell><PageHeader title="Live monitor" description="Polling the daemon every five seconds for its current detection and traffic snapshot."/><LiveStats/></DashboardShell>; }
