import { DashboardShell } from "@/components/dashboard-shell";
import { LiveStats } from "@/components/live-stats";
import { PageHeader } from "@/components/page-header";

export default function Home() {
  return <DashboardShell><PageHeader title="Security overview" description="Live state from the connected DigitDojo Shield daemon."/><LiveStats/></DashboardShell>;
}
