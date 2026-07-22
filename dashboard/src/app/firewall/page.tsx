import { DashboardShell } from "@/components/dashboard-shell";
import { FirewallConsole } from "@/components/firewall-console";
import { PageHeader } from "@/components/page-header";
export default function FirewallPage() { return <DashboardShell><PageHeader title="Firewall" description="Review the Shield-managed block list and enforcement status."/><FirewallConsole/></DashboardShell>; }
