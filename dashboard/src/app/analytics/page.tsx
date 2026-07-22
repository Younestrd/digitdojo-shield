import { AnalyticsChart } from "@/components/analytics-chart"; import { DashboardShell } from "@/components/dashboard-shell"; import { PageHeader } from "@/components/page-header";
export default function AnalyticsPage() { return <DashboardShell><PageHeader title="Analytics" description="Persisted host-level traffic and detector activity."/><AnalyticsChart/></DashboardShell>; }
