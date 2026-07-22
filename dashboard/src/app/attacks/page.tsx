import { AttackHistory } from "@/components/attack-history"; import { DashboardShell } from "@/components/dashboard-shell"; import { PageHeader } from "@/components/page-header";
export default function AttacksPage() { return <DashboardShell><PageHeader title="Attack center" description="Detector-derived lifecycle records retained by this Shield daemon."/><AttackHistory/></DashboardShell>; }
