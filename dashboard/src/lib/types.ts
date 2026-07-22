export type ShieldStats = {
  signals: number;
  blocked: number;
  packets_per_second: number;
  bandwidth_mbps: number;
  attack_status: string;
  firewall_backend: string;
  firewall_enforced: boolean;
};

export type BlockedResponse = { blocked: string[]; enforced: boolean };

export type APIError = { error: string };
export type Attack = { id: string; type: string; severity: string; started_at: string; resolved_at?: string; mitigation: string };
export type AttackPage = { items: Attack[]; total: number; offset: number; limit: number };
export type Metric = { timestamp: string; packets_per_second: number; connections_per_second: number; bytes_per_second: number; blocked: number; signals: number };
export type Analytics = { period: "24h" | "7d" | "30d"; metrics: Metric[]; attack_count: number; unavailable_dimensions: string[] };
export type SystemInventory = { hostname:string; distribution:string; kernel:string; architecture:string; uptime_seconds:number; cpu_model:string; cpu_cores:number; cpu_usage_percent:number; memory_total_bytes:number; memory_available_bytes:number; load_average:number[]; interfaces:{name:string;mac:string;up:boolean;addresses:string[]}[]; disks:{mount:string;total_bytes:number;used_bytes:number;available_bytes:number}[]; nftables_available:boolean; iptables_available:boolean; daemon_version:string };
