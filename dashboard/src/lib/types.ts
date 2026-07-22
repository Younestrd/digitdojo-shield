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
