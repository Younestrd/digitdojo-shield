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
