import type { Analytics, AttackPage, BlockedResponse, ShieldStats } from "@/lib/types";

const proxyBase = "/api/shield";

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${proxyBase}${path}`, {
    ...init,
    headers: { "Content-Type": "application/json", ...init?.headers },
    cache: "no-store",
  });
  if (!response.ok) {
    const body = (await response.json().catch(() => ({ error: response.statusText }))) as { error?: string };
    throw new Error(body.error || `Shield API request failed (${response.status})`);
  }
  return response.json() as Promise<T>;
}

export const shieldAPI = {
  stats: () => request<ShieldStats>("/stats"),
  blocked: () => request<BlockedResponse>("/blocked"),
  blacklist: (ip: string) => request<void>("/blacklist", { method: "POST", body: JSON.stringify({ ip }) }),
  whitelist: (ip: string) => request<void>("/whitelist", { method: "POST", body: JSON.stringify({ ip }) }),
  unban: (ip: string) => request<void>("/unban", { method: "POST", body: JSON.stringify({ ip }) }),
  attacks: (offset = 0, limit = 50) => request<AttackPage>(`/attacks?offset=${offset}&limit=${limit}`),
  analytics: (period: "24h" | "7d" | "30d") => request<Analytics>(`/analytics?period=${period}`),
};
