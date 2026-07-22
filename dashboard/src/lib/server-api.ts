const configuredAPIURL = process.env.SHIELD_API_URL ?? "http://127.0.0.1:9090";

export function shieldAPIURL(path: string): URL {
  return new URL(path, configuredAPIURL.endsWith("/") ? configuredAPIURL : `${configuredAPIURL}/`);
}

export async function verifyShieldToken(token: string): Promise<boolean> {
  const response = await fetch(shieldAPIURL("/stats"), {
    headers: { Authorization: `Bearer ${token}` },
    cache: "no-store",
  });
  return response.ok;
}
