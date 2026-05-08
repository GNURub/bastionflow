import { reverse } from "node:dns/promises";
import { classifyIp, getCachedIpIntel, upsertIpIntel, type CachedIpIntel } from "./store";
import type { CrowdSecAlert, CrowdSecDecision } from "./types";

type JsonRecord = Record<string, unknown>;

interface GeoProvider {
  name: string;
  url: (ip: string) => string;
}

interface PublicTargetLocation {
  name: string;
  latitude: number;
  longitude: number;
  provider: string;
}

let publicTargetLocationCache: { expiresAt: number; value: PublicTargetLocation } | null = null;

function record(value: unknown): JsonRecord {
  return value && typeof value === "object" ? value as JsonRecord : {};
}

function text(value: unknown): string | undefined {
  if (typeof value === "string" && value.trim()) return value.trim();
  if (typeof value === "number" && Number.isFinite(value)) return String(value);
  return undefined;
}

function numberValue(value: unknown): number | undefined {
  return typeof value === "number" && Number.isFinite(value) ? value : undefined;
}

function coordinatesFromLoc(value: unknown): { latitude?: number; longitude?: number } {
  const loc = text(value);
  if (!loc) return {};
  const [latRaw, lonRaw] = loc.split(",").map((part) => Number(part.trim()));
  return typeof latRaw === "number" && typeof lonRaw === "number" && Number.isFinite(latRaw) && Number.isFinite(lonRaw) ? { latitude: latRaw, longitude: lonRaw } : {};
}

function boolValue(value: unknown): boolean | undefined {
  return typeof value === "boolean" ? value : undefined;
}

function normalizeCountry(value?: string): string | undefined {
  const trimmed = value?.trim().toUpperCase();
  return trimmed && /^[A-Z]{2}$/.test(trimmed) ? trimmed : undefined;
}

function listText(value: unknown): string | undefined {
  if (Array.isArray(value)) return value.map((item) => text(item)).filter(Boolean).join(", ") || undefined;
  return text(value);
}

function templateProvider(url: string, index: number): GeoProvider {
  return { name: `custom-${index + 1}`, url: (ip) => url.replaceAll("{ip}", encodeURIComponent(ip)) };
}

function geoProviders(): GeoProvider[] {
  const configured = process.env.CROWDSEC_GEOIP_LOOKUP_URLS?.trim();
  if (configured) {
    if (["none", "disabled", "false"].includes(configured.toLowerCase())) return [];
    return configured.split(",").map((item) => item.trim()).filter(Boolean).map(templateProvider);
  }
  return [
    { name: "ipwho.is", url: (ip) => `https://ipwho.is/${encodeURIComponent(ip)}` },
    { name: "ipapi.co", url: (ip) => `https://ipapi.co/${encodeURIComponent(ip)}/json/` },
    { name: "freeipapi", url: (ip) => `https://free.freeipapi.com/api/json/${encodeURIComponent(ip)}` },
    { name: "ipwho.org", url: (ip) => `https://api.ipwho.org/ip/${encodeURIComponent(ip)}` },
    { name: "ip-api.com", url: (ip) => `http://ip-api.com/json/${encodeURIComponent(ip)}?fields=status,country,countryCode,regionName,city,zip,lat,lon,timezone,currency,isp,org,as,asname,mobile,proxy,hosting,query` }
  ];
}

function publicTargetGeoProviders(): GeoProvider[] {
  const configured = process.env.CROWDSEC_TARGET_GEO_LOOKUP_URLS?.trim();
  if (configured) {
    if (["none", "disabled", "false"].includes(configured.toLowerCase())) return [];
    return configured.split(",").map((item) => item.trim()).filter(Boolean).map((url, index) => ({ name: `target-custom-${index + 1}`, url: () => url }));
  }
  return [
    { name: "ipwho.is", url: () => "https://ipwho.is/" },
    { name: "ipapi.co", url: () => "https://ipapi.co/json/" },
    { name: "ipinfo.io", url: () => "https://ipinfo.io/json" },
    { name: "freeipapi", url: () => "https://free.freeipapi.com/api/json" },
    { name: "ip-api.com", url: () => "http://ip-api.com/json/?fields=status,country,countryCode,regionName,city,lat,lon,timezone,currency,isp,org,as,asname,mobile,proxy,hosting,query" },
    { name: "ip.sb", url: () => "https://api.ip.sb/geoip" }
  ];
}

function parseGeo(body: unknown, provider: string): Omit<CachedIpIntel, "ip"> | null {
  const root = Array.isArray(body) ? record(body[0]) : record(body);
  const nestedData = record(root.data);
  const source = Object.keys(nestedData).length > 0 ? nestedData : root;
  if (source.success === false || source.status === "fail" || source.error === true) return null;

  const connection = record(source.connection);
  const asn = record(source.asn);
  const timezone = record(source.timezone);
  const currency = record(source.currency);

  const countryText = text(source.country);
  const country = normalizeCountry(
    text(source.country_code) ??
    text(source.countryCode) ??
    text(source.country_code_iso2) ??
    text(source.countryCode2) ??
    (countryText?.length === 2 ? countryText : undefined)
  );
  const countryName = text(source.country_name) ?? text(source.countryName) ?? (country && countryText?.length !== 2 ? countryText : undefined);
  const city = text(source.city) ?? text(source.cityName);
  const region = text(source.region) ?? text(source.regionName) ?? text(source.region_name);
  const continent = text(source.continent);
  const continentCode = text(source.continent_code) ?? text(source.continentCode);
  const postalCode = text(source.postal) ?? text(source.zip) ?? text(source.zipCode) ?? text(source.postal_Code);
  const locCoordinates = coordinatesFromLoc(source.loc);
  const latitude = numberValue(source.latitude) ?? numberValue(source.lat) ?? locCoordinates.latitude;
  const longitude = numberValue(source.longitude) ?? numberValue(source.lon) ?? locCoordinates.longitude;
  const timezoneName = text(source.timezone) ?? text(source.time_zone) ?? text(timezone.id) ?? text(timezone.time_zone);
  const currencyCode = text(source.currency) ?? text(currency.code) ?? listText(source.currencies);
  const languages = listText(source.languages);
  const asnValue = text(source.asn) ?? text(asn.number);
  const asName =
    text(connection.org) ??
    text(connection.isp) ??
    text(asn.org) ??
    text(source.asnOrganization) ??
    text(source.asname) ??
    text(source.as_name) ??
    text(source.org) ??
    text(source.isp) ??
    text(source.as);
  const isp = text(source.isp) ?? text(connection.isp);
  const org = text(source.org) ?? text(connection.org);
  const isProxy = boolValue(source.proxy) ?? boolValue(source.isProxy);
  const isHosting = boolValue(source.hosting) ?? boolValue(source.isHosting);
  const isMobile = boolValue(source.mobile) ?? boolValue(source.isMobile);

  const enrichment: Omit<CachedIpIntel, "ip"> = {
    country,
    countryName,
    city,
    region,
    continent,
    continentCode,
    postalCode,
    latitude,
    longitude,
    timezone: timezoneName,
    currency: currencyCode,
    languages,
    asn: asnValue,
    asName,
    isp,
    org,
    isProxy,
    isHosting,
    isMobile,
    provider
  };
  const hasValue = Object.entries(enrichment).some(([key, value]) => key !== "provider" && value !== undefined && value !== null && value !== "");
  return hasValue ? enrichment : null;
}

export async function getPublicTargetLocation(): Promise<PublicTargetLocation | null> {
  if (publicTargetLocationCache && publicTargetLocationCache.expiresAt > Date.now()) return publicTargetLocationCache.value;
  for (const provider of publicTargetGeoProviders()) {
    try {
      const response = await fetch(provider.url(""), { headers: { accept: "application/json", "user-agent": "bastionflow/0.1" }, cache: "no-store", signal: AbortSignal.timeout(2_500) });
      if (!response.ok) continue;
      const enrichment = parseGeo(await response.json(), provider.name);
      if (enrichment?.latitude === undefined || enrichment.longitude === undefined) continue;
      const nameParts = [enrichment.city, enrichment.region, enrichment.countryName ?? enrichment.country].filter(Boolean);
      const value = {
        name: nameParts.length > 0 ? nameParts.join(", ") : "Detected edge location",
        latitude: enrichment.latitude,
        longitude: enrichment.longitude,
        provider: provider.name
      };
      publicTargetLocationCache = { value, expiresAt: Date.now() + 6 * 60 * 60_000 };
      return value;
    } catch {}
  }
  return null;
}

export async function enrichReverseDns(ip: string): Promise<CachedIpIntel | null> {
  const cached = getCachedIpIntel(ip);
  if (cached?.reverseDns) return cached;
  if (!classifyIp(ip).isPublic) return cached;
  try {
    const names = await reverse(ip);
    const reverseDns = names[0];
    if (!reverseDns) return cached;
    upsertIpIntel(ip, { reverseDns, provider: cached?.provider ?? "reverse-dns" });
    return { ...(cached ?? { ip }), reverseDns };
  } catch {
    return cached;
  }
}

export async function enrichIp(ip: string): Promise<CachedIpIntel | null> {
  const cached = getCachedIpIntel(ip);
  if (cached?.country && cached?.asName && cached?.city) {
    void enrichReverseDns(ip);
    return cached;
  }
  if (!classifyIp(ip).isPublic) return cached;

  for (const provider of geoProviders()) {
    try {
      const response = await fetch(provider.url(ip), { headers: { accept: "application/json", "user-agent": "bastionflow/0.1" }, cache: "no-store", signal: AbortSignal.timeout(2_500) });
      if (!response.ok) continue;
      const enrichment = parseGeo(await response.json(), provider.name);
      if (!enrichment) continue;
      upsertIpIntel(ip, enrichment);
      await enrichReverseDns(ip);
      return { ip, ...enrichment };
    } catch {}
  }
  await enrichReverseDns(ip);
  return getCachedIpIntel(ip) ?? cached;
}

export async function enrichAlertsWithGeo(alerts: readonly CrowdSecAlert[]): Promise<CrowdSecAlert[]> {
  return Promise.all(alerts.map(async (alert) => {
    if (!alert.sourceIp || alert.sourceCountry) return alert;
    const geo = await enrichIp(alert.sourceIp);
    return geo?.country || geo?.asName ? { ...alert, sourceCountry: geo.country ?? alert.sourceCountry, sourceAsName: geo.asName ?? alert.sourceAsName } : alert;
  }));
}

export async function enrichDecisionsWithGeo(decisions: readonly CrowdSecDecision[]): Promise<CrowdSecDecision[]> {
  return Promise.all(decisions.map(async (decision) => {
    if (decision.scope !== "ip" || decision.country) return decision;
    const geo = await enrichIp(decision.value);
    return geo?.country || geo?.asName ? { ...decision, country: geo.country ?? decision.country, asName: geo.asName ?? decision.asName } : decision;
  }));
}
