import { getCrowdSecConfig } from "./config";
import { enrichIp } from "./geo";
import type { AttackArc, AttackEvent, CrowdSecAlert, Coordinates } from "./types";

const countryCoordinates: Record<string, Coordinates> = {
  AU: [151.2093, -33.8688], BR: [-46.6333, -23.5505], CA: [-79.3832, 43.6532], CN: [116.4074, 39.9042], DE: [8.6821, 50.1109],
  ES: [-3.7038, 40.4168], FR: [2.3522, 48.8566], GB: [-0.1276, 51.5072], IN: [77.209, 28.6139], JP: [139.6917, 35.6895],
  NL: [4.9041, 52.3676], RU: [37.6173, 55.7558], SG: [103.8198, 1.3521], US: [-74.006, 40.7128], ZA: [18.4241, -33.9249]
};

export function attacksFromAlerts(alerts: readonly CrowdSecAlert[]): AttackArc[] {
  const config = getCrowdSecConfig();
  const target: Coordinates = [config.targetLng, config.targetLat];
  return alerts
    .filter((alert) => Boolean(alert.sourceIp && alert.sourceCountry && countryCoordinates[alert.sourceCountry.toUpperCase()]))
    .map((alert, index): AttackArc => {
      const country = alert.sourceCountry!.toUpperCase();
      const from = countryCoordinates[country]!;
      return {
        id: `${alert.id}-${index}`,
        sourceIp: alert.sourceIp!,
        origin: country,
        destination: config.targetName,
        from,
        to: target,
        severity: alert.severity,
        scenario: alert.scenario,
        timestamp: alert.createdAt ?? new Date().toISOString()
      };
    });
}


export async function attacksFromEvents(events: readonly AttackEvent[]): Promise<AttackArc[]> {
  const config = getCrowdSecConfig();
  const target: Coordinates = [config.targetLng, config.targetLat];
  const candidates = events.filter((event) => Boolean(event.sourceIp)).slice(0, 80);
  const enriched = await Promise.all(candidates.map(async (event) => ({ event, geo: event.sourceIp ? await enrichIp(event.sourceIp) : null })));
  return enriched.flatMap(({ event, geo }, index): AttackArc[] => {
    const country = geo?.country?.toUpperCase();
    if (!country || !countryCoordinates[country]) return [];
    return [{
      id: `access-${event.id}-${index}`,
      sourceIp: event.sourceIp!,
      origin: country,
      destination: event.host ?? config.targetName,
      from: countryCoordinates[country],
      to: target,
      severity: event.severity,
      scenario: event.scenario,
      timestamp: event.timestamp
    }];
  });
}
