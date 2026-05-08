"use client";

import Link from "next/link";
import { useEffect, useMemo, useState } from "react";
import type { ExpressionSpecification } from "maplibre-gl";
import { Activity } from "lucide-react";
import { Card } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Map, MapArc, MapControls, MapMarker, MapPopup, MarkerContent, MarkerLabel, type MapArcDatum } from "@/components/ui/map";
import type { AttackArc, Severity } from "@/lib/crowdsec/types";

const severityColors: Record<Severity, string> = {
  critical: "#ef4444",
  high: "#f97316",
  medium: "#f59e0b",
  low: "#38bdf8",
  info: "#a1a1aa"
};

interface AttackArcDatum extends AttackArc, MapArcDatum {}

export function AttackMap({ initial }: { initial: AttackArc[] }): React.ReactElement {
  const [arcs, setArcs] = useState<AttackArc[]>(initial);
  const [selected, setSelected] = useState<{ arc: AttackArcDatum; longitude: number; latitude: number } | null>(null);

  useEffect(() => {
    const source = new EventSource("/api/attacks/stream");
    source.addEventListener("attacks", (event) => {
      const next = JSON.parse((event as MessageEvent<string>).data) as AttackArc[];
      setArcs(next);
    });
    return () => source.close();
  }, []);

  const endpoints = useMemo(() => {
    const points = new globalThis.Map<string, { name: string; coords: readonly [number, number]; severity?: Severity }>();
    for (const arc of arcs) {
      points.set(`${arc.origin}:${arc.from.join(",")}`, { name: arc.origin, coords: arc.from, severity: arc.severity });
      points.set(`${arc.destination}:${arc.to.join(",")}`, { name: arc.destination, coords: arc.to });
    }
    return [...points.values()];
  }, [arcs]);

  const colorExpression: ExpressionSpecification = [
    "match", ["get", "severity"],
    "critical", severityColors.critical,
    "high", severityColors.high,
    "medium", severityColors.medium,
    "low", severityColors.low,
    severityColors.info
  ];

  return (
    <Card className="relative h-[520px] overflow-hidden border-white/10 bg-black p-0">
      <div className="absolute left-4 top-4 z-10 flex items-center gap-2 rounded-full border bg-background/80 px-3 py-1 text-xs shadow-xl backdrop-blur">
        <Activity className="h-3.5 w-3.5 text-red-400" /> Live attack arcs <Badge variant="secondary">{arcs.length}</Badge>
      </div>
      <Map center={[12, 28]} zoom={1.05} projection={{ type: "globe" }}>
        <MapControls position="top-right" />
        <MapArc<AttackArcDatum>
          data={arcs as AttackArcDatum[]}
          paint={{ "line-color": colorExpression, "line-width": 1.6, "line-opacity": 0.82 }}
          hoverPaint={{ "line-width": 3, "line-opacity": 1 }}
          animated
          flowPaint={{ "line-width": ["interpolate", ["linear"], ["zoom"], 0, 1.7, 3, 3], "line-blur": 0.2 }}
          onHover={(event) => setSelected(event ? { arc: event.arc, longitude: event.longitude, latitude: event.latitude } : null)}
        />
        {endpoints.map((point) => (
          <MapMarker key={`${point.name}-${point.coords.join(",")}`} longitude={point.coords[0]} latitude={point.coords[1]}>
            <MarkerContent>
              <div className="size-2.5 rounded-full border border-white bg-red-500 shadow-[0_0_18px_rgba(239,68,68,.8)]" style={{ backgroundColor: point.severity ? severityColors[point.severity] : "#fafafa" }} />
              <MarkerLabel>{point.name}</MarkerLabel>
            </MarkerContent>
          </MapMarker>
        ))}
        {selected && (
          <MapPopup longitude={selected.longitude} latitude={selected.latitude} className="p-0">
            <div className="space-y-1 px-3 py-2 text-xs">
              <div className="font-medium">{selected.arc.origin} → {selected.arc.destination}</div>
              <Link className="font-mono text-muted-foreground underline-offset-4 hover:text-amber-300 hover:underline" href={`/ip/${encodeURIComponent(selected.arc.sourceIp)}`}>{selected.arc.sourceIp}</Link>
              <div className="text-muted-foreground">{selected.arc.scenario}</div>
            </div>
          </MapPopup>
        )}
      </Map>
      <div className="absolute bottom-4 left-4 z-10 flex flex-wrap gap-2 rounded-full border bg-background/80 px-3 py-1 text-[11px] backdrop-blur">
        {Object.entries(severityColors).map(([severity, color]) => <span key={severity} className="flex items-center gap-1.5"><span className="size-1.5 rounded-full" style={{ backgroundColor: color }} />{severity}</span>)}
      </div>
    </Card>
  );
}
