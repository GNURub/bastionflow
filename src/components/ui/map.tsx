"use client";

import * as React from "react";
import maplibregl, { type GeoJSONSource, type LngLatLike, type Map as MapLibreMap } from "maplibre-gl";
import { cn } from "@/lib/utils";

export interface MapRef {
  getMap: () => MapLibreMap | null;
  flyTo: (options: Parameters<MapLibreMap["flyTo"]>[0]) => void;
}

interface MapContextValue {
  map: MapLibreMap | null;
}

const MapContext = React.createContext<MapContextValue>({ map: null });

export interface MapProps extends React.HTMLAttributes<HTMLDivElement> {
  center: LngLatLike;
  zoom: number;
  projection?: { type: "globe" | "mercator" };
}

const darkStyle = "https://basemaps.cartocdn.com/gl/dark-matter-gl-style/style.json";
const lightStyle = "https://basemaps.cartocdn.com/gl/positron-gl-style/style.json";

export const Map = React.forwardRef<MapRef, MapProps>(({ center, zoom, projection, className, children, ...props }, ref) => {
  const containerRef = React.useRef<HTMLDivElement>(null);
  const [map, setMap] = React.useState<MapLibreMap | null>(null);

  React.useImperativeHandle(ref, () => ({
    getMap: () => map,
    flyTo: (options) => map?.flyTo(options)
  }), [map]);

  React.useEffect(() => {
    if (!containerRef.current) return;
    const prefersDark = window.matchMedia("(prefers-color-scheme: dark)").matches;
    const instance = new maplibregl.Map({
      container: containerRef.current,
      style: prefersDark ? darkStyle : lightStyle,
      center,
      zoom,
      attributionControl: false
    });
    instance.addControl(new maplibregl.AttributionControl({ compact: true }), "bottom-right");
    instance.on("load", () => {
      if (projection?.type === "globe") instance.setProjection({ type: "globe" });
      setMap(instance);
    });
    return () => {
      setMap(null);
      instance.remove();
    };
    // The MapLibre instance is intentionally created once; subsequent center/zoom changes are handled by the effect below.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  React.useEffect(() => {
    map?.easeTo({ center, zoom, duration: 600 });
  }, [center, map, zoom]);

  return (
    <MapContext.Provider value={{ map }}>
      <div ref={containerRef} className={cn("relative h-full w-full overflow-hidden rounded-xl", className)} {...props} />
      {children}
    </MapContext.Provider>
  );
});
Map.displayName = "Map";

export function MapControls({ position = "top-right", showZoom = true }: { position?: "top-right" | "top-left" | "bottom-right" | "bottom-left"; showZoom?: boolean }): null {
  const { map } = React.useContext(MapContext);
  React.useEffect(() => {
    if (!map || !showZoom) return;
    const control = new maplibregl.NavigationControl({ showCompass: true, showZoom: true });
    map.addControl(control, position);
    return () => {
      // MapLibre removes registered controls when the map instance is destroyed.
      // React can still run this child cleanup afterwards, so avoid a second
      // removeControl call when the control is already detached.
      const attachedMap = (control as maplibregl.NavigationControl & { _map?: MapLibreMap })._map;
      if (!attachedMap) return;
      try {
        attachedMap.removeControl(control);
      } catch {
        // The map is already being torn down; cleanup must be idempotent.
      }
    };
  }, [map, position, showZoom]);
  return null;
}

export interface MapArcDatum {
  id: string;
  from: readonly [number, number];
  to: readonly [number, number];
  [key: string]: unknown;
}

interface HoverEvent<T extends MapArcDatum> {
  arc: T;
  longitude: number;
  latitude: number;
}

function curve(from: readonly [number, number], to: readonly [number, number]): [number, number][] {
  const points: [number, number][] = [];
  const midLng = (from[0] + to[0]) / 2;
  const midLat = (from[1] + to[1]) / 2 + Math.min(35, Math.abs(from[0] - to[0]) * 0.18 + 8);
  for (let i = 0; i <= 40; i += 1) {
    const t = i / 40;
    const lng = (1 - t) ** 2 * from[0] + 2 * (1 - t) * t * midLng + t ** 2 * to[0];
    const lat = (1 - t) ** 2 * from[1] + 2 * (1 - t) * t * midLat + t ** 2 * to[1];
    points.push([lng, lat]);
  }
  return points;
}

type LinePaint = NonNullable<maplibregl.LineLayerSpecification["paint"]>;
function arcLineCollection<T extends MapArcDatum>(data: readonly T[]): GeoJSON.FeatureCollection<GeoJSON.LineString> {
  return {
    type: "FeatureCollection",
    features: data.map((arc) => ({
      type: "Feature",
      properties: { id: arc.id, severity: arc.severity },
      geometry: { type: "LineString", coordinates: curve(arc.from, arc.to) }
    }))
  };
}

function progressLineCollection<T extends MapArcDatum>(data: readonly T[], progress: number): GeoJSON.FeatureCollection<GeoJSON.LineString> {
  return {
    type: "FeatureCollection",
    features: data.map((arc, index) => {
      const path = curve(arc.from, arc.to);
      const shifted = (progress + index * 0.16) % 1;
      const tailLength = Math.max(3, Math.floor(path.length * 0.16));
      const headIndex = Math.min(path.length - 1, Math.max(1, Math.floor(shifted * (path.length - 1))));
      const tailIndex = Math.max(0, headIndex - tailLength);
      const coordinates = path.slice(tailIndex, headIndex + 1);
      return {
        type: "Feature",
        properties: { id: arc.id, severity: arc.severity },
        geometry: { type: "LineString", coordinates: coordinates.length > 1 ? coordinates : [[arc.from[0], arc.from[1]], [arc.to[0], arc.to[1]]] }
      };
    })
  };
}

export function MapArc<T extends MapArcDatum>({ data, paint, hoverPaint, onHover, interactive = true, animated = false, flowPaint }: { data: readonly T[]; paint?: LinePaint; hoverPaint?: LinePaint; onHover?: (event: HoverEvent<T> | null) => void; interactive?: boolean; animated?: boolean; flowPaint?: LinePaint }): null {
  const { map } = React.useContext(MapContext);
  const ids = React.useMemo(() => ({ source: `arcs-${crypto.randomUUID()}`, layer: `arcs-layer-${crypto.randomUUID()}`, flowSource: `arc-flow-${crypto.randomUUID()}`, flowLayer: `arc-flow-layer-${crypto.randomUUID()}` }), []);

  React.useEffect(() => {
    if (!map || !map.isStyleLoaded()) return;
    map.addSource(ids.source, { type: "geojson", data: arcLineCollection(data) });
    map.addLayer({
      id: ids.layer,
      type: "line",
      source: ids.source,
      layout: { "line-cap": "round", "line-join": "round" },
      paint: { "line-color": "#ef4444", "line-width": 1.5, "line-opacity": 0.78, ...(paint ?? {}) }
    });

    if (animated) {
      map.addSource(ids.flowSource, { type: "geojson", data: progressLineCollection(data, 0) });
      map.addLayer({
        id: ids.flowLayer,
        type: "line",
        source: ids.flowSource,
        layout: { "line-cap": "round", "line-join": "round" },
        paint: {
          "line-color": ["match", ["get", "severity"], "critical", "#fb7185", "high", "#fdba74", "medium", "#fde68a", "low", "#7dd3fc", "#fafafa"],
          "line-width": ["interpolate", ["linear"], ["zoom"], 0, 1.4, 3, 2.6],
          "line-opacity": 0.92,
          "line-blur": 0.35,
          ...(flowPaint ?? {})
        }
      });
    }

    const handleMove = (event: maplibregl.MapLayerMouseEvent) => {
      if (!interactive) return;
      const feature = event.features?.[0];
      if (!feature?.properties) return;
      const id = String(feature.properties.id);
      const arc = data.find((candidate) => candidate.id === id);
      if (!arc) return;
      map.getCanvas().style.cursor = "pointer";
      for (const [key, value] of Object.entries(hoverPaint ?? { "line-width": 3 })) map.setPaintProperty(ids.layer, key, value);
      onHover?.({ arc, longitude: event.lngLat.lng, latitude: event.lngLat.lat });
    };
    const handleLeave = () => {
      map.getCanvas().style.cursor = "";
      if (hoverPaint) for (const key of Object.keys(hoverPaint)) map.setPaintProperty(ids.layer, key, paint?.[key as keyof LinePaint] ?? (key === "line-width" ? 1.5 : undefined));
      onHover?.(null);
    };
    map.on("mousemove", ids.layer, handleMove);
    map.on("mouseleave", ids.layer, handleLeave);
    return () => {
      // MapLibre can already be in teardown when React runs this cleanup.
      // Every map operation below must be defensive/idempotent.
      try { map.off("mousemove", ids.layer, handleMove); } catch {}
      try { map.off("mouseleave", ids.layer, handleLeave); } catch {}
      try { if (map.getLayer(ids.flowLayer)) map.removeLayer(ids.flowLayer); } catch {}
      try { if (map.getSource(ids.flowSource)) map.removeSource(ids.flowSource); } catch {}
      try { if (map.getLayer(ids.layer)) map.removeLayer(ids.layer); } catch {}
      try { if (map.getSource(ids.source)) map.removeSource(ids.source); } catch {}
    };
  }, [animated, data, flowPaint, hoverPaint, ids.flowLayer, ids.flowSource, ids.layer, ids.source, interactive, map, onHover, paint]);

  React.useEffect(() => {
    if (!map || !animated || !map.getSource(ids.flowSource)) return;
    let frame = 0;
    const started = performance.now();
    const tick = (now: number) => {
      const progress = ((now - started) / 2200) % 1;
      try {
        const source = map.getSource(ids.flowSource) as GeoJSONSource | undefined;
        source?.setData(progressLineCollection(data, progress));
        frame = requestAnimationFrame(tick);
      } catch {
        cancelAnimationFrame(frame);
      }
    };
    frame = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(frame);
  }, [animated, data, ids.flowSource, map]);

  return null;
}

export function MapMarker({ longitude, latitude, children }: { longitude: number; latitude: number; children: React.ReactNode }): null {
  const { map } = React.useContext(MapContext);
  React.useEffect(() => {
    if (!map) return;
    const element = document.createElement("div");
    const root = document.createElement("div");
    element.appendChild(root);
    const marker = new maplibregl.Marker({ element }).setLngLat([longitude, latitude]).addTo(map);
    void import("react-dom/client").then(({ createRoot }) => {
      const reactRoot = createRoot(root);
      reactRoot.render(<>{children}</>);
      marker.getElement().dataset.root = "mounted";
    });
    return () => { marker.remove(); };
  }, [children, latitude, longitude, map]);
  return null;
}

export function MarkerContent({ className, ...props }: React.HTMLAttributes<HTMLDivElement>): React.ReactElement {
  return <div className={cn("flex flex-col items-center gap-1", className)} {...props} />;
}
export function MarkerLabel({ className, ...props }: React.HTMLAttributes<HTMLDivElement> & { position?: "top" | "bottom" }): React.ReactElement {
  return <div className={cn("rounded bg-background/80 px-1.5 py-0.5 text-[10px] text-foreground shadow backdrop-blur", className)} {...props} />;
}

export function MapPopup({ longitude, latitude, children, className }: { longitude: number; latitude: number; children: React.ReactNode; className?: string; offset?: number; closeOnClick?: boolean }): React.ReactElement {
  return <div className={cn("pointer-events-none absolute left-4 top-4 z-10 rounded-md border bg-background/90 text-foreground shadow-xl backdrop-blur", className)} data-lng={longitude} data-lat={latitude}>{children}</div>;
}
