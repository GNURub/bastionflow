import { Badge } from "@/components/ui/badge";
import type { ApiEnvelope } from "@/lib/crowdsec/types";

export function SourcePill({ source, error }: Pick<ApiEnvelope<unknown>, "source" | "error">): React.ReactElement {
  if (error) return <Badge variant="warning">{source}: {error}</Badge>;
  return <Badge variant={source === "crowdsec" ? "success" : "secondary"}>{source}</Badge>;
}
