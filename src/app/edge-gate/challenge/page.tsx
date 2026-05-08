import { EdgeGateChallengePage } from "@/components/edge-gate/challenge-page";

export default async function Page({ searchParams }: { searchParams: Promise<{ next?: string; required?: string }> }): Promise<React.ReactElement> {
  const params = await searchParams;
  return <EdgeGateChallengePage next={params.next ?? "/"} required={(params.required ?? "bot").split(",").filter(Boolean)} />;
}
