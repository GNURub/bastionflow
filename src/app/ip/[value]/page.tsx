import { IpDetailPage } from "@/components/ip/ip-detail-page";

export default async function Page({ params }: { params: Promise<{ value: string }> }): Promise<React.ReactElement> {
  const { value } = await params;
  return <IpDetailPage ip={decodeURIComponent(value)} />;
}
