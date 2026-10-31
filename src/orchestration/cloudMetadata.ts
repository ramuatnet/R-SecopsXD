/**
 * Cloud metadata merge (newtask.md E5) — merges cloud-side context into the
 * asset graph by the SAME asset UID (3.3: conflicts resolve to credentialed/
 * authoritative values, uncredentialed retained as history).
 *
 * Reads instance identity from an AWS IMDSv2-compatible endpoint:
 *   PUT  /latest/api/token  (TTL header) → session token
 *   GET  /latest/dynamic/instance-identity/document (token-authed) → identity JSON
 * The endpoint is configurable so the same code runs against a local
 * IMDSv2-emulating endpoint (PoC) or the real 169.254.169.254 in-cloud.
 */
import { assetUid } from '../graph/uid.ts';
import type { GraphStore } from '../graph/graph.ts';

export interface CloudIdentity {
  accountId: string;
  region: string;
  instanceId: string;
  instanceType: string;
  imageId: string;
  availabilityZone?: string | undefined;
}

export interface MergeResult {
  hostUid: string;
  cloudNodeUid: string;
  edges: string[];
}

export async function fetchCloudIdentity(imdsBase: string, timeoutMs = 5000): Promise<CloudIdentity> {
  // IMDSv2: session token first, then token-authed GETs
  const tokenRes = await fetch(`${imdsBase}/latest/api/token`, {
    method: 'PUT',
    headers: { 'x-aws-ec2-metadata-token-ttl-seconds': '21600' },
    signal: AbortSignal.timeout(timeoutMs),
  });
  if (!tokenRes.ok) throw new Error(`imds token failed (${tokenRes.status})`);
  const token = await tokenRes.text();

  const docRes = await fetch(`${imdsBase}/latest/dynamic/instance-identity/document`, {
    headers: { 'x-aws-ec2-metadata-token': token },
    signal: AbortSignal.timeout(timeoutMs),
  });
  if (!docRes.ok) throw new Error(`imds identity failed (${docRes.status})`);
  const doc = await docRes.json() as {
    accountId: string; region: string; instanceId: string; instanceType: string; imageId: string; availabilityZone?: string;
  };
  return {
    accountId: doc.accountId, region: doc.region, instanceId: doc.instanceId,
    instanceType: doc.instanceType, imageId: doc.imageId, availabilityZone: doc.availabilityZone,
  };
}

/**
 * Merge cloud identity onto a host node: a cloud_resource node carries the
 * instance context; edges: host member_of cloud_account, host runs
 * cloud_resource... per the spec the cloud view merges BY THE SAME host UID.
 */
export function mergeCloudIdentity(
  identity: CloudIdentity,
  hostIdentity: string,
  store: GraphStore,
  at = new Date().toISOString(),
): MergeResult {
  const hostUid = store.upsertNode({
    type: 'host', identity: hostIdentity, display: hostIdentity,
    attributes: { cloudAccountId: identity.accountId, cloudRegion: identity.region },
    provenance: ['cloud-metadata'],
  }, at);
  const accountUid = store.upsertNode({
    type: 'cloud_account', identity: identity.accountId, display: `aws account ${identity.accountId}`,
    attributes: { region: identity.region }, provenance: ['cloud-metadata'],
  }, at);
  const instanceUid = store.upsertNode({
    type: 'cloud_resource', identity: identity.instanceId,
    display: `instance ${identity.instanceId} (${identity.instanceType})`,
    attributes: { instanceType: identity.instanceType, imageId: identity.imageId, availabilityZone: identity.availabilityZone ?? null, region: identity.region },
    provenance: ['cloud-metadata'],
  }, at);
  const edges = [
    store.upsertEdge({ edgeType: 'member_of', src: { type: 'host', identity: hostIdentity, display: hostIdentity }, dst: { type: 'cloud_account', identity: identity.accountId, display: `aws account ${identity.accountId}` }, provenance: ['cloud-metadata'] }, at),
    store.upsertEdge({ edgeType: 'runs', src: { type: 'host', identity: hostIdentity, display: hostIdentity }, dst: { type: 'cloud_resource', identity: identity.instanceId, display: identity.instanceId }, provenance: ['cloud-metadata'] }, at),
  ];
  void assetUid;
  return { hostUid, cloudNodeUid: instanceUid, edges };
}
