/**
 * Unified asset graph types (newtask.md Phase C, 3.1).
 *
 * Node and edge vocabularies are closed sets (graph-sprawl guard). Every
 * node/edge is bitemporal: valid_from/valid_to model assertion intervals and
 * observed_at tracks the last observation. Nothing is deleted — nodes are
 * closed (valid_to set), history stays queryable.
 */

export const NODE_TYPES = [
  'org', 'domain', 'subdomain', 'ip', 'host', 'port', 'service', 'os',
  'webapp', 'api', 'endpoint', 'cloud_account', 'cloud_resource', 'iam_role',
  'container_image', 'certificate', 'finding', 'evidence', 'sensor',
] as const;
export type NodeType = (typeof NODE_TYPES)[number];

export const EDGE_TYPES = [
  'resolves_to', 'hosts', 'exposes', 'runs', 'member_of', 'assumes',
  'trusts', 'reachable_from', 'derived_from', 'found_on',
] as const;
export type EdgeType = (typeof EDGE_TYPES)[number];

export interface NodeAssertion {
  type: NodeType;
  /** Canonical, source-independent identity (lowercased, normalized). */
  identity: string;
  display: string;
  attributes?: Record<string, unknown>;
  provenance?: string[];
}

export interface EdgeAssertion {
  edgeType: EdgeType;
  src: NodeAssertion;
  dst: NodeAssertion;
  provenance?: string[];
}

export interface AssetNode {
  uid: string;
  type: NodeType;
  identity: string;
  display: string;
  attributes: Record<string, unknown>;
  firstSeen: string;
  lastSeen: string;
  /** Bitemporal: assertion interval. validTo = null means open. */
  validFrom: string;
  validTo: string | null;
  observedAt: string;
  provenance: string[];
}

export interface AssetEdge {
  uid: string;
  edgeType: EdgeType;
  srcUid: string;
  dstUid: string;
  firstSeen: string;
  lastSeen: string;
  validFrom: string;
  validTo: string | null;
  observedAt: string;
  provenance: string[];
}

/** OCSF-aligned observable: typed value extracted from the raw source record. */
export interface Observable {
  kind: 'ip' | 'domain' | 'port' | 'banner' | 'version' | 'cve' | 'cwe' | 'header' | 'url' | 'hash' | 'text';
  value: string;
}

/**
 * NormalizedEvent (3.1): one adapter per source; adapters emit ONLY this
 * shape. severityRaw is stored verbatim and never overwritten.
 */
export interface NormalizedEvent {
  /** OCSF-style class, e.g. 'easm.host.resolved', 'scanner.port.open', 'dast.header.missing'. */
  classUid: string;
  /** 'observed' | 'opened' | 'closed'. */
  activityId: 'observed' | 'opened' | 'closed';
  time: string;
  assetUid: string;
  sourceUid?: string | undefined;
  observables: Observable[];
  evidenceRef?: string | undefined;
  confidence: 'high' | 'medium' | 'low';
  severityRaw: string;
  severityNorm: 'critical' | 'high' | 'medium' | 'low' | 'info';
  firstSeen: string;
  lastSeen: string;
  provenance: Array<{ engine: string; rawId?: string; scanId?: string }>;
}

export interface AdapterOutput {
  events: NormalizedEvent[];
  nodes: NodeAssertion[];
  edges: EdgeAssertion[];
}
