/**
 * Sensor registry (newtask.md E1 — registration half).
 *
 * Sensors are the scanning workforce: three tiers per the architecture spec —
 * external (egress IPs), internal (one per VPC/subnet, no inbound), and
 * cloud-readonly (API credentials, no packets). Registration, heartbeats and
 * capability declaration are implemented here; each registered sensor becomes
 * a `sensor` node in the asset graph so work assignment and attribution are
 * graph-queryable. The distributed deployment (containers pulling from the
 * bus) registers through this same surface.
 */
import type { GraphStore } from '../graph/graph.ts';

export type SensorTier = 'external' | 'internal' | 'cloud-readonly';

export const SENSOR_TIERS: SensorTier[] = ['external', 'internal', 'cloud-readonly'];

export interface SensorRegistration {
  id: string;
  tier: SensorTier;
  /** Capability tags, e.g. ['http', 'tcp', 'cloud-describe']. */
  capabilities: string[];
  /** Placement context: egress IP, VPC/subnet id, or cloud account. */
  network?: string | undefined;
}

export interface SensorState extends SensorRegistration {
  registeredAt: string;
  lastHeartbeat: string;
  /** Work counter — how many scan requests this sensor has claimed. */
  claimed: number;
}

const STALE_MS = 5 * 60 * 1000;

export class SensorRegistry {
  private readonly sensors = new Map<string, SensorState>();
  private readonly graph: GraphStore | undefined;

  constructor(graph?: GraphStore) {
    this.graph = graph;
  }

  register(reg: SensorRegistration, at = new Date().toISOString()): SensorState {
    if (!SENSOR_TIERS.includes(reg.tier)) throw new Error(`invalid sensor tier: ${reg.tier}`);
    if (reg.id.trim() === '') throw new Error('sensor id required');
    const state: SensorState = { ...reg, registeredAt: at, lastHeartbeat: at, claimed: 0 };
    this.sensors.set(reg.id, state);
    this.graph?.upsertNode({
      type: 'sensor',
      identity: reg.id,
      display: `sensor ${reg.id} (${reg.tier})`,
      attributes: { tier: reg.tier, capabilities: reg.capabilities, network: reg.network ?? null, lastHeartbeat: at },
      provenance: ['sensor-registry'],
    });
    return state;
  }

  heartbeat(id: string, at = new Date().toISOString()): void {
    const s = this.sensors.get(id);
    if (s === undefined) throw new Error(`unknown sensor: ${id}`);
    s.lastHeartbeat = at;
  }

  /** A sensor claims a work item — attribution for provenance. */
  claimWork(id: string): void {
    const s = this.sensors.get(id);
    if (s === undefined) throw new Error(`unknown sensor: ${id}`);
    s.claimed += 1;
  }

  list(tier?: SensorTier): SensorState[] {
    return [...this.sensors.values()]
      .filter((s) => tier === undefined || s.tier === tier)
      .sort((a, b) => a.id.localeCompare(b.id));
  }

  /** Sensor is alive = heartbeat within the stale window. */
  isAlive(id: string, now = Date.now()): boolean {
    const s = this.sensors.get(id);
    return s !== undefined && now - Date.parse(s.lastHeartbeat) < STALE_MS;
  }

  /** Pick the best alive sensor for a capability requirement (round-robin by claim count). */
  pick(capability: string, tier?: SensorTier): SensorState | undefined {
    const candidates = this.list(tier)
      .filter((s) => s.capabilities.includes(capability) && this.isAlive(s.id))
      .sort((a, b) => a.claimed - b.claimed);
    return candidates[0];
  }
}
