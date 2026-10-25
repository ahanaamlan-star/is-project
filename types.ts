// ───────────────────────────────────────────────────────────────────────────
// NetSentry XAI — core data contracts (shared by the worker engine and the UI)
// ───────────────────────────────────────────────────────────────────────────

export const ENGINE_VERSION = '2.0.0';
export const PARSER_NAME = 'netsentry-ts-dissector';
export const PARSER_VERSION = '2.0.0';

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'informational';
export type FindingStatus = 'new' | 'under_review' | 'benign_false_positive' | 'suspicious' | 'escalated';
export type SignalSource = 'rule' | 'statistical' | 'model';
export type Confidence = 'high' | 'medium' | 'low';

export interface DnsMeta {
  id: number;
  qr: 'query' | 'response';
  rcode: number;
  rcodeName: string;
  query?: string;
  qtype?: string;
  queryLen?: number;
  entropy?: number;
  subdomainEntropy?: number;
  baseDomain?: string;
  answers?: string[];
  ancount: number;
}

export interface TlsMeta {
  type: 'ClientHello' | 'ServerHello' | 'Record';
  version?: string;
  sni?: string;
  alpn?: string[];
  ja3?: string;
  ja3Hash?: string;
  ja3s?: string;
  ja3sHash?: string;
  cipher?: string;
}

export interface HttpMeta {
  kind: 'request' | 'response';
  method?: string;
  uri?: string;
  host?: string;
  userAgent?: string;
  status?: number;
  firstLine: string;
  hasBasicAuth?: boolean;
}

export interface PacketMeta {
  dns?: DnsMeta;
  tls?: TlsMeta;
  http?: HttpMeta;
  arp?: { op: 'request' | 'reply'; senderMac: string; senderIp: string; targetMac: string; targetIp: string };
  icmp?: { type: number; code: number; label: string };
  cred?: { protocol: string; kind: string }; // presence only — never the secret itself
  ssh?: string;
  quic?: boolean;
  payloadLen?: number;
  fragment?: boolean;
}

export interface PacketRecord {
  i: number;            // 1-based packet index in capture
  ts: number;           // epoch seconds (float)
  len: number;          // original wire length
  caplen: number;       // captured length
  off: number;          // byte offset of frame data inside the capture file
  src: string | null;
  dst: string | null;
  sport: number | null;
  dport: number | null;
  transport: string;    // TCP / UDP / ICMP / ICMPv6 / ARP / IPv4 / IPv6 / OTHER
  proto: string;        // highest decoded layer label (DNS, TLS, HTTP, ...)
  flags: string;        // TCP flags e.g. "SYN+ACK"
  flagBits: number;
  ttl?: number;
  srcMac?: string;
  dstMac?: string;
  info: string;
  meta: PacketMeta;
}

export type ConnState = 'S0' | 'REJ' | 'HALF' | 'S1' | 'SF' | 'RST' | 'OTH' | 'UDP' | 'ICMP';

export interface FlowFeatures {
  duration: number;
  total_packets: number;
  total_bytes: number;
  bytes_per_packet: number;
  packet_rate: number;
  byte_rate: number;
  fwd_bwd_ratio: number;
  out_in_byte_ratio: number;
  inter_arrival_mean: number;
  inter_arrival_cv: number;
  pkt_size_std: number;
  syn_count: number;
  rst_count: number;
  dst_port_class: number; // 0 well-known, 1 registered, 2 ephemeral
}

export interface Flow {
  id: string;
  key: string;
  src: string;
  dst: string;
  sport: number | null;
  dport: number | null;
  transport: string;
  app: string;
  start: number;
  end: number;
  duration: number;
  pktsFwd: number;
  pktsBwd: number;
  bytesFwd: number;
  bytesBwd: number;
  totalPkts: number;
  totalBytes: number;
  flagCounts: Record<string, number>;
  flagsSeen: string;
  state: ConnState;
  packetIdx: number[];
  sni?: string;
  httpHost?: string;
  dnsQueries?: string[];
  ja3Hash?: string;
  features: FlowFeatures;
  anomalyScore?: number;
  isAnomaly?: boolean;
  // internal (stripped before persistence)
  _ts?: number[];
  _sizes?: number[];
}

export interface HostSummary {
  ip: string;
  internal: boolean;
  hostnames: string[];
  macs: string[];
  flowsOut: number;
  flowsIn: number;
  fanOut: number;
  fanIn: number;
  distinctDstPorts: number;
  topDstPorts: number[];
  bytesOut: number;
  bytesIn: number;
  pktsOut: number;
  pktsIn: number;
  failedConns: number;
  protocols: string[];
  firstSeen: number;
  lastSeen: number;
  role: string;
}

export interface MitreRef { id: string; name: string; tactic: string }

export interface FeatureContribution {
  feature: string;
  observed: number;
  baseline: number;
  z: number;
  share: number; // 0..1 normalised attribution share
}

export interface Explanation {
  summary: string;
  observedFacts: string[];
  ruleEvidence: string[];
  modelSignal?: string;
  interpretation: string;
  alternatives: string[];
  nextChecks: string[];
  limitations: string[];
}

export interface RiskBreakdown {
  score: number; // 0..100 (priority, NOT a probability)
  components: { severity: number; anomaly: number; evidence: number; corroboration: number; context: number };
  weights: RiskWeights;
}

export interface Finding {
  id: string;
  runId: string;
  detectorId: string;
  detectorVersion: string;
  source: SignalSource;
  category: string;
  severity: Severity;
  confidence: Confidence;
  title: string;
  scoreType: string;
  score: number;
  explanation: Explanation;
  caveats: string;
  evidence: {
    srcIp?: string;
    dstIp?: string;
    entities: string[];
    packetIdx: number[];
    flowIds: string[];
    tsRange: [number, number];
    observed: Record<string, unknown>;
    thresholds: Record<string, unknown>;
    contributions?: FeatureContribution[];
  };
  mitre: MitreRef[];
  risk?: RiskBreakdown;
  incidentId?: string;
  status: FindingStatus;
  tags: string[];
  assignee?: string;
  suppressed?: boolean;
}

export interface Incident {
  id: string;
  title: string;
  severity: Severity;
  riskMax: number;
  start: number;
  end: number;
  findingIds: string[];
  entities: string[];
  pivot: string;
  reasons: string[];
  tactics: string[];
  narrative: string;
}

export interface TimeBucket { t: number; packets: number; bytes: number; findings: number }

export interface CaptureSummary {
  format: 'pcap' | 'pcapng';
  linktypes: string[];
  totalPackets: number;
  parsedPackets: number;
  totalBytes: number;
  totalFlows: number;
  start: number | null;
  end: number | null;
  duration: number;
  protocols: Record<string, number>;
  transports: Record<string, number>;
  topSrc: Array<{ ip: string; packets: number; bytes: number }>;
  topDst: Array<{ ip: string; packets: number; bytes: number }>;
  topPorts: Array<{ port: number; flows: number }>;
  topDomains: Array<{ name: string; count: number }>;
  topSni: Array<{ name: string; count: number }>;
  hostsInternal: number;
  hostsExternal: number;
  buckets: TimeBucket[];
  bucketSeconds: number;
  truncatedPackets: number;
  bySeverity: Record<string, number>;
  byCategory: Record<string, number>;
}

export interface StageTiming { stage: string; ms: number }

export interface RiskWeights { severity: number; anomaly: number; evidence: number; corroboration: number; context: number }

export interface AnalysisConfig {
  maxPackets: number;
  maxFileMB: number;
  flowIdleTimeout: number;
  runRules: boolean;
  runML: boolean;
  runStatistical: boolean;
  ml: { trees: number; sampleSize: number; contamination: number; seed: number; minScore: number; maxFindings: number };
  thresholds: {
    scanPorts: number;
    scanWindow: number;
    sweepHosts: number;
    failedConns: number;
    failedRatio: number;
    icmpSweepHosts: number;
    dnsNxRatio: number;
    dnsLongLabel: number;
    dnsEntropy: number;
    dnsUniqueSubdomains: number;
    beaconMin: number;
    beaconCv: number;
    beaconMinInterval: number;
    floodPps: number;
    floodSynRatio: number;
    outboundMB: number;
    lateralHosts: number;
    fanInSources: number;
    statZ: number;
  };
  weights: RiskWeights;
  criticalAssets: string[];
  allowlist: string[];
  correlationWindow: number;
}

export interface AnalysisResult {
  runId: string;
  captureId: string;
  caseId: string;
  configHash: string;
  config: AnalysisConfig;
  versions: Record<string, string>;
  startedAt: string;
  finishedAt: string;
  timings: StageTiming[];
  warnings: string[];
  summary: CaptureSummary;
  packets: PacketRecord[];
  flows: Flow[];
  hosts: HostSummary[];
  findings: Finding[];
  incidents: Incident[];
  dnsMap: Record<string, string[]>;
}

export interface WorkerProgress { type: 'progress'; stage: string; pct: number; detail?: string }
