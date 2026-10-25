export interface SampleCapture {
  file: string;
  title: string;
  description: string;
  expected: string[];   // detectors that should fire
  allowed: string[];    // corroborating detectors that are not counted as false positives
  benign: boolean;
}

export const SAMPLES: SampleCapture[] = [
  {
    file: 'enterprise_multistage_intrusion.pcap',
    title: 'Enterprise multi-stage intrusion',
    description: 'Synthetic 15-minute office capture: drive-by download on an odd port, TLS beaconing, ICMP sweep, port scan, SMB lateral movement, DNS tunnelling, 14 MB exfiltration, ARP spoofing, Xmas probes, cleartext FTP and Telnet — over realistic benign background traffic.',
    expected: ['rule_port_scan', 'rule_icmp_sweep', 'rule_beacon_periodicity', 'rule_dns_anomaly', 'rule_outbound_transfer', 'rule_lateral_movement', 'rule_arp_spoofing', 'rule_tcp_flag_anomaly', 'rule_cleartext_credentials', 'rule_protocol_port_mismatch'],
    allowed: ['rule_traffic_burst', 'stat_host_volume_outlier', 'ml_isolation_forest_flow', 'rule_failed_connections', 'rule_suspicious_port'],
    benign: false,
  },
  {
    file: 'office_baseline_benign.pcapng',
    title: 'Office baseline (benign, PCAPNG + IPv6)',
    description: 'Synthetic benign office traffic in PCAPNG format with IPv6 sessions — use it as a baseline for PCAP Diff and false-positive checks.',
    expected: [], allowed: ['ml_isolation_forest_flow'], benign: true,
  },
  { file: 'port_scan_recon.pcap', title: 'Vertical TCP SYN port scan', description: 'One host probes 25 ports on a target; closed ports answer with RST.', expected: ['rule_port_scan'], allowed: ['ml_isolation_forest_flow'], benign: false },
  { file: 'dns_tunneling_anomaly.pcap', title: 'DNS tunnelling + NXDOMAIN', description: 'Long, high-entropy labels under one base domain, all answered NXDOMAIN.', expected: ['rule_dns_anomaly'], allowed: ['ml_isolation_forest_flow'], benign: false },
  { file: 'c2_beaconing.pcap', title: 'C2 heartbeat beaconing', description: 'Six identical check-ins exactly two seconds apart.', expected: ['rule_beacon_periodicity'], allowed: ['ml_isolation_forest_flow'], benign: false },
  { file: 'syn_flood_burst.pcap', title: 'SYN flood burst', description: '260 SYN packets to one web server inside a single second.', expected: ['rule_traffic_burst'], allowed: ['rule_failed_connections', 'ml_isolation_forest_flow'], benign: false },
  { file: 'benign_web_browsing.pcap', title: 'Benign web browsing', description: 'One DNS lookup and a plain HTTP page fetch.', expected: [], allowed: [], benign: true },
];

export async function fetchSample(file: string): Promise<ArrayBuffer> {
  const r = await fetch(`/samples/${file}`);
  if (!r.ok) throw new Error(`Could not load sample ${file} (${r.status})`);
  return r.arrayBuffer();
}
