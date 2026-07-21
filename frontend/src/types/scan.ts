export interface Scan {
  id: number;
  project_id: number;
  scan_type: string;
  status: "pending" | "running" | "completed" | "failed" | "cancelled";
  tool_name: string;
  command: string;
  started_at: string | null;
  completed_at: string | null;
  error_message: string | null;
  result_count: number;
}

export interface ScanListResponse {
  scans: Scan[];
  running_count: number;
}

export interface ScanResult {
  id: number;
  scan_id: number;
  result_type: string;
  value: string;
  metadata_json: string;
}

export interface AggregatedResult {
  value: string;
  result_type: string;
  count: number;
  latest_scan_id: number;
  metadata_json: string;
}

export interface ResultStats {
  total: number;
  subdomains: number;
  urls: number;
  live_hosts: number;
  ports: number;
  directories: number;
  vulnerabilities: number;
  dns_records: number;
  screenshots: number;
}

export interface ConsolidatedEndpoint {
  value: string;
  result_type: string;
  count: number;
  status_code: number | null;
  title: string | null;
  server: string | null;
  tech: string[];
  ip: string | null;
  content_length: number | null;
  screenshot_filename: string | null;
  vulnerability_count: number;
  source_tools: string[];
  roi_score: number;
  roi_priority: "critical" | "high" | "medium" | "low";
  metadata_json: string;
}

export interface ConsolidationStats {
  total_endpoints: number;
  by_type: Record<string, number>;
  by_status: Record<string, number>;
  by_priority: Record<string, number>;
}

export interface ConsolidationResponse {
  stats: ConsolidationStats;
  endpoints: ConsolidatedEndpoint[];
}

export interface ToolDef {
  value: string;
  label: string;
  type: string;
  category: string;
  description: string;
}

export const SCAN_TOOLS: ToolDef[] = [
  // Subdomain Enumeration
  {
    value: "subfinder",
    label: "Subfinder",
    type: "subdomain_enum",
    category: "Subdomain Enumeration",
    description: "Fast passive subdomain discovery using multiple sources (APIs, search engines, CT logs)",
  },
  {
    value: "assetfinder",
    label: "Assetfinder",
    type: "subdomain_enum",
    category: "Subdomain Enumeration",
    description: "Find related domains and subdomains from various public data sources",
  },
  {
    value: "alterx",
    label: "AlterX",
    type: "subdomain_enum",
    category: "Subdomain Enumeration",
    description: "Generate subdomain permutation wordlists using pattern-based mutations",
  },
  // DNS Resolution
  {
    value: "dnsx",
    label: "DNSX",
    type: "dns_resolution",
    category: "DNS Resolution",
    description: "Fast DNS toolkit for bulk resolution, wildcard filtering, and DNS record enumeration",
  },
  // Port Scanning
  {
    value: "nmap",
    label: "Nmap",
    type: "port_scan",
    category: "Port Scanning",
    description: "Network port scanner with service version detection and OS fingerprinting",
  },
  {
    value: "rustscan",
    label: "RustScan",
    type: "port_scan",
    category: "Port Scanning",
    description: "Ultra-fast port scanner that feeds into nmap for service detection",
  },
  // Live Host Discovery
  {
    value: "httpx",
    label: "HTTPX",
    type: "live_hosts",
    category: "Live Host Discovery",
    description: "Probe live HTTP/HTTPS servers with status codes, titles, tech detection, and response analysis",
  },
  // URL Discovery
  {
    value: "gau",
    label: "GAU",
    type: "url_crawl",
    category: "URL Discovery",
    description: "Get All URLs from Wayback Machine, Common Crawl, OTX, and URLScan for a domain",
  },
  {
    value: "katana",
    label: "Katana",
    type: "url_crawl",
    category: "URL Discovery",
    description: "Next-gen web crawler with JavaScript parsing, form detection, and automatic scope control",
  },
  {
    value: "waybackurls",
    label: "Waybackurls",
    type: "url_crawl",
    category: "URL Discovery",
    description: "Fetch all known URLs for a domain from the Wayback Machine archive",
  },
  // Directory Fuzzing
  {
    value: "ffuf",
    label: "FFUF",
    type: "dir_fuzz",
    category: "Directory Fuzzing",
    description: "Fast web fuzzer for directory/file discovery, parameter brute-forcing, and vhost enumeration",
  },
  // Vulnerability Scanning
  {
    value: "nuclei",
    label: "Nuclei",
    type: "vuln_scan",
    category: "Vulnerability Scanning",
    description: "Template-based vulnerability scanner with 8000+ detection templates for CVEs, misconfigs, and exposures",
  },
  {
    value: "dalfox",
    label: "DalFox",
    type: "vuln_scan",
    category: "Vulnerability Scanning",
    description: "Parameter analysis and XSS vulnerability scanner with DOM-based detection",
  },
  {
    value: "subjack",
    label: "Subjack",
    type: "vuln_scan",
    category: "Vulnerability Scanning",
    description: "Subdomain takeover checker testing for dangling CNAME records across cloud providers",
  },
  // Screenshots & Consolidation
  {
    value: "gowitness",
    label: "GoWitness",
    type: "screenshot",
    category: "Screenshots & Consolidation",
    description: "Web screenshot capture tool for visual reconnaissance of discovered hosts",
  },
  // Notifications (display-only)
  {
    value: "notify",
    label: "Notify",
    type: "notification",
    category: "Notifications",
    description: "Alert delivery tool for sending scan results to Slack, Discord, Telegram, or email",
  },
];

// Group tools by category
export function getToolsByCategory(): Record<string, ToolDef[]> {
  const grouped: Record<string, ToolDef[]> = {};
  for (const tool of SCAN_TOOLS) {
    if (!grouped[tool.category]) grouped[tool.category] = [];
    grouped[tool.category].push(tool);
  }
  return grouped;
}

// Get a single tool definition by name
export function getToolDef(name: string): ToolDef | undefined {
  return SCAN_TOOLS.find((t) => t.value === name);
}

// ── Pipeline Phases ─────────────────────────────────────────────────

export interface PipelinePhase {
  phase: number;
  name: string;
  description: string;
  tools: string[];
  applicableCategories: string[];
}

export const PIPELINE_PHASES: PipelinePhase[] = [
  {
    phase: 1,
    name: "Subdomain Discovery",
    description: "Enumerate subdomains from passive and permutation sources",
    tools: ["subfinder", "assetfinder", "alterx"],
    applicableCategories: ["wildcard_domain"],
  },
  {
    phase: 2,
    name: "DNS Resolution",
    description: "Resolve discovered subdomains and filter wildcards",
    tools: ["dnsx"],
    applicableCategories: ["wildcard_domain"],
  },
  {
    phase: 3,
    name: "Port Scanning",
    description: "Discover open ports and running services",
    tools: ["nmap", "rustscan"],
    applicableCategories: ["wildcard_domain", "single_host", "single_ip", "cidr_range", "ip_list"],
  },
  {
    phase: 4,
    name: "Live Host Discovery",
    description: "Probe for live HTTP/HTTPS servers with tech detection",
    tools: ["httpx"],
    applicableCategories: ["wildcard_domain", "single_host", "single_ip", "cidr_range", "ip_list"],
  },
  {
    phase: 5,
    name: "URL Discovery",
    description: "Crawl and collect URLs from archives and active spidering",
    tools: ["gau", "katana", "waybackurls"],
    applicableCategories: ["wildcard_domain", "single_host"],
  },
  {
    phase: 6,
    name: "Directory Fuzzing",
    description: "Brute-force directories and files on discovered hosts",
    tools: ["ffuf"],
    applicableCategories: ["wildcard_domain", "single_host", "single_ip", "cidr_range", "ip_list"],
  },
  {
    phase: 7,
    name: "Vulnerability Scanning",
    description: "Scan for CVEs, misconfigs, XSS, and subdomain takeovers",
    tools: ["nuclei", "dalfox", "subjack"],
    applicableCategories: ["wildcard_domain", "single_host", "single_ip", "cidr_range", "ip_list"],
  },
  {
    phase: 8,
    name: "Screenshots & Consolidation",
    description: "Capture visual screenshots of all live hosts",
    tools: ["gowitness"],
    applicableCategories: ["wildcard_domain", "single_host", "single_ip", "cidr_range", "ip_list"],
  },
];
