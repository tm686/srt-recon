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
  // DNS Resolution
  {
    value: "dnsx",
    label: "DNSX",
    type: "dns_resolution",
    category: "DNS Resolution",
    description: "Fast DNS toolkit for bulk resolution, wildcard filtering, and DNS record enumeration",
  },
  // Live Host Discovery
  {
    value: "httpx",
    label: "HTTPX",
    type: "live_hosts",
    category: "Live Host Discovery",
    description: "Probe live HTTP/HTTPS servers with status codes, titles, tech detection, and response analysis",
  },
  // URL Crawling
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
  // Port Scanning
  {
    value: "nmap",
    label: "Nmap",
    type: "port_scan",
    category: "Port Scanning",
    description: "Network port scanner with service version detection and OS fingerprinting",
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
