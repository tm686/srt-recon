export type TargetType = "ip" | "ip_range" | "url" | "wildcard_domain";
export type ScopeDirection = "in_scope" | "out_of_scope";
export type ProjectCategory = "wildcard_domain" | "single_host" | "single_ip" | "cidr_range" | "ip_list";

export interface Target {
  id: number;
  project_id: number;
  value: string;
  target_type: TargetType;
  direction: ScopeDirection;
}

export interface Project {
  id: number;
  name: string;
  description: string;
  category: ProjectCategory;
  target_value: string;
  created_at: string;
  updated_at: string;
  targets: Target[];
}

export interface ProjectListItem {
  id: number;
  name: string;
  description: string;
  category: ProjectCategory;
  target_value: string;
  created_at: string;
  updated_at: string;
  target_count: number;
}

export interface ScopeValidateResponse {
  in_scope: string[];
  out_of_scope: string[];
}

export const PROJECT_CATEGORIES = [
  {
    value: "wildcard_domain" as const,
    label: "Wildcard Domain",
    description: "*.target.com — full subdomain enumeration, crawling, fuzzing, vuln scanning",
    placeholder: "*.example.com",
  },
  {
    value: "single_host" as const,
    label: "Single HTTPS Host",
    description: "https://app.target.com — crawling, URL discovery, fuzzing, vuln scanning",
    placeholder: "https://app.example.com",
  },
  {
    value: "single_ip" as const,
    label: "Single IP",
    description: "192.168.1.1 — port scanning, service detection, vulnerability scanning",
    placeholder: "10.0.0.1",
  },
  {
    value: "cidr_range" as const,
    label: "CIDR Range",
    description: "192.168.1.0/24 — range port scanning, host discovery, vuln scanning",
    placeholder: "10.0.0.0/24",
  },
  {
    value: "ip_list" as const,
    label: "IP Address List",
    description: "Paste a list of IPs — port scanning, service detection, vuln scanning per IP",
    placeholder: "10.0.0.1\n10.0.0.5\n10.0.0.12",
  },
] as const;
