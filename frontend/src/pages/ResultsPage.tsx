import { useState, useEffect } from "react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Dialog,
  DialogContent,
} from "@/components/ui/dialog";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Download, Search, Trash2, ExternalLink } from "lucide-react";
import { useProjects } from "@/hooks/useProjects";
import { useResults } from "@/hooks/useResults";

const RESULT_TYPES = [
  { value: "", label: "All Types" },
  { value: "subdomain", label: "Subdomains" },
  { value: "live_host", label: "Live Hosts" },
  { value: "url", label: "URLs" },
  { value: "port", label: "Ports" },
  { value: "directory", label: "Directories" },
  { value: "vulnerability", label: "Vulnerabilities" },
  { value: "dns_record", label: "DNS Records" },
  { value: "screenshot", label: "Screenshots" },
  { value: "exploit", label: "Exploits" },
];

// ── Severity Badge ──────────────────────────────────────────────────
const SEVERITY_COLORS: Record<string, string> = {
  critical: "bg-red text-white",
  high: "bg-orange-500 text-white",
  medium: "bg-yellow text-background",
  low: "bg-blue-500 text-white",
  info: "bg-text-muted/30 text-text",
};

function SeverityBadge({ severity }: { severity: string }) {
  const s = (severity || "").toLowerCase();
  const cls = SEVERITY_COLORS[s] || "bg-text-muted/20 text-text-muted";
  return (
    <span className={`inline-block px-1.5 py-0.5 rounded text-[10px] font-bold uppercase ${cls}`}>
      {s || "unknown"}
    </span>
  );
}

function StatusBadge({ code }: { code: number | undefined }) {
  if (!code) return null;
  const cls =
    code < 300 ? "bg-green/20 text-green" :
    code < 400 ? "bg-yellow/20 text-yellow" :
    code < 500 ? "bg-orange-500/20 text-orange-400" :
    "bg-red/20 text-red";
  return <span className={`inline-block px-1.5 py-0.5 rounded text-[10px] font-bold ${cls}`}>{code}</span>;
}

// ── Metadata Details renderer ───────────────────────────────────────
// eslint-disable-next-line @typescript-eslint/no-explicit-any
function safeParse(json: string): Record<string, any> {
  try {
    return JSON.parse(json || "{}");
  } catch {
    return {};
  }
}

function MetadataDetails({ resultType, metadataJson, value, projectId }: {
  resultType: string;
  metadataJson: string;
  value: string;
  projectId: number;
}) {
  const m = safeParse(metadataJson);

  // Skip empty metadata
  const hasData = Object.keys(m).some((k) => m[k] !== null && m[k] !== undefined && m[k] !== "");
  if (!hasData) return <span className="text-text-muted">-</span>;

  switch (resultType) {
    case "vulnerability":
      return (
        <div className="flex items-center gap-2 flex-wrap">
          {m.severity && <SeverityBadge severity={String(m.severity)} />}
          {m.name && <span className="text-text text-xs">{String(m.name)}</span>}
          {m.template_id && <span className="text-text-muted text-[10px] font-mono">{String(m.template_id)}</span>}
          {m.service && <span className="text-text text-xs">{String(m.service)}</span>}
          {m.type && <span className="text-orange-400 text-xs">{String(m.type)}</span>}
        </div>
      );

    case "live_host":
      return (
        <div className="flex items-center gap-2 flex-wrap">
          {m.status_code && <StatusBadge code={Number(m.status_code)} />}
          {m.title && <span className="text-text text-xs">{String(m.title)}</span>}
          {m.server && <span className="text-text-muted text-[10px]">{String(m.server)}</span>}
          {Array.isArray(m.tech) && m.tech.length > 0 && (
            <div className="flex gap-1 flex-wrap">
              {(m.tech as string[]).slice(0, 3).map((t) => (
                <Badge key={t} variant="secondary" className="text-[9px]">{t}</Badge>
              ))}
              {(m.tech as string[]).length > 3 && (
                <span className="text-text-muted text-[10px]">+{(m.tech as string[]).length - 3}</span>
              )}
            </div>
          )}
        </div>
      );

    case "port":
      return (
        <span className="text-xs">
          {m.hostname && <span className="text-purple-400 mr-1">{String(m.hostname)}</span>}
          {m.service && <span className="text-green mr-1">{String(m.service)}</span>}
          {m.version && <span className="text-text mr-1">{String(m.version)}</span>}
          {m.protocol && <span className="text-text-muted">/{String(m.protocol)}</span>}
        </span>
      );

    case "directory":
      return (
        <span className="text-xs flex items-center gap-2">
          {m.status && <StatusBadge code={Number(m.status)} />}
          {m.length != null && <span className="text-text-muted">{String(m.length)} bytes</span>}
        </span>
      );

    case "dns_record": {
      const records = ["a", "aaaa", "cname", "mx", "ns", "txt"]
        .filter((k) => m[k])
        .map((k) => `${k.toUpperCase()}: ${Array.isArray(m[k]) ? (m[k] as string[]).join(", ") : String(m[k])}`)
        .join(" | ");
      return <span className="text-xs text-text-muted">{records || "-"}</span>;
    }

    case "screenshot":
      return (
        <img
          src={`/api/screenshots/${projectId}/${value}`}
          alt={value}
          className="w-48 h-auto rounded border border-border cursor-pointer hover:border-cyan hover:shadow-lg transition-all"
          loading="lazy"
          onDoubleClick={() => {
            // Dispatch custom event to open lightbox in parent
            window.dispatchEvent(
              new CustomEvent("screenshot-lightbox", { detail: { filename: value, projectId } })
            );
          }}
          title="Double-click to enlarge"
        />
      );

    default:
      return <span className="text-text-muted">-</span>;
  }
}

export function ResultsPage() {
  const { projects } = useProjects();
  const [selectedProject, setSelectedProject] = useState<string>("");
  const [resultType, setResultType] = useState("");
  const [search, setSearch] = useState("");
  const [searchInput, setSearchInput] = useState("");
  const [lightbox, setLightbox] = useState<{ filename: string; projectId: number } | null>(null);

  // Listen for screenshot-lightbox events from MetadataDetails
  useEffect(() => {
    const handler = (e: Event) => {
      const detail = (e as CustomEvent).detail;
      setLightbox({ filename: detail.filename, projectId: detail.projectId });
    };
    window.addEventListener("screenshot-lightbox", handler);
    return () => window.removeEventListener("screenshot-lightbox", handler);
  }, []);

  const projectId = selectedProject ? Number(selectedProject) : 0;
  const { results, stats, loading, clearResults } = useResults(
    projectId || -1,
    resultType || undefined,
    search || undefined
  );

  const handleSearch = () => setSearch(searchInput);

  const exportUrl = (format: string) => {
    const params = new URLSearchParams();
    if (resultType) params.set("result_type", resultType);
    return `/api/projects/${projectId}/export/${format}?${params}`;
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-lg font-bold">Results</h1>
        {projectId > 0 && (
          <div className="flex gap-2">
            <a href={exportUrl("json")} download>
              <Button variant="secondary" size="sm">
                <Download className="w-3 h-3 mr-1" /> JSON
              </Button>
            </a>
            <a href={exportUrl("csv")} download>
              <Button variant="secondary" size="sm">
                <Download className="w-3 h-3 mr-1" /> CSV
              </Button>
            </a>
            <a href={exportUrl("markdown")} download>
              <Button variant="secondary" size="sm">
                <Download className="w-3 h-3 mr-1" /> Report
              </Button>
            </a>
            <Button
              variant="secondary"
              size="sm"
              className="text-red hover:text-red"
              onClick={clearResults}
            >
              <Trash2 className="w-3 h-3 mr-1" /> Clear
            </Button>
          </div>
        )}
      </div>

      {/* Filters */}
      <div className="flex gap-3 items-end">
        <div>
          <Select value={selectedProject} onValueChange={(v) => setSelectedProject(v ?? "")}>
            <SelectTrigger className="w-48 bg-surface">
              <SelectValue placeholder="Select project" />
            </SelectTrigger>
            <SelectContent>
              {projects.map((p) => (
                <SelectItem key={p.id} value={String(p.id)}>
                  {p.name}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
        <div>
          <Select value={resultType} onValueChange={(v) => setResultType(v ?? "")}>
            <SelectTrigger className="w-40 bg-surface">
              <SelectValue placeholder="All Types" />
            </SelectTrigger>
            <SelectContent>
              {RESULT_TYPES.map((t) => (
                <SelectItem key={t.value} value={t.value}>
                  {t.label}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
        <div className="flex gap-1 flex-1">
          <Input
            placeholder="Search results..."
            value={searchInput}
            onChange={(e) => setSearchInput(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && handleSearch()}
            className="bg-surface"
          />
          <Button variant="secondary" onClick={handleSearch}>
            <Search className="w-4 h-4" />
          </Button>
        </div>
      </div>

      {/* Stats */}
      {projectId > 0 && stats && (
        <div className="grid grid-cols-3 md:grid-cols-9 gap-2">
          {[
            { label: "Subdomains", count: stats.subdomains, color: "text-cyan" },
            { label: "Live Hosts", count: stats.live_hosts, color: "text-green" },
            { label: "URLs", count: stats.urls, color: "text-primary" },
            { label: "Ports", count: stats.ports, color: "text-yellow" },
            { label: "Dirs", count: stats.directories, color: "text-text" },
            { label: "Vulns", count: stats.vulnerabilities, color: "text-red" },
            { label: "Exploits", count: stats.exploits, color: "text-orange-400" },
            { label: "DNS", count: stats.dns_records, color: "text-text-muted" },
            { label: "Screenshots", count: stats.screenshots, color: "text-purple-400" },
          ].map((s) => (
            <Card key={s.label} className="bg-surface">
              <CardContent className="p-3 text-center">
                <div className={`text-xl font-bold ${s.color}`}>{s.count}</div>
                <div className="text-xs text-text-muted">{s.label}</div>
              </CardContent>
            </Card>
          ))}
        </div>
      )}

      {/* Results table */}
      {projectId > 0 && (
        <Card className="bg-surface">
          <CardHeader>
            <CardTitle className="text-sm">
              {loading ? "Loading..." : `${results.length} results`}
            </CardTitle>
          </CardHeader>
          <CardContent>
            {results.length === 0 ? (
              <p className="text-text-muted text-sm py-4 text-center">
                No results yet. Run scans to collect data.
              </p>
            ) : (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Value</TableHead>
                    <TableHead>Type</TableHead>
                    <TableHead>Details</TableHead>
                    <TableHead>Seen</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {results.map((r, i) => (
                    <TableRow key={`${r.value}-${i}`}>
                      <TableCell className="font-mono text-sm max-w-md">
                        <div className="flex items-center gap-1">
                          {/^https?:\/\//i.test(r.value) ? (
                            <a
                              href={r.value}
                              target="_blank"
                              rel="noopener noreferrer"
                              className="truncate text-cyan hover:underline"
                              title={r.value}
                            >
                              {r.value}
                            </a>
                          ) : (
                            <span className="truncate">{r.value}</span>
                          )}
                          {/^https?:\/\//i.test(r.value) ? (
                            <a href={r.value} target="_blank" rel="noopener noreferrer" className="shrink-0 opacity-30 hover:opacity-100 transition-opacity">
                              <ExternalLink className="w-3 h-3" />
                            </a>
                          ) : /^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/i.test(r.value) ? (
                            <a href={`https://${r.value}`} target="_blank" rel="noopener noreferrer" className="shrink-0 opacity-30 hover:opacity-100 transition-opacity" title={`Open https://${r.value}`}>
                              <ExternalLink className="w-3 h-3" />
                            </a>
                          ) : null}
                        </div>
                      </TableCell>
                      <TableCell>
                        <Badge variant="secondary" className="text-xs">
                          {r.result_type}
                        </Badge>
                      </TableCell>
                      <TableCell>
                        <MetadataDetails
                          resultType={r.result_type}
                          metadataJson={r.metadata_json}
                          value={r.value}
                          projectId={projectId}
                        />
                      </TableCell>
                      <TableCell className="text-text-muted">{r.count}x</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            )}
          </CardContent>
        </Card>
      )}

      {/* Screenshot lightbox */}
      {lightbox && (
        <Dialog open={!!lightbox} onOpenChange={(o) => !o && setLightbox(null)}>
          <DialogContent className="sm:max-w-5xl p-2 bg-background">
            <img
              src={`/api/screenshots/${lightbox.projectId}/${lightbox.filename}`}
              alt={lightbox.filename}
              className="w-full h-auto rounded"
            />
            <div className="text-center text-xs text-text-muted mt-1 font-mono">
              {lightbox.filename}
            </div>
          </DialogContent>
        </Dialog>
      )}
    </div>
  );
}
