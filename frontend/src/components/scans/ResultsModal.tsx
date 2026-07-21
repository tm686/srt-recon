import { useState, useEffect, useCallback } from "react";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Badge } from "@/components/ui/badge";
import api from "@/lib/api";
import type { ScanResult } from "@/types/scan";

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

// ── Per-tool result renderers ───────────────────────────────────────

function NucleiTable({ results }: { results: ScanResult[] }) {
  return (
    <table className="w-full text-xs">
      <thead>
        <tr className="text-text-muted border-b border-border">
          <th className="text-left py-1.5 pr-2">Severity</th>
          <th className="text-left py-1.5 pr-2">Template</th>
          <th className="text-left py-1.5 pr-2">Name</th>
          <th className="text-left py-1.5">Matched URL</th>
        </tr>
      </thead>
      <tbody>
        {results.map((r) => {
          const m = safeParse(r.metadata_json);
          return (
            <tr key={r.id} className="border-b border-border/30">
              <td className="py-1.5 pr-2"><SeverityBadge severity={m.severity} /></td>
              <td className="py-1.5 pr-2 font-mono text-cyan">{m.template_id}</td>
              <td className="py-1.5 pr-2 text-text">{m.name}</td>
              <td className="py-1.5 text-text-muted truncate max-w-[200px]">{m.matched_at || r.value}</td>
            </tr>
          );
        })}
      </tbody>
    </table>
  );
}

function HttpxTable({ results }: { results: ScanResult[] }) {
  return (
    <table className="w-full text-xs">
      <thead>
        <tr className="text-text-muted border-b border-border">
          <th className="text-left py-1.5 pr-2">URL</th>
          <th className="text-left py-1.5 pr-2">Status</th>
          <th className="text-left py-1.5 pr-2">Title</th>
          <th className="text-left py-1.5 pr-2">Server</th>
          <th className="text-left py-1.5">Technologies</th>
        </tr>
      </thead>
      <tbody>
        {results.map((r) => {
          const m = safeParse(r.metadata_json);
          const techs: string[] = Array.isArray(m.tech) ? m.tech : [];
          return (
            <tr key={r.id} className="border-b border-border/30">
              <td className="py-1.5 pr-2 font-mono text-cyan truncate max-w-[200px]">{r.value}</td>
              <td className="py-1.5 pr-2"><StatusBadge code={m.status_code} /></td>
              <td className="py-1.5 pr-2 text-text">{m.title}</td>
              <td className="py-1.5 pr-2 text-text-muted">{m.server || "-"}</td>
              <td className="py-1.5">
                <div className="flex flex-wrap gap-1">
                  {techs.slice(0, 5).map((t) => (
                    <Badge key={t} variant="secondary" className="text-[9px]">{t}</Badge>
                  ))}
                  {techs.length > 5 && <span className="text-text-muted">+{techs.length - 5}</span>}
                </div>
              </td>
            </tr>
          );
        })}
      </tbody>
    </table>
  );
}

function PortTable({ results }: { results: ScanResult[] }) {
  return (
    <table className="w-full text-xs">
      <thead>
        <tr className="text-text-muted border-b border-border">
          <th className="text-left py-1.5 pr-2">Host:Port</th>
          <th className="text-left py-1.5 pr-2">Protocol</th>
          <th className="text-left py-1.5 pr-2">Service</th>
          <th className="text-left py-1.5">State</th>
        </tr>
      </thead>
      <tbody>
        {results.map((r) => {
          const m = safeParse(r.metadata_json);
          return (
            <tr key={r.id} className="border-b border-border/30">
              <td className="py-1.5 pr-2 font-mono text-cyan">{r.value}</td>
              <td className="py-1.5 pr-2 text-text">{m.protocol || "tcp"}</td>
              <td className="py-1.5 pr-2 text-green">{m.service || "-"}</td>
              <td className="py-1.5 text-text-muted">{m.state || "open"}</td>
            </tr>
          );
        })}
      </tbody>
    </table>
  );
}

function FfufTable({ results }: { results: ScanResult[] }) {
  return (
    <table className="w-full text-xs">
      <thead>
        <tr className="text-text-muted border-b border-border">
          <th className="text-left py-1.5 pr-2">URL</th>
          <th className="text-left py-1.5 pr-2">Status</th>
          <th className="text-left py-1.5 pr-2">Length</th>
          <th className="text-left py-1.5">Words</th>
        </tr>
      </thead>
      <tbody>
        {results.map((r) => {
          const m = safeParse(r.metadata_json);
          return (
            <tr key={r.id} className="border-b border-border/30">
              <td className="py-1.5 pr-2 font-mono text-cyan truncate max-w-[250px]">{r.value}</td>
              <td className="py-1.5 pr-2"><StatusBadge code={m.status} /></td>
              <td className="py-1.5 pr-2 text-text">{m.length ?? "-"}</td>
              <td className="py-1.5 text-text-muted">{m.words ?? "-"}</td>
            </tr>
          );
        })}
      </tbody>
    </table>
  );
}

function DalfoxTable({ results }: { results: ScanResult[] }) {
  return (
    <table className="w-full text-xs">
      <thead>
        <tr className="text-text-muted border-b border-border">
          <th className="text-left py-1.5 pr-2">POC URL</th>
          <th className="text-left py-1.5 pr-2">Type</th>
          <th className="text-left py-1.5">Parameter</th>
        </tr>
      </thead>
      <tbody>
        {results.map((r) => {
          const m = safeParse(r.metadata_json);
          return (
            <tr key={r.id} className="border-b border-border/30">
              <td className="py-1.5 pr-2 font-mono text-cyan truncate max-w-[300px]">{m.poc || r.value}</td>
              <td className="py-1.5 pr-2 text-orange-400">{m.type || "XSS"}</td>
              <td className="py-1.5 text-text">{m.param || "-"}</td>
            </tr>
          );
        })}
      </tbody>
    </table>
  );
}

function SubjackTable({ results }: { results: ScanResult[] }) {
  return (
    <table className="w-full text-xs">
      <thead>
        <tr className="text-text-muted border-b border-border">
          <th className="text-left py-1.5 pr-2">Domain</th>
          <th className="text-left py-1.5 pr-2">Service</th>
          <th className="text-left py-1.5">Status</th>
        </tr>
      </thead>
      <tbody>
        {results.map((r) => {
          const m = safeParse(r.metadata_json);
          return (
            <tr key={r.id} className="border-b border-border/30">
              <td className="py-1.5 pr-2 font-mono text-cyan">{r.value}</td>
              <td className="py-1.5 pr-2 text-text">{m.service || "-"}</td>
              <td className="py-1.5">
                {m.vulnerable ? (
                  <Badge className="bg-red/20 text-red text-[10px]">VULNERABLE</Badge>
                ) : (
                  <Badge variant="secondary" className="text-[10px]">safe</Badge>
                )}
              </td>
            </tr>
          );
        })}
      </tbody>
    </table>
  );
}

function ScreenshotGallery({ results, projectId }: { results: ScanResult[]; projectId: number }) {
  const [enlarged, setEnlarged] = useState<string | null>(null);

  return (
    <>
      <div className="grid grid-cols-2 md:grid-cols-3 gap-3">
        {results.map((r) => (
          <div
            key={r.id}
            className="border border-border rounded overflow-hidden bg-background cursor-pointer hover:border-cyan transition-colors"
            onDoubleClick={() => setEnlarged(r.value)}
            title="Double-click to enlarge"
          >
            <img
              src={`/api/screenshots/${projectId}/${r.value}`}
              alt={r.value}
              className="w-full h-auto"
              loading="lazy"
            />
            <div className="px-2 py-1 text-[10px] text-text-muted truncate">{r.value}</div>
          </div>
        ))}
      </div>
      {enlarged && (
        <Dialog open={!!enlarged} onOpenChange={(o) => !o && setEnlarged(null)}>
          <DialogContent className="sm:max-w-5xl p-2 bg-background">
            <img
              src={`/api/screenshots/${projectId}/${enlarged}`}
              alt={enlarged}
              className="w-full h-auto rounded"
            />
            <div className="text-center text-xs text-text-muted mt-1 font-mono">
              {enlarged}
            </div>
          </DialogContent>
        </Dialog>
      )}
    </>
  );
}

function DnsxTable({ results }: { results: ScanResult[] }) {
  return (
    <table className="w-full text-xs">
      <thead>
        <tr className="text-text-muted border-b border-border">
          <th className="text-left py-1.5 pr-2">Host</th>
          <th className="text-left py-1.5 pr-2">A</th>
          <th className="text-left py-1.5 pr-2">CNAME</th>
          <th className="text-left py-1.5">Other</th>
        </tr>
      </thead>
      <tbody>
        {results.map((r) => {
          const m = safeParse(r.metadata_json);
          const a = Array.isArray(m.a) ? m.a.join(", ") : "";
          const cname = Array.isArray(m.cname) ? m.cname.join(", ") : "";
          const other = ["aaaa", "mx", "ns", "txt"]
            .filter((k) => m[k])
            .map((k) => `${k.toUpperCase()}: ${Array.isArray(m[k]) ? m[k].join(", ") : m[k]}`)
            .join(" | ");
          return (
            <tr key={r.id} className="border-b border-border/30">
              <td className="py-1.5 pr-2 font-mono text-cyan">{r.value}</td>
              <td className="py-1.5 pr-2 text-text">{a || "-"}</td>
              <td className="py-1.5 pr-2 text-text-muted">{cname || "-"}</td>
              <td className="py-1.5 text-text-muted truncate max-w-[200px]">{other || "-"}</td>
            </tr>
          );
        })}
      </tbody>
    </table>
  );
}

function DefaultList({ results }: { results: ScanResult[] }) {
  return (
    <div className="space-y-0.5 font-mono text-xs max-h-[50vh] overflow-y-auto">
      {results.map((r) => (
        <div key={r.id} className="text-text truncate py-0.5">
          <span className="text-green mr-2">&gt;</span>
          {r.value}
        </div>
      ))}
    </div>
  );
}

// ── Helpers ──────────────────────────────────────────────────────────

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function safeParse(json: string): Record<string, any> {
  try {
    return JSON.parse(json || "{}");
  } catch {
    return {};
  }
}

// ── Main Component ──────────────────────────────────────────────────

interface ResultsModalProps {
  open: boolean;
  onClose: () => void;
  projectId: number;
  scanId: number;
  toolName: string;
  isRunning?: boolean;
}

export function ResultsModal({ open, onClose, projectId, scanId, toolName, isRunning }: ResultsModalProps) {
  const [results, setResults] = useState<ScanResult[]>([]);
  const [loading, setLoading] = useState(true);

  const fetchResults = useCallback(async () => {
    try {
      const { data } = await api.get<ScanResult[]>(
        `/projects/${projectId}/scans/${scanId}/results?limit=500`
      );
      setResults(data);
    } catch {
      /* scan may have been deleted */
    } finally {
      setLoading(false);
    }
  }, [projectId, scanId]);

  useEffect(() => {
    if (!open) return;
    fetchResults();
    if (isRunning) {
      const interval = setInterval(fetchResults, 2000);
      return () => clearInterval(interval);
    }
  }, [open, fetchResults, isRunning]);

  const renderResults = () => {
    if (loading) return <div className="text-text-muted text-sm py-8 text-center">Loading results...</div>;
    if (results.length === 0) return <div className="text-text-muted text-sm py-8 text-center">No results yet.</div>;

    switch (toolName) {
      case "nuclei": return <NucleiTable results={results} />;
      case "httpx": return <HttpxTable results={results} />;
      case "nmap":
      case "rustscan": return <PortTable results={results} />;
      case "ffuf": return <FfufTable results={results} />;
      case "dalfox": return <DalfoxTable results={results} />;
      case "subjack": return <SubjackTable results={results} />;
      case "dnsx": return <DnsxTable results={results} />;
      case "gowitness": return <ScreenshotGallery results={results} projectId={projectId} />;
      default: return <DefaultList results={results} />;
    }
  };

  return (
    <Dialog open={open} onOpenChange={(o) => { if (!o) onClose(); }}>
      <DialogContent className="sm:max-w-4xl max-h-[80vh] overflow-hidden flex flex-col">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <span className="text-cyan">{toolName}</span>
            <span className="text-text-muted font-normal">results</span>
            <Badge variant="secondary" className="text-xs ml-2">{results.length}</Badge>
            {isRunning && (
              <Badge className="bg-cyan/20 text-cyan text-[10px] animate-pulse ml-1">LIVE</Badge>
            )}
          </DialogTitle>
        </DialogHeader>
        <div className="flex-1 overflow-y-auto min-h-0">
          {renderResults()}
        </div>
      </DialogContent>
    </Dialog>
  );
}
