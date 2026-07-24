import { useState, useMemo } from "react";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
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
import { Tabs, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  Loader2,
  Camera,
  Zap,
  Search,
  X,
  AlertTriangle,
  Shield,
  ExternalLink,
} from "lucide-react";
import { useConsolidation } from "@/hooks/useConsolidation";
import type { ConsolidatedEndpoint } from "@/types/scan";

// ── Badges ───────────────────────────────────────────────────────────

function StatusBadge({ code }: { code: number | null }) {
  if (!code) return <span className="text-text-muted text-[10px]">—</span>;
  const cls =
    code < 300
      ? "bg-green/20 text-green"
      : code < 400
        ? "bg-cyan/20 text-cyan"
        : code < 500
          ? "bg-yellow/20 text-yellow"
          : "bg-red/20 text-red";
  return (
    <span
      className={`inline-block px-1.5 py-0.5 rounded text-[10px] font-bold tabular-nums ${cls}`}
    >
      {code}
    </span>
  );
}

function ROIBadge({ score, priority }: { score: number; priority: string }) {
  const cls =
    priority === "critical"
      ? "bg-red/20 text-red"
      : priority === "high"
        ? "bg-orange-500/20 text-orange-400"
        : priority === "medium"
          ? "bg-yellow/20 text-yellow"
          : "bg-blue-500/20 text-blue-400";
  const letter = priority[0].toUpperCase();
  return (
    <span
      className={`inline-block px-1.5 py-0.5 rounded text-[10px] font-bold tabular-nums ${cls}`}
    >
      {score} {letter}
    </span>
  );
}

// ── Summary Banner ───────────────────────────────────────────────────

function SummaryBanner({
  byPriority,
}: {
  byPriority: Record<string, number>;
}) {
  const cards = [
    {
      label: "Critical",
      count: byPriority.critical || 0,
      color: "text-red",
      bg: "bg-red/10 border-red/30",
    },
    {
      label: "High",
      count: byPriority.high || 0,
      color: "text-orange-400",
      bg: "bg-orange-500/10 border-orange-500/30",
    },
    {
      label: "Medium",
      count: byPriority.medium || 0,
      color: "text-yellow",
      bg: "bg-yellow/10 border-yellow/30",
    },
    {
      label: "Low",
      count: byPriority.low || 0,
      color: "text-blue-400",
      bg: "bg-blue-500/10 border-blue-500/30",
    },
  ];

  return (
    <div className="grid grid-cols-4 gap-2">
      {cards.map((c) => (
        <Card key={c.label} className={`border ${c.bg}`}>
          <CardContent className="p-3 text-center">
            <div className={`text-2xl font-bold tabular-nums ${c.color}`}>
              {c.count}
            </div>
            <div className="text-[10px] text-text-muted uppercase tracking-wider">
              {c.label}
            </div>
          </CardContent>
        </Card>
      ))}
    </div>
  );
}

// ── Filter Bar ───────────────────────────────────────────────────────

const TYPE_TABS = [
  { value: "", label: "All" },
  { value: "subdomain", label: "Subdomains" },
  { value: "live_host", label: "Live Hosts" },
  { value: "url", label: "URLs" },
  { value: "port", label: "Ports" },
  { value: "directory", label: "Dirs" },
  { value: "vulnerability", label: "Vulns" },
  { value: "dns_record", label: "DNS" },
];

const STATUS_CHIPS = [
  { value: "", label: "All" },
  { value: "2xx", label: "2xx" },
  { value: "3xx", label: "3xx" },
  { value: "4xx", label: "4xx" },
  { value: "5xx", label: "5xx" },
];

// ── Endpoint Table ───────────────────────────────────────────────────

function EndpointTable({
  endpoints,
  projectId,
  onScreenshot,
}: {
  endpoints: ConsolidatedEndpoint[];
  projectId: number;
  onScreenshot: (filename: string) => void;
}) {
  if (endpoints.length === 0) {
    return (
      <div className="text-center py-12 text-text-muted text-sm">
        No endpoints match the current filters.
      </div>
    );
  }

  return (
    <div className="overflow-x-auto">
      <table className="w-full text-xs">
        <thead>
          <tr className="text-text-muted border-b border-border">
            <th className="text-left py-2 pr-2 w-12">Status</th>
            <th className="text-left py-2 pr-2 w-14">ROI</th>
            <th className="text-left py-2 pr-2">Endpoint</th>
            <th className="text-left py-2 pr-2 w-36">Title</th>
            <th className="text-left py-2 pr-2 w-28">Tech</th>
            <th className="text-left py-2 pr-2 w-10">Img</th>
            <th className="text-left py-2 pr-2 w-24">Tools</th>
            <th className="text-left py-2 w-10">Vulns</th>
          </tr>
        </thead>
        <tbody>
          {endpoints.map((ep, i) => (
            <tr
              key={`${ep.value}-${ep.result_type}-${i}`}
              className="border-b border-border/30 hover:bg-surface/50"
            >
              <td className="py-1.5 pr-2">
                <StatusBadge code={ep.status_code} />
              </td>
              <td className="py-1.5 pr-2">
                <ROIBadge score={ep.roi_score} priority={ep.roi_priority} />
              </td>
              <td className="py-1.5 pr-2">
                <div className="font-mono text-cyan max-w-[350px] flex items-center gap-1">
                  {/^https?:\/\//i.test(ep.value) ? (
                    <a
                      href={ep.value}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="truncate hover:underline"
                      title={ep.value}
                    >
                      {ep.value}
                    </a>
                  ) : (
                    <span className="truncate">{ep.value}</span>
                  )}
                  {/^https?:\/\//i.test(ep.value) ? (
                    <a href={ep.value} target="_blank" rel="noopener noreferrer" className="shrink-0 opacity-30 hover:opacity-100 transition-opacity">
                      <ExternalLink className="w-2.5 h-2.5" />
                    </a>
                  ) : /^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/i.test(ep.value) ? (
                    <a href={`https://${ep.value}`} target="_blank" rel="noopener noreferrer" className="shrink-0 opacity-30 hover:opacity-100 transition-opacity" title={`Open https://${ep.value}`}>
                      <ExternalLink className="w-2.5 h-2.5" />
                    </a>
                  ) : null}
                </div>
                {ep.server && (
                  <div className="text-text-muted text-[10px] truncate">
                    {ep.server}
                  </div>
                )}
              </td>
              <td className="py-1.5 pr-2 text-text truncate max-w-[140px]">
                {ep.title || "—"}
              </td>
              <td className="py-1.5 pr-2">
                <div className="flex flex-wrap gap-0.5">
                  {ep.tech.slice(0, 3).map((t) => (
                    <Badge
                      key={t}
                      variant="secondary"
                      className="text-[8px] px-1 py-0"
                    >
                      {t}
                    </Badge>
                  ))}
                  {ep.tech.length > 3 && (
                    <span className="text-text-muted text-[9px]">
                      +{ep.tech.length - 3}
                    </span>
                  )}
                </div>
              </td>
              <td className="py-1.5 pr-2">
                {ep.screenshot_filename ? (
                  <button
                    onDoubleClick={() => onScreenshot(ep.screenshot_filename!)}
                    className="block cursor-pointer"
                    title="Double-click to enlarge"
                  >
                    <img
                      src={`/api/screenshots/${projectId}/${ep.screenshot_filename}`}
                      alt="thumb"
                      className="h-6 w-auto rounded border border-border hover:border-cyan hover:shadow-lg hover:scale-110 transition-all"
                      loading="lazy"
                    />
                  </button>
                ) : (
                  <span className="text-text-muted text-[10px]">—</span>
                )}
              </td>
              <td className="py-1.5 pr-2">
                <span className="text-text-muted text-[10px]">
                  {ep.source_tools.join(", ")}
                </span>
              </td>
              <td className="py-1.5">
                {ep.vulnerability_count > 0 ? (
                  <Badge className="bg-red/20 text-red text-[10px] gap-0.5">
                    <AlertTriangle className="w-2.5 h-2.5" />
                    {ep.vulnerability_count}
                  </Badge>
                ) : (
                  <span className="text-text-muted text-[10px]">—</span>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

// ── Screenshot Lightbox ──────────────────────────────────────────────

function ScreenshotLightbox({
  open,
  filename,
  projectId,
  onClose,
}: {
  open: boolean;
  filename: string;
  projectId: number;
  onClose: () => void;
}) {
  return (
    <Dialog open={open} onOpenChange={(o) => !o && onClose()}>
      <DialogContent className="sm:max-w-5xl p-2 bg-background">
        <img
          src={`/api/screenshots/${projectId}/${filename}`}
          alt={filename}
          className="w-full h-auto rounded"
        />
        <div className="text-center text-xs text-text-muted mt-1 font-mono">
          {filename}
        </div>
      </DialogContent>
    </Dialog>
  );
}

// ── Main Component ───────────────────────────────────────────────────

export function ConsolidationView({ projectId }: { projectId: number }) {
  // Filter state
  const [resultType, setResultType] = useState("");
  const [statusClass, setStatusClass] = useState("");
  const [searchInput, setSearchInput] = useState("");
  const [search, setSearch] = useState("");
  const [sortBy, setSortBy] = useState("roi_score");
  const [sortDir] = useState("desc");

  // Lightbox state
  const [lightbox, setLightbox] = useState<string | null>(null);

  const filters = useMemo(
    () => ({
      result_type: resultType || undefined,
      status_class: statusClass || undefined,
      search: search || undefined,
      sort_by: sortBy,
      sort_dir: sortDir,
      limit: 500,
    }),
    [resultType, statusClass, search, sortBy, sortDir]
  );

  const { data, loading, consolidating, refresh, runConsolidation } =
    useConsolidation(projectId, filters);

  const handleSearch = () => setSearch(searchInput);
  const clearSearch = () => {
    setSearchInput("");
    setSearch("");
  };

  if (loading && !data) {
    return (
      <div className="flex items-center justify-center py-12 text-text-muted gap-2">
        <Loader2 className="w-4 h-4 animate-spin" />
        Loading consolidation...
      </div>
    );
  }

  const stats = data?.stats;
  const endpoints = data?.endpoints || [];

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between">
        <h2 className="text-xs font-bold text-text-muted uppercase tracking-wider flex items-center gap-2">
          <Shield className="w-3.5 h-3.5" />
          Consolidation
          {stats && (
            <Badge variant="secondary" className="text-[10px] ml-1">
              {stats.total_endpoints} endpoints
            </Badge>
          )}
        </h2>
        <div className="flex gap-2">
          <Button
            variant="outline"
            size="sm"
            className="border-cyan text-cyan hover:bg-cyan/10 text-xs"
            onClick={() => runConsolidation(false)}
            disabled={consolidating}
          >
            {consolidating ? (
              <>
                <Loader2 className="w-3 h-3 mr-1 animate-spin" /> Probing...
              </>
            ) : (
              <>
                <Zap className="w-3 h-3 mr-1" /> Consolidate
              </>
            )}
          </Button>
          <Button
            variant="outline"
            size="sm"
            className="border-purple-500 text-purple-400 hover:bg-purple-500/10 text-xs"
            onClick={() => runConsolidation(true)}
            disabled={consolidating}
          >
            <Camera className="w-3 h-3 mr-1" /> Screenshots
          </Button>
        </div>
      </div>

      {/* Summary Banner */}
      {stats && <SummaryBanner byPriority={stats.by_priority} />}

      {/* Filter Bar */}
      <Card className="bg-surface border-border">
        <CardContent className="p-3 space-y-3">
          {/* Type Tabs */}
          <Tabs
            value={resultType}
            onValueChange={(v) => setResultType(v)}
          >
            <TabsList className="bg-background h-7">
              {TYPE_TABS.map((tab) => (
                <TabsTrigger
                  key={tab.value}
                  value={tab.value}
                  className="text-[10px] px-2 py-1 h-6 data-[state=active]:bg-cyan/20 data-[state=active]:text-cyan"
                >
                  {tab.label}
                  {tab.value && stats?.by_type[tab.value] !== undefined && (
                    <span className="ml-1 text-text-muted">
                      {stats.by_type[tab.value]}
                    </span>
                  )}
                </TabsTrigger>
              ))}
            </TabsList>
          </Tabs>

          {/* Status chips + Sort + Search */}
          <div className="flex items-center gap-3 flex-wrap">
            {/* Status chips */}
            <div className="flex gap-1">
              {STATUS_CHIPS.map((chip) => (
                <button
                  key={chip.value}
                  onClick={() =>
                    setStatusClass(statusClass === chip.value ? "" : chip.value)
                  }
                  className={`px-2 py-0.5 text-[10px] rounded border transition-colors ${
                    statusClass === chip.value
                      ? "border-cyan bg-cyan/10 text-cyan"
                      : "border-border text-text-muted hover:border-cyan/40"
                  }`}
                >
                  {chip.label}
                  {chip.value && stats?.by_status[chip.value] !== undefined && (
                    <span className="ml-1 opacity-60">
                      {stats.by_status[chip.value]}
                    </span>
                  )}
                </button>
              ))}
            </div>

            {/* Sort */}
            <Select value={sortBy} onValueChange={(v) => setSortBy(v ?? "roi_score")}>
              <SelectTrigger className="w-32 h-7 text-[10px] bg-background">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="roi_score">ROI Score</SelectItem>
                <SelectItem value="status_code">Status Code</SelectItem>
                <SelectItem value="value">Name</SelectItem>
                <SelectItem value="count">Count</SelectItem>
              </SelectContent>
            </Select>

            {/* Search */}
            <div className="flex gap-1 ml-auto">
              <div className="relative">
                <Input
                  value={searchInput}
                  onChange={(e) => setSearchInput(e.target.value)}
                  onKeyDown={(e) => e.key === "Enter" && handleSearch()}
                  placeholder="Search endpoints..."
                  className="bg-background h-7 text-xs w-48 pr-7"
                />
                {searchInput && (
                  <button
                    onClick={clearSearch}
                    className="absolute right-1.5 top-1/2 -translate-y-1/2 text-text-muted hover:text-text"
                  >
                    <X className="w-3 h-3" />
                  </button>
                )}
              </div>
              <Button
                variant="outline"
                size="sm"
                className="h-7 px-2"
                onClick={handleSearch}
              >
                <Search className="w-3 h-3" />
              </Button>
            </div>

            {/* Refresh */}
            <Button
              variant="ghost"
              size="sm"
              className="h-7 px-2 text-text-muted"
              onClick={refresh}
            >
              {loading ? (
                <Loader2 className="w-3 h-3 animate-spin" />
              ) : (
                "↻"
              )}
            </Button>
          </div>
        </CardContent>
      </Card>

      {/* Endpoint Table */}
      <Card className="bg-surface border-border">
        <CardContent className="p-4">
          <EndpointTable
            endpoints={endpoints}
            projectId={projectId}
            onScreenshot={(f) => setLightbox(f)}
          />
        </CardContent>
      </Card>

      {/* Screenshot Lightbox */}
      {lightbox && (
        <ScreenshotLightbox
          open={!!lightbox}
          filename={lightbox}
          projectId={projectId}
          onClose={() => setLightbox(null)}
        />
      )}
    </div>
  );
}
