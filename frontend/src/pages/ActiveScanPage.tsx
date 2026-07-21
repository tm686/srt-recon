import { useState } from "react";
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
  Play,
  Square,
  CheckCircle,
  XCircle,
  Loader2,
  History,
  Eye,
  Rocket,
  Zap,
  Flame,
  Settings2,
} from "lucide-react";
import { useScans } from "@/hooks/useScans";
import { useProjects } from "@/hooks/useProjects";
import { useTools } from "@/hooks/useSettings";
import { SCAN_TOOLS, PIPELINE_PHASES, getToolDef } from "@/types/scan";
import type { Scan, ToolDef } from "@/types/scan";
import type { ToolStatus } from "@/types/settings";
import { ResultsModal } from "@/components/scans/ResultsModal";
import { ConsolidationView } from "@/components/scans/ConsolidationView";

// ─── Progress Bar ───────────────────────────────────────────────────
function ScanProgress({ scan }: { scan: Scan }) {
  if (scan.status !== "running") return null;

  const started = scan.started_at ? new Date(scan.started_at).getTime() : Date.now();
  const elapsed = (Date.now() - started) / 1000;
  const estimate = scan.tool_name === "nmap" ? 120 : scan.tool_name === "nuclei" ? 180 : 60;
  const percent = Math.min(95, Math.round((elapsed / estimate) * 100));

  return (
    <div className="w-full mt-2">
      <div className="flex justify-between text-xs text-text-muted mb-1">
        <span>{scan.result_count} results</span>
        <span>~{percent}%</span>
      </div>
      <div className="w-full h-2 bg-background rounded-full overflow-hidden">
        <div
          className="h-full bg-cyan rounded-full transition-all duration-1000 animate-pulse"
          style={{ width: `${percent}%` }}
        />
      </div>
    </div>
  );
}

// ─── Tool Card (3-button layout) ────────────────────────────────────
function ToolCard({
  tool,
  installed,
  latestScan,
  relevant,
  onScan,
  onCancel,
  onResults,
  onHistory,
}: {
  tool: ToolDef;
  installed: boolean;
  latestScan: Scan | null;
  relevant: boolean;
  onScan: () => void;
  onCancel: () => void;
  onResults: () => void;
  onHistory: () => void;
}) {
  const isRunning = latestScan?.status === "running";
  const isCompleted = latestScan?.status === "completed";
  const isFailed = latestScan?.status === "failed";

  return (
    <Card className={`bg-surface border-border hover:border-cyan/40 transition-colors ${!relevant ? "opacity-40" : ""}`}>
      <CardContent className="p-4 flex flex-col h-full min-h-[160px]">
        {/* Header */}
        <div className="flex items-start justify-between mb-2">
          <h3 className="text-sm font-bold text-cyan">{tool.label}</h3>
          <div className="flex gap-1">
            {installed ? (
              <Badge className="bg-green/15 text-green text-[10px] gap-1">
                <CheckCircle className="w-2.5 h-2.5" /> installed
              </Badge>
            ) : (
              <Badge className="bg-red/15 text-red text-[10px] gap-1">
                <XCircle className="w-2.5 h-2.5" /> missing
              </Badge>
            )}
          </div>
        </div>

        {/* Description */}
        <p className="text-xs text-text-muted mb-3 leading-relaxed flex-1">
          {tool.description}
        </p>

        {/* Status */}
        {latestScan && (
          <div className="mb-3">
            <div className="flex items-center gap-2 text-xs">
              {isRunning && (
                <>
                  <Loader2 className="w-3 h-3 text-cyan animate-spin" />
                  <span className="text-cyan">Scanning...</span>
                  <span className="text-text-muted ml-auto">{latestScan.result_count} found</span>
                </>
              )}
              {isCompleted && (
                <>
                  <CheckCircle className="w-3 h-3 text-green" />
                  <span className="text-green">Complete</span>
                  <span className="text-text-muted ml-auto">{latestScan.result_count} results</span>
                </>
              )}
              {isFailed && (
                <>
                  <XCircle className="w-3 h-3 text-red" />
                  <span className="text-red">Failed</span>
                </>
              )}
            </div>
            {isRunning && <ScanProgress scan={latestScan} />}
          </div>
        )}

        {/* 3-button action bar */}
        <div className="flex gap-1.5 mt-auto">
          <Button
            variant="outline"
            size="sm"
            className="flex-1 border-border text-text-muted hover:text-text text-xs"
            onClick={onHistory}
          >
            <History className="w-3 h-3 mr-1" /> History
          </Button>
          {isRunning ? (
            <Button
              variant="outline"
              size="sm"
              className="flex-1 border-red text-red hover:bg-red/10 text-xs"
              onClick={onCancel}
            >
              <Square className="w-3 h-3 mr-1" /> Cancel
            </Button>
          ) : (
            <Button
              variant="outline"
              size="sm"
              className="flex-1 border-cyan text-cyan hover:bg-cyan/10 text-xs"
              onClick={onScan}
              disabled={!installed || !relevant}
            >
              <Play className="w-3 h-3 mr-1" /> Scan
            </Button>
          )}
          <Button
            variant="outline"
            size="sm"
            className="flex-1 border-border text-text-muted hover:text-text text-xs"
            onClick={onResults}
            disabled={!latestScan || latestScan.result_count === 0}
          >
            <Eye className="w-3 h-3 mr-1" /> Results
          </Button>
        </div>
      </CardContent>
    </Card>
  );
}

// ─── Scan History ───────────────────────────────────────────────────
function ScanHistory({
  scans,
  onDelete,
  filterTool,
}: {
  scans: Scan[];
  onDelete: (id: number) => void;
  filterTool: string | null;
}) {
  const filtered = filterTool
    ? scans.filter((s) => s.tool_name === filterTool)
    : scans;

  if (filtered.length === 0) return null;

  return (
    <Card className="bg-surface border-border">
      <CardContent className="p-4">
        <h3 className="text-sm font-bold text-text-muted mb-3 flex items-center gap-2">
          <History className="w-4 h-4" /> Recent Scans
          {filterTool && (
            <Badge variant="secondary" className="text-xs">{filterTool}</Badge>
          )}
        </h3>
        <div className="space-y-1 max-h-64 overflow-y-auto">
          {filtered.slice(0, 20).map((scan) => (
            <div key={scan.id} className="flex items-center gap-3 text-xs py-1.5 border-b border-border/50 last:border-0">
              <span className="font-mono text-cyan w-24">{scan.tool_name}</span>
              <StatusDot status={scan.status} />
              <span className="text-text-muted flex-1">{scan.scan_type}</span>
              <span className="text-text">{scan.result_count} results</span>
              <span className="text-text-muted w-20 text-right">
                {scan.started_at ? new Date(scan.started_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : "-"}
              </span>
              {scan.status !== "running" && (
                <button
                  className="text-text-muted hover:text-red transition-colors"
                  onClick={() => onDelete(scan.id)}
                >
                  &times;
                </button>
              )}
            </div>
          ))}
        </div>
      </CardContent>
    </Card>
  );
}

function StatusDot({ status }: { status: Scan["status"] }) {
  const colors: Record<string, string> = {
    pending: "bg-yellow",
    running: "bg-cyan animate-pulse",
    completed: "bg-green",
    failed: "bg-red",
    cancelled: "bg-text-muted",
  };
  return <span className={`w-2 h-2 rounded-full inline-block ${colors[status] || "bg-text-muted"}`} />;
}

// ─── Overall Progress ───────────────────────────────────────────────
function OverallProgress({ scans }: { scans: Scan[] }) {
  const total = scans.length;
  const completed = scans.filter((s) => s.status === "completed").length;
  const running = scans.filter((s) => s.status === "running").length;
  const failed = scans.filter((s) => s.status === "failed").length;

  if (total === 0) return null;

  const percent = Math.round(((completed + failed) / total) * 100);
  const totalResults = scans.reduce((sum, s) => sum + s.result_count, 0);

  return (
    <Card className="bg-surface border-border">
      <CardContent className="p-4">
        <div className="flex items-center justify-between mb-2">
          <div className="flex items-center gap-3">
            {running > 0 && <Loader2 className="w-4 h-4 text-cyan animate-spin" />}
            <span className="text-sm font-bold text-text">
              {running > 0 ? `${running} scan${running > 1 ? "s" : ""} running` : "Scans complete"}
            </span>
          </div>
          <div className="flex items-center gap-4 text-xs text-text-muted">
            <span><span className="text-green font-bold">{completed}</span> done</span>
            <span><span className="text-red font-bold">{failed}</span> failed</span>
            <span><span className="text-cyan font-bold">{totalResults}</span> total results</span>
            <span className="text-text font-bold">{percent}%</span>
          </div>
        </div>
        <div className="w-full h-2.5 bg-background rounded-full overflow-hidden">
          <div
            className="h-full bg-gradient-to-r from-green to-cyan rounded-full transition-all duration-500"
            style={{ width: `${percent}%` }}
          />
        </div>
      </CardContent>
    </Card>
  );
}

// ─── Consolidation: imported from ConsolidationView ─────────────────

// ─── Main Page ──────────────────────────────────────────────────────
export function ActiveScanPage() {
  const { projects } = useProjects();
  const { tools: toolStatus } = useTools();
  const [selectedProject, setSelectedProject] = useState<string>("");
  const [targetOverride, setTargetOverride] = useState("");
  const [autoScanning, setAutoScanning] = useState(false);
  const [quickScanning, setQuickScanning] = useState(false);
  const [deepScanning, setDeepScanning] = useState(false);
  const [portConfig, setPortConfig] = useState("");
  const [showPortConfig, setShowPortConfig] = useState(false);
  const [historyFilter, setHistoryFilter] = useState<string | null>(null);

  // Results modal state
  const [resultsModal, setResultsModal] = useState<{
    open: boolean;
    scanId: number;
    toolName: string;
    isRunning: boolean;
  }>({ open: false, scanId: 0, toolName: "", isRunning: false });

  const projectId = selectedProject ? Number(selectedProject) : 0;
  const { scans, startScan, cancelScan, deleteScan, autoScan, quickScan, deepScan } = useScans(projectId || -1);

  // Map tool status by name
  const toolMap: Record<string, ToolStatus> = {};
  for (const t of toolStatus) {
    toolMap[t.name] = t;
  }

  // Get latest scan per tool
  const latestScanByTool: Record<string, Scan> = {};
  for (const scan of scans) {
    if (!latestScanByTool[scan.tool_name]) {
      latestScanByTool[scan.tool_name] = scan;
    }
  }

  const selectedProjectData = projects.find((p) => String(p.id) === selectedProject);
  const projectCategory = selectedProjectData?.category || "";
  const isIpBased = selectedProjectData && ["single_ip", "cidr_range", "ip_list"].includes(selectedProjectData.category);

  const handleScan = async (tool: ToolDef) => {
    if (!projectId) return;
    await startScan(tool.value, tool.type, { threads: 10 }, targetOverride || undefined);
  };

  const handleCancel = async (tool: ToolDef) => {
    const scan = latestScanByTool[tool.value];
    if (scan && scan.status === "running") {
      await cancelScan(scan.id);
    }
  };

  const handleOpenResults = (tool: ToolDef) => {
    const scan = latestScanByTool[tool.value];
    if (!scan) return;
    setResultsModal({
      open: true,
      scanId: scan.id,
      toolName: tool.value,
      isRunning: scan.status === "running",
    });
  };

  const portsArg = portConfig.trim() || undefined;

  const handleAutoScan = async () => {
    if (!projectId) return;
    setAutoScanning(true);
    try {
      await autoScan(portsArg);
    } finally {
      setAutoScanning(false);
    }
  };

  const handleQuickScan = async () => {
    if (!projectId) return;
    setQuickScanning(true);
    try {
      await quickScan(portsArg);
    } finally {
      setQuickScanning(false);
    }
  };

  const handleDeepScan = async () => {
    if (!projectId) return;
    setDeepScanning(true);
    try {
      await deepScan(portsArg);
    } finally {
      setDeepScanning(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header + Project selector */}
      <div className="flex items-center justify-between flex-wrap gap-3">
        <h1 className="text-lg font-bold text-text">Active Scan</h1>
        <div className="flex items-center gap-3">
          <Input
            value={targetOverride}
            onChange={(e) => setTargetOverride(e.target.value)}
            placeholder="Target override (optional)"
            className="bg-surface w-56 text-sm"
          />
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
      </div>

      {/* No project selected */}
      {!projectId && (
        <div className="text-center py-16 text-text-muted">
          Select a project to begin scanning.
        </div>
      )}

      {/* Scan Controls */}
      {projectId > 0 && (
        <Card className="bg-surface border-border">
          <CardContent className="p-4 space-y-3">
            <div className="flex items-center justify-between">
              <div>
                <div className="text-sm font-bold text-text flex items-center gap-2">
                  <Rocket className="w-4 h-4 text-cyan" />
                  Scan
                  {selectedProjectData && (
                    <Badge variant="secondary" className="text-xs ml-2">
                      {selectedProjectData.category?.replace(/_/g, " ")}
                    </Badge>
                  )}
                </div>
                <p className="text-xs text-text-muted mt-1">
                  <span className="text-cyan">Quick</span> = fast, small wordlists.{" "}
                  <span className="text-green">Auto</span> = full pipeline.{" "}
                  <span className="text-orange-400">Deep</span> = all ports, long wordlists, thorough.
                </p>
              </div>
              <div className="flex gap-2">
                <Button
                  onClick={handleQuickScan}
                  disabled={quickScanning || scans.some((s) => s.status === "running")}
                  className="bg-cyan text-background hover:bg-cyan/90"
                >
                  {quickScanning ? (
                    <><Loader2 className="w-4 h-4 mr-1 animate-spin" /> Starting...</>
                  ) : (
                    <><Zap className="w-4 h-4 mr-1" /> Quick Scan</>
                  )}
                </Button>
                <Button
                  onClick={handleAutoScan}
                  disabled={autoScanning || scans.some((s) => s.status === "running")}
                  className="bg-green text-background hover:bg-green/90"
                >
                  {autoScanning ? (
                    <><Loader2 className="w-4 h-4 mr-1 animate-spin" /> Starting...</>
                  ) : (
                    <><Rocket className="w-4 h-4 mr-1" /> Auto Scan</>
                  )}
                </Button>
                <Button
                  onClick={handleDeepScan}
                  disabled={deepScanning || scans.some((s) => s.status === "running")}
                  className="bg-orange-500 text-background hover:bg-orange-500/90"
                >
                  {deepScanning ? (
                    <><Loader2 className="w-4 h-4 mr-1 animate-spin" /> Starting...</>
                  ) : (
                    <><Flame className="w-4 h-4 mr-1" /> Deep Scan</>
                  )}
                </Button>
              </div>
            </div>

            {/* Port Configuration */}
            {isIpBased && (
              <div className="border-t border-border pt-3">
                <button
                  className="flex items-center gap-2 text-xs text-text-muted hover:text-text transition-colors"
                  onClick={() => setShowPortConfig(!showPortConfig)}
                >
                  <Settings2 className="w-3 h-3" />
                  Port Configuration
                  <span className="text-[10px]">{showPortConfig ? "\u25B2" : "\u25BC"}</span>
                  {portConfig && (
                    <Badge variant="secondary" className="text-[10px] ml-1">
                      {portConfig.length > 30 ? portConfig.slice(0, 30) + "..." : portConfig}
                    </Badge>
                  )}
                </button>
                {showPortConfig && (
                  <div className="mt-2 space-y-2">
                    <div className="flex flex-wrap gap-1.5">
                      {[
                        { label: "Top 100", value: "--top-ports 100" },
                        { label: "Common (1-1000)", value: "1-1000" },
                        { label: "HTTP Ports", value: "80,443,8080,8443,8000,8888,3000,5000,9090" },
                        { label: "All Ports", value: "1-65535" },
                      ].map((preset) => (
                        <button
                          key={preset.label}
                          onClick={() => setPortConfig(preset.value)}
                          className={`px-2 py-1 text-xs rounded border transition-colors ${
                            portConfig === preset.value
                              ? "border-cyan bg-cyan/10 text-cyan"
                              : "border-border text-text-muted hover:border-cyan/40"
                          }`}
                        >
                          {preset.label}
                        </button>
                      ))}
                      {portConfig && (
                        <button
                          onClick={() => setPortConfig("")}
                          className="px-2 py-1 text-xs rounded border border-border text-text-muted hover:border-red hover:text-red transition-colors"
                        >
                          Clear
                        </button>
                      )}
                    </div>
                    <Input
                      value={portConfig}
                      onChange={(e) => setPortConfig(e.target.value)}
                      placeholder="Custom ports: 22,80,443,8080 or 1-1000 or --top-ports 500"
                      className="bg-background text-sm font-mono"
                    />
                    <p className="text-[10px] text-text-muted">
                      Leave empty for scan defaults (Quick=top 100, Auto=1-1000, Deep=all ports)
                    </p>
                  </div>
                )}
              </div>
            )}
          </CardContent>
        </Card>
      )}

      {/* Overall progress */}
      {projectId > 0 && scans.length > 0 && <OverallProgress scans={scans} />}

      {/* Pipeline Phases — all tools always visible */}
      {projectId > 0 && PIPELINE_PHASES.map((phase) => {
        const isRelevant = phase.applicableCategories.includes(projectCategory);
        const phaseTools = phase.tools
          .map((name) => getToolDef(name))
          .filter((t): t is ToolDef => t !== undefined);

        return (
          <div key={phase.phase} className={!isRelevant ? "opacity-40" : ""}>
            <div className="flex items-center gap-3 mb-3">
              <span className="text-xs font-bold text-cyan bg-cyan/10 w-6 h-6 rounded-full flex items-center justify-center">
                {phase.phase}
              </span>
              <div>
                <h2 className="text-xs font-bold text-text-muted uppercase tracking-wider">
                  {phase.name}
                </h2>
                <p className="text-[10px] text-text-muted">{phase.description}</p>
              </div>
              {!isRelevant && (
                <Badge variant="secondary" className="text-[10px] ml-auto">
                  not applicable
                </Badge>
              )}
            </div>
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
              {phaseTools.map((tool) => (
                <ToolCard
                  key={tool.value}
                  tool={tool}
                  installed={toolMap[tool.value]?.installed ?? false}
                  latestScan={latestScanByTool[tool.value] || null}
                  relevant={isRelevant}
                  onScan={() => handleScan(tool)}
                  onCancel={() => handleCancel(tool)}
                  onResults={() => handleOpenResults(tool)}
                  onHistory={() => setHistoryFilter(historyFilter === tool.value ? null : tool.value)}
                />
              ))}
            </div>
          </div>
        );
      })}

      {/* Consolidation section */}
      {projectId > 0 && <ConsolidationView projectId={projectId} />}

      {/* Scan history */}
      {projectId > 0 && (
        <ScanHistory
          scans={scans}
          onDelete={deleteScan}
          filterTool={historyFilter}
        />
      )}

      {/* Results Modal */}
      <ResultsModal
        open={resultsModal.open}
        onClose={() => setResultsModal((s) => ({ ...s, open: false }))}
        projectId={projectId}
        scanId={resultsModal.scanId}
        toolName={resultsModal.toolName}
        isRunning={resultsModal.isRunning}
      />
    </div>
  );
}
