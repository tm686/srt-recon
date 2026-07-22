import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Checkbox } from "@/components/ui/checkbox";
import { Slider } from "@/components/ui/slider";
import { Settings2, Play, Loader2 } from "lucide-react";
import { PIPELINE_PHASES, SCAN_TOOLS } from "@/types/scan";
import type { CustomToolConfig } from "@/types/scan";
import type { ToolStatus } from "@/types/settings";

// ── Per-tool configurable parameters with defaults ──────────────────

interface ParamDef {
  key: string;
  label: string;
  type: "slider" | "text" | "severity";
  default: unknown;
  min?: number;
  max?: number;
  step?: number;
  suffix?: string;
}

const TOOL_PARAMS: Record<string, ParamDef[]> = {
  subfinder: [
    { key: "threads", label: "Threads", type: "slider", default: 10, min: 1, max: 100, step: 1 },
  ],
  alterx: [
    { key: "limit", label: "Limit", type: "text", default: "10000" },
  ],
  dnsx: [
    { key: "threads", label: "Threads", type: "slider", default: 10, min: 1, max: 100, step: 1 },
  ],
  nmap: [
    { key: "ports", label: "Ports", type: "text", default: "1-1000" },
  ],
  rustscan: [
    { key: "batch_size", label: "Batch Size", type: "slider", default: 1500, min: 100, max: 10000, step: 100 },
    { key: "timeout", label: "Timeout", type: "text", default: "2000", suffix: "ms" },
  ],
  httpx: [
    { key: "threads", label: "Threads", type: "slider", default: 10, min: 1, max: 100, step: 1 },
  ],
  gau: [
    { key: "threads", label: "Threads", type: "slider", default: 5, min: 1, max: 100, step: 1 },
  ],
  katana: [
    { key: "threads", label: "Threads", type: "slider", default: 10, min: 1, max: 100, step: 1 },
    { key: "depth", label: "Depth", type: "slider", default: 3, min: 1, max: 10, step: 1 },
  ],
  ffuf: [
    { key: "threads", label: "Threads", type: "slider", default: 40, min: 1, max: 100, step: 1 },
    { key: "wordlist", label: "Wordlist", type: "text", default: "common.txt" },
  ],
  nuclei: [
    { key: "threads", label: "Threads", type: "slider", default: 25, min: 1, max: 100, step: 1 },
    { key: "severity", label: "Severity", type: "severity", default: "low,medium,high,critical" },
  ],
  dalfox: [
    { key: "threads", label: "Threads", type: "slider", default: 10, min: 1, max: 100, step: 1 },
  ],
  subjack: [
    { key: "threads", label: "Threads", type: "slider", default: 10, min: 1, max: 100, step: 1 },
  ],
  gowitness: [
    { key: "threads", label: "Threads", type: "slider", default: 8, min: 1, max: 100, step: 1 },
  ],
};

const SEVERITY_OPTIONS = ["info", "low", "medium", "high", "critical"] as const;

interface ToolState {
  enabled: boolean;
  options: Record<string, unknown>;
}

function buildDefaults(): Record<string, ToolState> {
  const state: Record<string, ToolState> = {};
  for (const tool of SCAN_TOOLS) {
    if (tool.type === "notification") continue;
    const params = TOOL_PARAMS[tool.value] || [];
    const opts: Record<string, unknown> = {};
    for (const p of params) {
      opts[p.key] = p.default;
    }
    state[tool.value] = { enabled: false, options: opts };
  }
  return state;
}

// ── Severity Chips ──────────────────────────────────────────────────

function SeverityChips({
  value,
  onChange,
  disabled,
}: {
  value: string;
  onChange: (v: string) => void;
  disabled: boolean;
}) {
  const selected = new Set(value.split(",").filter(Boolean));

  const toggle = (sev: string) => {
    const next = new Set(selected);
    if (next.has(sev)) {
      next.delete(sev);
    } else {
      next.add(sev);
    }
    onChange(Array.from(next).join(","));
  };

  const colorMap: Record<string, string> = {
    info: "border-text-muted text-text-muted",
    low: "border-green text-green",
    medium: "border-yellow text-yellow",
    high: "border-orange-400 text-orange-400",
    critical: "border-red text-red",
  };

  return (
    <div className="flex flex-wrap gap-1">
      {SEVERITY_OPTIONS.map((sev) => (
        <button
          key={sev}
          disabled={disabled}
          onClick={() => toggle(sev)}
          className={`px-1.5 py-0.5 text-[10px] rounded border transition-colors ${
            selected.has(sev)
              ? `${colorMap[sev]} bg-current/10`
              : "border-border text-text-muted/50"
          } ${disabled ? "opacity-40 cursor-not-allowed" : "hover:opacity-80"}`}
        >
          {sev}
        </button>
      ))}
    </div>
  );
}

// ── Tool Row ────────────────────────────────────────────────────────

function ToolRow({
  toolName,
  toolLabel,
  installed,
  applicable,
  state,
  onToggle,
  onOptionChange,
}: {
  toolName: string;
  toolLabel: string;
  installed: boolean;
  applicable: boolean;
  state: ToolState;
  onToggle: () => void;
  onOptionChange: (key: string, value: unknown) => void;
}) {
  const params = TOOL_PARAMS[toolName] || [];
  const controlsDisabled = !state.enabled;
  const canEnable = installed;

  return (
    <div
      className={`flex items-center gap-3 py-1.5 px-2 rounded transition-colors ${
        !applicable ? "opacity-40" : ""
      } ${state.enabled ? "bg-cyan/5" : ""}`}
    >
      <Checkbox
        checked={state.enabled}
        onCheckedChange={onToggle}
        disabled={!canEnable}
        className="shrink-0"
      />
      <span
        className={`text-xs font-mono w-24 shrink-0 ${
          state.enabled ? "text-cyan font-bold" : "text-text-muted"
        }`}
      >
        {toolLabel}
      </span>
      {!installed && (
        <Badge className="bg-red/15 text-red text-[9px] shrink-0">missing</Badge>
      )}

      {params.length === 0 && (
        <span className="text-[10px] text-text-muted italic">no options</span>
      )}

      <div className="flex flex-1 items-center gap-3 flex-wrap">
        {params.map((p) => {
          if (p.type === "slider") {
            const val = Number(state.options[p.key] ?? p.default);
            return (
              <div key={p.key} className="flex items-center gap-2 min-w-[160px]">
                <span className="text-[10px] text-text-muted w-14 shrink-0">{p.label}</span>
                <Slider
                  min={p.min}
                  max={p.max}
                  step={p.step}
                  value={[val]}
                  onValueChange={([v]) => onOptionChange(p.key, v)}
                  disabled={controlsDisabled}
                  className="flex-1"
                />
                <span className="text-[10px] text-text font-mono w-8 text-right">{val}</span>
              </div>
            );
          }

          if (p.type === "text") {
            return (
              <div key={p.key} className="flex items-center gap-1.5 min-w-[120px]">
                <span className="text-[10px] text-text-muted shrink-0">{p.label}</span>
                <Input
                  value={String(state.options[p.key] ?? p.default)}
                  onChange={(e) => onOptionChange(p.key, e.target.value)}
                  disabled={controlsDisabled}
                  className="h-6 text-[11px] bg-background px-1.5 w-24"
                />
                {p.suffix && (
                  <span className="text-[10px] text-text-muted">{p.suffix}</span>
                )}
              </div>
            );
          }

          if (p.type === "severity") {
            return (
              <div key={p.key} className="flex items-center gap-1.5">
                <span className="text-[10px] text-text-muted shrink-0">{p.label}</span>
                <SeverityChips
                  value={String(state.options[p.key] ?? p.default)}
                  onChange={(v) => onOptionChange(p.key, v)}
                  disabled={controlsDisabled}
                />
              </div>
            );
          }

          return null;
        })}
      </div>
    </div>
  );
}

// ── Main Panel ──────────────────────────────────────────────────────

interface CustomScanPanelProps {
  projectId: number;
  toolStatus: Record<string, ToolStatus>;
  projectCategory: string;
  scanSpeed: string;
  portConfig: string;
  targetOverride: string;
  onRun: (tools: CustomToolConfig[]) => Promise<void>;
  disabled: boolean;
}

export function CustomScanPanel({
  toolStatus,
  projectCategory,
  onRun,
  disabled,
}: CustomScanPanelProps) {
  const [open, setOpen] = useState(false);
  const [toolStates, setToolStates] = useState<Record<string, ToolState>>(buildDefaults);
  const [running, setRunning] = useState(false);

  const toggleTool = (name: string) => {
    setToolStates((prev) => ({
      ...prev,
      [name]: { ...prev[name], enabled: !prev[name].enabled },
    }));
  };

  const setOption = (name: string, key: string, value: unknown) => {
    setToolStates((prev) => ({
      ...prev,
      [name]: {
        ...prev[name],
        options: { ...prev[name].options, [key]: value },
      },
    }));
  };

  const selectAll = () => {
    setToolStates((prev) => {
      const next = { ...prev };
      for (const key of Object.keys(next)) {
        if (toolStatus[key]?.installed) {
          next[key] = { ...next[key], enabled: true };
        }
      }
      return next;
    });
  };

  const clearAll = () => {
    setToolStates((prev) => {
      const next = { ...prev };
      for (const key of Object.keys(next)) {
        next[key] = { ...next[key], enabled: false };
      }
      return next;
    });
  };

  const selectedCount = Object.values(toolStates).filter((s) => s.enabled).length;

  const handleRun = async () => {
    const tools: CustomToolConfig[] = [];
    // Walk pipeline phases in order so tools run sequentially as intended
    for (const phase of PIPELINE_PHASES) {
      for (const toolName of phase.tools) {
        const st = toolStates[toolName];
        if (!st?.enabled) continue;
        const toolDef = SCAN_TOOLS.find((t) => t.value === toolName);
        if (!toolDef) continue;
        tools.push({
          tool_name: toolName,
          scan_type: toolDef.type,
          options: { ...st.options },
        });
      }
    }
    if (tools.length === 0) return;

    setRunning(true);
    try {
      await onRun(tools);
    } finally {
      setRunning(false);
    }
  };

  return (
    <div className="border-t border-border pt-3">
      <button
        className="flex items-center gap-2 text-xs text-text-muted hover:text-text transition-colors w-full"
        onClick={() => setOpen(!open)}
      >
        <Settings2 className="w-3.5 h-3.5 text-purple-400" />
        <span className="font-bold text-purple-400">Custom Scan</span>
        <span className="text-[10px]">{open ? "\u25B2" : "\u25BC"}</span>
        {selectedCount > 0 && (
          <Badge className="bg-purple-500/15 text-purple-400 text-[10px] ml-1">
            {selectedCount} tool{selectedCount !== 1 ? "s" : ""}
          </Badge>
        )}
      </button>

      {open && (
        <div className="mt-3 space-y-4">
          {PIPELINE_PHASES.map((phase) => {
            const isApplicable = phase.applicableCategories.includes(projectCategory);
            const phaseTools = phase.tools.filter((name) =>
              SCAN_TOOLS.some((t) => t.value === name && t.type !== "notification")
            );
            if (phaseTools.length === 0) return null;

            return (
              <div key={phase.phase}>
                <div className="flex items-center gap-2 mb-1">
                  <span className="text-[10px] font-bold text-cyan bg-cyan/10 w-4 h-4 rounded-full flex items-center justify-center">
                    {phase.phase}
                  </span>
                  <span className="text-[10px] font-bold text-text-muted uppercase tracking-wider">
                    {phase.name}
                  </span>
                  {!isApplicable && (
                    <Badge variant="secondary" className="text-[9px]">
                      not applicable
                    </Badge>
                  )}
                </div>
                <div className="space-y-0.5">
                  {phaseTools.map((toolName) => {
                    const toolDef = SCAN_TOOLS.find((t) => t.value === toolName);
                    if (!toolDef) return null;
                    const st = toolStates[toolName];
                    if (!st) return null;
                    return (
                      <ToolRow
                        key={toolName}
                        toolName={toolName}
                        toolLabel={toolDef.label}
                        installed={toolStatus[toolName]?.installed ?? false}
                        applicable={isApplicable}
                        state={st}
                        onToggle={() => toggleTool(toolName)}
                        onOptionChange={(k, v) => setOption(toolName, k, v)}
                      />
                    );
                  })}
                </div>
              </div>
            );
          })}

          {/* Actions */}
          <div className="flex items-center gap-2 pt-2 border-t border-border">
            <button
              className="text-[10px] text-text-muted hover:text-text px-2 py-1 rounded border border-border hover:border-cyan/40 transition-colors"
              onClick={selectAll}
            >
              Select All
            </button>
            <button
              className="text-[10px] text-text-muted hover:text-text px-2 py-1 rounded border border-border hover:border-cyan/40 transition-colors"
              onClick={clearAll}
            >
              Clear All
            </button>
            <div className="flex-1" />
            <Button
              onClick={handleRun}
              disabled={selectedCount === 0 || running || disabled}
              className="bg-purple-600 text-white hover:bg-purple-600/90"
            >
              {running ? (
                <>
                  <Loader2 className="w-4 h-4 mr-1 animate-spin" /> Starting...
                </>
              ) : (
                <>
                  <Play className="w-4 h-4 mr-1" /> Run Custom Scan
                </>
              )}
            </Button>
          </div>
        </div>
      )}
    </div>
  );
}
