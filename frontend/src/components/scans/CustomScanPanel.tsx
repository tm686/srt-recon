import { useState, useRef, useEffect } from "react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Checkbox } from "@/components/ui/checkbox";
import { Slider } from "@/components/ui/slider";
import { Settings2, Play, Loader2, FolderOpen } from "lucide-react";
import { PIPELINE_PHASES, SCAN_TOOLS } from "@/types/scan";
import type { CustomToolConfig } from "@/types/scan";
import type { ToolStatus } from "@/types/settings";

// ── Per-tool configurable parameters with defaults ──────────────────

interface ParamDef {
  key: string;
  label: string;
  type: "slider" | "text" | "severity" | "wordlist";
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
    { key: "wordlist", label: "Wordlist", type: "wordlist", default: "/usr/share/wordlists/seclists/Discovery/Web-Content/common.txt" },
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

const WORDLIST_PRESETS = [
  { label: "common.txt", path: "/usr/share/wordlists/seclists/Discovery/Web-Content/common.txt" },
  { label: "directory-list-2.3-small", path: "/usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-small.txt" },
  { label: "directory-list-2.3-medium", path: "/usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt" },
  { label: "raft-medium-directories", path: "/usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-directories.txt" },
  { label: "raft-large-directories", path: "/usr/share/wordlists/seclists/Discovery/Web-Content/raft-large-directories.txt" },
  { label: "big.txt", path: "/usr/share/wordlists/seclists/Discovery/Web-Content/big.txt" },
];

const SEVERITY_OPTIONS = ["info", "low", "medium", "high", "critical"] as const;

export interface ToolState {
  enabled: boolean;
  options: Record<string, unknown>;
}

export function buildDefaults(): Record<string, ToolState> {
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

// ── Editable Number ─────────────────────────────────────────────────

function EditableNumber({
  value,
  onChange,
  disabled,
  min,
  max,
}: {
  value: number;
  onChange: (v: number) => void;
  disabled: boolean;
  min?: number;
  max?: number;
}) {
  const [editing, setEditing] = useState(false);
  const [text, setText] = useState(String(value));
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (!editing) setText(String(value));
  }, [value, editing]);

  useEffect(() => {
    if (editing) inputRef.current?.select();
  }, [editing]);

  const commit = () => {
    setEditing(false);
    let num = parseInt(text, 10);
    if (isNaN(num)) num = value;
    if (min !== undefined) num = Math.max(min, num);
    if (max !== undefined) num = Math.min(max, num);
    onChange(num);
  };

  if (editing && !disabled) {
    return (
      <input
        ref={inputRef}
        value={text}
        onChange={(e) => setText(e.target.value)}
        onBlur={commit}
        onKeyDown={(e) => { if (e.key === "Enter") commit(); if (e.key === "Escape") setEditing(false); }}
        className="w-10 h-5 text-[10px] text-center font-mono bg-background border border-cyan rounded px-0.5 text-text outline-none"
      />
    );
  }

  return (
    <button
      onClick={() => !disabled && setEditing(true)}
      disabled={disabled}
      className={`text-[10px] font-mono w-10 text-center rounded px-0.5 py-0.5 transition-colors ${
        disabled
          ? "text-text-muted/50 cursor-not-allowed"
          : "text-text hover:bg-cyan/10 hover:text-cyan cursor-pointer"
      }`}
      title="Click to edit"
    >
      {value}
    </button>
  );
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

// ── Wordlist Selector ───────────────────────────────────────────────

function WordlistSelector({
  value,
  onChange,
  disabled,
}: {
  value: string;
  onChange: (v: string) => void;
  disabled: boolean;
}) {
  const [showPresets, setShowPresets] = useState(false);

  return (
    <div className="flex flex-col gap-1 min-w-[200px]">
      <div className="flex items-center gap-1">
        <span className="text-[10px] text-text-muted shrink-0">Wordlist</span>
        <Input
          value={value}
          onChange={(e) => onChange(e.target.value)}
          disabled={disabled}
          className="h-6 text-[10px] bg-background px-1.5 flex-1 font-mono"
          placeholder="/usr/share/wordlists/seclists/..."
        />
        <button
          onClick={() => setShowPresets(!showPresets)}
          disabled={disabled}
          className={`p-1 rounded transition-colors ${disabled ? "opacity-40" : "hover:bg-cyan/10 text-text-muted hover:text-cyan"}`}
          title="Browse wordlist presets"
        >
          <FolderOpen className="w-3.5 h-3.5" />
        </button>
      </div>
      {showPresets && !disabled && (
        <div className="flex flex-wrap gap-1 ml-14">
          {WORDLIST_PRESETS.map((wl) => (
            <button
              key={wl.label}
              onClick={() => { onChange(wl.path); setShowPresets(false); }}
              className={`px-1.5 py-0.5 text-[9px] rounded border transition-colors ${
                value === wl.path
                  ? "border-cyan bg-cyan/10 text-cyan"
                  : "border-border text-text-muted hover:border-cyan/40 hover:text-text"
              }`}
            >
              {wl.label}
            </button>
          ))}
        </div>
      )}
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
              <div key={p.key} className="flex items-center gap-2 min-w-[180px]">
                <span className="text-[10px] text-text-muted w-14 shrink-0">{p.label}</span>
                <Slider
                  min={p.min}
                  max={p.max}
                  step={p.step}
                  value={[val]}
                  onValueChange={(v) => onOptionChange(p.key, Array.isArray(v) ? v[0] : v)}
                  disabled={controlsDisabled}
                  className="flex-1"
                />
                <EditableNumber
                  value={val}
                  onChange={(v) => onOptionChange(p.key, v)}
                  disabled={controlsDisabled}
                  min={p.min}
                  max={p.max}
                />
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

          if (p.type === "wordlist") {
            return (
              <WordlistSelector
                key={p.key}
                value={String(state.options[p.key] ?? p.default)}
                onChange={(v) => onOptionChange(p.key, v)}
                disabled={controlsDisabled}
              />
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

// ── Preset Definitions ──────────────────────────────────────────────

export type PresetMode = "quick" | "auto" | "deep" | null;

interface PresetConfig {
  label: string;
  tools: Record<string, Record<string, unknown>>;
}

const QUICK_TOOLS: Record<string, Record<string, unknown>> = {
  httpx: { threads: 5 },
  ffuf: { threads: 20, wordlist: "/usr/share/wordlists/seclists/Discovery/Web-Content/common.txt" },
  nuclei: { threads: 15, severity: "high,critical" },
  gowitness: { threads: 4 },
};

const AUTO_TOOLS: Record<string, Record<string, unknown>> = {
  subfinder: { threads: 10 },
  assetfinder: {},
  dnsx: { threads: 10 },
  httpx: { threads: 10 },
  gau: { threads: 5 },
  katana: { threads: 10, depth: 3 },
  waybackurls: {},
  ffuf: { threads: 40, wordlist: "/usr/share/wordlists/seclists/Discovery/Web-Content/common.txt" },
  nuclei: { threads: 25, severity: "low,medium,high,critical" },
  dalfox: { threads: 10 },
  subjack: { threads: 10 },
  gowitness: { threads: 8 },
};

const DEEP_TOOLS: Record<string, Record<string, unknown>> = {
  subfinder: { threads: 20 },
  assetfinder: {},
  alterx: { limit: "50000" },
  dnsx: { threads: 20 },
  nmap: { ports: "1-65535" },
  rustscan: { batch_size: 4500, timeout: "2000" },
  httpx: { threads: 20 },
  gau: { threads: 10 },
  katana: { threads: 20, depth: 5 },
  waybackurls: {},
  ffuf: { threads: 60, wordlist: "/usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt" },
  nuclei: { threads: 50, severity: "info,low,medium,high,critical" },
  dalfox: { threads: 20 },
  subjack: { threads: 20 },
  gowitness: { threads: 16 },
};

const PRESETS: Record<string, PresetConfig> = {
  quick: { label: "Quick Scan", tools: QUICK_TOOLS },
  auto: { label: "Auto Scan", tools: AUTO_TOOLS },
  deep: { label: "Deep Scan", tools: DEEP_TOOLS },
};

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
  presetMode: PresetMode;
  onPresetClear: () => void;
}

export function CustomScanPanel({
  toolStatus,
  projectCategory,
  onRun,
  disabled,
  presetMode,
  onPresetClear,
}: CustomScanPanelProps) {
  const [open, setOpen] = useState(false);
  const [toolStates, setToolStates] = useState<Record<string, ToolState>>(buildDefaults);
  const [running, setRunning] = useState(false);

  // Load preset when presetMode changes
  useEffect(() => {
    if (!presetMode) return;
    const preset = PRESETS[presetMode];
    if (!preset) return;

    setToolStates(() => {
      const base = buildDefaults();
      for (const [toolName, opts] of Object.entries(preset.tools)) {
        if (!base[toolName]) continue;
        // Only enable if the tool is applicable to this project category
        const isApplicable = PIPELINE_PHASES.some(
          (ph) => ph.tools.includes(toolName) && ph.applicableCategories.includes(projectCategory)
        );
        if (!isApplicable) continue;
        base[toolName].enabled = toolStatus[toolName]?.installed ?? false;
        base[toolName].options = { ...base[toolName].options, ...opts };
      }
      return base;
    });
    setOpen(true);
  }, [presetMode, projectCategory, toolStatus]);

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
    onPresetClear();
  };

  const selectedCount = Object.values(toolStates).filter((s) => s.enabled).length;

  const handleRun = async () => {
    const tools: CustomToolConfig[] = [];
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
      onPresetClear();
    }
  };

  const handleClose = () => {
    setOpen(false);
    onPresetClear();
  };

  return (
    <div className="border-t border-border pt-3">
      <button
        className="flex items-center gap-2 text-xs text-text-muted hover:text-text transition-colors w-full"
        onClick={() => open ? handleClose() : setOpen(true)}
      >
        <Settings2 className="w-3.5 h-3.5 text-purple-400" />
        <span className="font-bold text-purple-400">Custom Scan</span>
        {presetMode && (
          <Badge className="bg-purple-500/15 text-purple-400 text-[10px] ml-1">
            {PRESETS[presetMode]?.label} preset
          </Badge>
        )}
        <span className="text-[10px]">{open ? "\u25B2" : "\u25BC"}</span>
        {selectedCount > 0 && !presetMode && (
          <Badge className="bg-purple-500/15 text-purple-400 text-[10px] ml-1">
            {selectedCount} tool{selectedCount !== 1 ? "s" : ""}
          </Badge>
        )}
      </button>

      {open && (
        <div className="mt-3 space-y-4">
          {presetMode && (
            <div className="flex items-center gap-2 text-xs text-purple-400 bg-purple-500/10 rounded px-3 py-2">
              <Settings2 className="w-3.5 h-3.5" />
              <span className="font-bold">{PRESETS[presetMode]?.label}</span>
              <span className="text-text-muted">— adjust tools and settings below, then launch</span>
            </div>
          )}

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
                  <Play className="w-4 h-4 mr-1" /> Run {presetMode ? PRESETS[presetMode]?.label : "Custom Scan"}
                </>
              )}
            </Button>
          </div>
        </div>
      )}
    </div>
  );
}
