import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { CheckCircle, XCircle, Loader2, Gauge, Zap, Shield, FileText } from "lucide-react";
import { useSettings, useTools, useWordlists } from "@/hooks/useSettings";
import api from "@/lib/api";
import type { Aggressiveness } from "@/types/settings";

const AGGRESSIVENESS_OPTIONS: { value: Aggressiveness; label: string; icon: React.ReactNode; desc: string }[] = [
  { value: "conservative", label: "Conservative", icon: <Shield className="w-4 h-4" />, desc: "Fewer tools, reduced threads, skip fuzzing — stealth mode" },
  { value: "normal", label: "Normal", icon: <Gauge className="w-4 h-4" />, desc: "Balanced speed and noise — default for most engagements" },
  { value: "aggressive", label: "Aggressive", icon: <Zap className="w-4 h-4" />, desc: "Max threads, extra tools, full fuzzing — fast but loud" },
];

export function SettingsPageContent() {
  const { settings, update } = useSettings();
  const { tools, loading: toolsLoading, refresh: refreshTools } = useTools();
  const { wordlists, refresh: refreshWordlists } = useWordlists();
  const [seclistsPath, setSeclistsPath] = useState("");
  const [threads, setThreads] = useState("");
  const [aggressiveness, setAggressiveness] = useState<Aggressiveness | "">("");
  const [pathValid, setPathValid] = useState<boolean | null>(null);
  const [saving, setSaving] = useState(false);
  const [customWordlist, setCustomWordlist] = useState("");
  const [savingCustom, setSavingCustom] = useState(false);

  if (!settings) return null;

  const currentThreads = threads || String(settings.default_threads);
  const currentAggr = aggressiveness || settings.aggressiveness || "normal";

  const handleValidatePath = async () => {
    const { data } = await api.post("/settings/validate-path", {
      path: seclistsPath || settings.seclists_path,
    });
    setPathValid(data.exists && data.is_directory);
  };

  const handleSave = async () => {
    setSaving(true);
    try {
      await update({
        seclists_path: seclistsPath || settings.seclists_path,
        default_threads: Number(currentThreads) || 10,
        aggressiveness: currentAggr as Aggressiveness,
      });
    } finally {
      setSaving(false);
    }
  };

  // Effective threads display based on aggressiveness
  const baseThreads = Number(currentThreads) || 10;
  const multiplier = currentAggr === "conservative" ? 0.5 : currentAggr === "aggressive" ? 2.5 : 1.0;
  const effectiveThreads = Math.max(1, Math.round(baseThreads * multiplier));

  return (
    <div className="space-y-6 max-w-2xl">
      <h1 className="text-lg font-bold">Settings</h1>

      {/* Scan Configuration */}
      <Card className="bg-surface">
        <CardHeader>
          <CardTitle className="text-sm">Scan Configuration</CardTitle>
        </CardHeader>
        <CardContent className="space-y-5">
          {/* Aggressiveness */}
          <div>
            <Label className="mb-2 block">Aggressiveness</Label>
            <div className="space-y-2">
              {AGGRESSIVENESS_OPTIONS.map((opt) => (
                <button
                  key={opt.value}
                  onClick={() => setAggressiveness(opt.value)}
                  className={`w-full text-left p-3 rounded-lg border transition-all flex items-center gap-3 ${
                    currentAggr === opt.value
                      ? "border-cyan bg-cyan/5"
                      : "border-border hover:border-cyan/40 bg-background"
                  }`}
                >
                  <div className={`${currentAggr === opt.value ? "text-cyan" : "text-text-muted"}`}>
                    {opt.icon}
                  </div>
                  <div className="flex-1">
                    <div className="text-sm font-bold text-text">{opt.label}</div>
                    <div className="text-xs text-text-muted">{opt.desc}</div>
                  </div>
                  {currentAggr === opt.value && (
                    <Badge className="bg-cyan/15 text-cyan text-[10px]">Active</Badge>
                  )}
                </button>
              ))}
            </div>
          </div>

          {/* Threads */}
          <div>
            <Label htmlFor="threads">Base Thread Count</Label>
            <div className="flex items-center gap-3 mt-1">
              <Input
                id="threads"
                type="number"
                min={1}
                max={100}
                value={currentThreads}
                onChange={(e) => setThreads(e.target.value)}
                className="bg-background w-24"
              />
              <span className="text-xs text-text-muted">
                Effective: <span className="text-cyan font-bold">{effectiveThreads}</span> threads
                ({currentAggr} = {multiplier}x multiplier)
              </span>
            </div>
            <p className="text-xs text-text-muted mt-1">
              Base threads per tool. Multiplied by aggressiveness level.
            </p>
          </div>
        </CardContent>
      </Card>

      {/* Paths */}
      <Card className="bg-surface">
        <CardHeader>
          <CardTitle className="text-sm">Paths</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div>
            <Label>SecLists Path</Label>
            <div className="flex gap-2 mt-1">
              <Input
                value={seclistsPath || settings.seclists_path}
                onChange={(e) => { setSeclistsPath(e.target.value); setPathValid(null); }}
                className="bg-background"
              />
              <Button variant="secondary" onClick={handleValidatePath}>
                Validate
              </Button>
            </div>
            {pathValid !== null && (
              <p className={`text-sm mt-1 ${pathValid ? "text-green" : "text-red"}`}>
                {pathValid ? "Path is valid" : "Path not found or not a directory"}
              </p>
            )}
          </div>
          <Button
            onClick={handleSave}
            disabled={saving}
            className="bg-cyan text-background hover:bg-cyan/90"
          >
            {saving ? "Saving..." : "Save Settings"}
          </Button>
        </CardContent>
      </Card>

      {/* Wordlists */}
      <Card className="bg-surface">
        <CardHeader>
          <CardTitle className="text-sm flex items-center gap-2">
            <FileText className="w-4 h-4" /> Wordlists
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          {/* ffuf wordlist selector */}
          <div>
            <Label className="mb-1 block">ffuf Wordlist</Label>
            <Select
              value={settings.wordlist_ffuf || "__default__"}
              onValueChange={(v) => update({ wordlist_ffuf: v === "__default__" ? "" : v })}
            >
              <SelectTrigger className="bg-background">
                <SelectValue placeholder="Select wordlist" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="__default__">
                  Default (bundled small — 2,500 words)
                </SelectItem>
                {wordlists.map((wl) => (
                  <SelectItem key={wl.path} value={wl.path}>
                    {wl.name}
                    <span className="text-text-muted ml-2">
                      ({wl.source} · {wl.size_kb} KB)
                    </span>
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            {settings.wordlist_ffuf && (
              <Badge variant="secondary" className="text-xs mt-2">
                {settings.wordlist_ffuf.split("/").pop()}
              </Badge>
            )}
          </div>

          {/* Custom wordlist */}
          <div>
            <Label className="mb-1 block">Paste Custom Wordlist</Label>
            <textarea
              value={customWordlist}
              onChange={(e) => setCustomWordlist(e.target.value)}
              placeholder="one/path/per/line&#10;admin&#10;login&#10;api/v1"
              className="w-full h-32 bg-background border border-border rounded p-2 text-sm font-mono text-text resize-y"
            />
            <Button
              variant="secondary"
              size="sm"
              className="mt-2"
              disabled={!customWordlist.trim() || savingCustom}
              onClick={async () => {
                setSavingCustom(true);
                try {
                  await api.post("/settings/wordlists/custom", customWordlist, {
                    headers: { "Content-Type": "text/plain" },
                  });
                  setCustomWordlist("");
                  refreshWordlists();
                } finally {
                  setSavingCustom(false);
                }
              }}
            >
              {savingCustom ? "Saving..." : "Save Custom Wordlist"}
            </Button>
          </div>
        </CardContent>
      </Card>

      {/* Tool Status */}
      <Card className="bg-surface">
        <CardHeader className="flex flex-row items-center justify-between">
          <CardTitle className="text-sm">Tool Status</CardTitle>
          <Button variant="ghost" size="sm" onClick={refreshTools} disabled={toolsLoading}>
            {toolsLoading ? <Loader2 className="w-3 h-3 animate-spin" /> : "Refresh"}
          </Button>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-2 gap-2">
            {tools.map((t) => (
              <div key={t.name} className="flex items-center gap-2 text-sm">
                {t.installed ? (
                  <CheckCircle className="w-4 h-4 text-green" />
                ) : (
                  <XCircle className="w-4 h-4 text-red" />
                )}
                <span>{t.name}</span>
                {t.installed && (
                  <Badge variant="secondary" className="text-xs">
                    installed
                  </Badge>
                )}
              </div>
            ))}
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
