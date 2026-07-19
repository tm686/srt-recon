import { useState } from "react";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Plus, Globe, Server, Cpu, Network, List } from "lucide-react";
import { PROJECT_CATEGORIES } from "@/types/project";
import type { ProjectCategory } from "@/types/project";

const ICONS: Record<ProjectCategory, React.ReactNode> = {
  wildcard_domain: <Globe className="w-5 h-5" />,
  single_host: <Server className="w-5 h-5" />,
  single_ip: <Cpu className="w-5 h-5" />,
  cidr_range: <Network className="w-5 h-5" />,
  ip_list: <List className="w-5 h-5" />,
};

interface Props {
  onCreate: (name: string, description: string, category: ProjectCategory, targetValue: string) => Promise<void>;
}

export function CreateProjectDialog({ onCreate }: Props) {
  const [open, setOpen] = useState(false);
  const [step, setStep] = useState<1 | 2>(1);
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [category, setCategory] = useState<ProjectCategory>("wildcard_domain");
  const [targetValue, setTargetValue] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const selectedCat = PROJECT_CATEGORIES.find((c) => c.value === category)!;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");
    if (!targetValue.trim()) {
      setError("Target value is required");
      return;
    }
    setLoading(true);
    try {
      await onCreate(name, description, category, targetValue.trim());
      setName("");
      setDescription("");
      setCategory("wildcard_domain");
      setTargetValue("");
      setStep(1);
      setOpen(false);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Failed to create project";
      setError(msg);
    } finally {
      setLoading(false);
    }
  };

  const handleClose = (v: boolean) => {
    setOpen(v);
    if (!v) { setStep(1); setError(""); }
  };

  return (
    <Dialog open={open} onOpenChange={handleClose}>
      <DialogTrigger render={<Button className="bg-green text-background hover:bg-green/90" />}>
        <Plus className="w-4 h-4 mr-1" /> New Project
      </DialogTrigger>
      <DialogContent className="bg-surface border-border max-w-lg">
        <DialogHeader>
          <DialogTitle>{step === 1 ? "Choose Target Type" : "Project Details"}</DialogTitle>
        </DialogHeader>

        {step === 1 && (
          <div className="space-y-3">
            {PROJECT_CATEGORIES.map((cat) => (
              <button
                key={cat.value}
                onClick={() => { setCategory(cat.value); setStep(2); }}
                className={`w-full text-left p-4 rounded-lg border transition-all ${
                  category === cat.value
                    ? "border-cyan bg-cyan/5"
                    : "border-border hover:border-cyan/40 bg-background"
                }`}
              >
                <div className="flex items-center gap-3">
                  <div className="text-cyan">{ICONS[cat.value]}</div>
                  <div>
                    <div className="text-sm font-bold text-text">{cat.label}</div>
                    <div className="text-xs text-text-muted">{cat.description}</div>
                  </div>
                </div>
              </button>
            ))}
          </div>
        )}

        {step === 2 && (
          <form onSubmit={handleSubmit} className="space-y-4">
            <div className="flex items-center gap-2 p-2 bg-background rounded border border-border">
              <div className="text-cyan">{ICONS[category]}</div>
              <span className="text-sm text-text-muted">{selectedCat.label}</span>
              <Button
                type="button"
                variant="ghost"
                size="sm"
                className="ml-auto text-xs text-text-muted"
                onClick={() => setStep(1)}
              >
                Change
              </Button>
            </div>

            <div>
              <Label htmlFor="target">
                {category === "ip_list" ? "IP Addresses (one per line)" : "Target"}
              </Label>
              {category === "ip_list" ? (
                <textarea
                  id="target"
                  value={targetValue}
                  onChange={(e) => setTargetValue(e.target.value)}
                  placeholder={selectedCat.placeholder}
                  required
                  className="w-full h-36 bg-background border border-border rounded p-2 text-sm font-mono text-text resize-y mt-1"
                  autoFocus
                />
              ) : (
                <Input
                  id="target"
                  value={targetValue}
                  onChange={(e) => setTargetValue(e.target.value)}
                  placeholder={selectedCat.placeholder}
                  required
                  className="bg-background font-mono"
                  autoFocus
                />
              )}
            </div>
            <div>
              <Label htmlFor="name">Project Name</Label>
              <Input
                id="name"
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="e.g. target-corp"
                required
                className="bg-background"
              />
            </div>
            <div>
              <Label htmlFor="desc">Description (optional)</Label>
              <Input
                id="desc"
                value={description}
                onChange={(e) => setDescription(e.target.value)}
                placeholder="SRT engagement notes"
                className="bg-background"
              />
            </div>
            {error && <p className="text-red text-sm">{error}</p>}
            <Button
              type="submit"
              disabled={loading || !name || !targetValue}
              className="w-full bg-cyan text-background hover:bg-cyan/90"
            >
              {loading ? "Creating..." : "Create Project"}
            </Button>
          </form>
        )}
      </DialogContent>
    </Dialog>
  );
}
