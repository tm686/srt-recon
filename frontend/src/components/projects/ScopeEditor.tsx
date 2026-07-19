import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Plus, Trash2, Search } from "lucide-react";
import type { Target, TargetType, ScopeDirection, ScopeValidateResponse } from "@/types/project";

interface Props {
  targets: Target[];
  onAdd: (target: { value: string; target_type: TargetType; direction: ScopeDirection }) => Promise<void>;
  onRemove: (id: number) => Promise<void>;
  onValidate: (values: string[]) => Promise<ScopeValidateResponse>;
}

export function ScopeEditor({ targets, onAdd, onRemove, onValidate }: Props) {
  const [value, setValue] = useState("");
  const [type, setType] = useState<TargetType>("wildcard_domain");
  const [direction, setDirection] = useState<ScopeDirection>("in_scope");
  const [testValue, setTestValue] = useState("");
  const [testResult, setTestResult] = useState<ScopeValidateResponse | null>(null);

  const inScope = targets.filter((t) => t.direction === "in_scope");
  const outScope = targets.filter((t) => t.direction === "out_of_scope");

  const handleAdd = async () => {
    if (!value.trim()) return;
    await onAdd({ value: value.trim(), target_type: type, direction });
    setValue("");
  };

  const handleTest = async () => {
    if (!testValue.trim()) return;
    const result = await onValidate(testValue.split(",").map((v) => v.trim()));
    setTestResult(result);
  };

  const typeBadgeColor = (t: TargetType) => {
    const map: Record<TargetType, string> = {
      ip: "bg-cyan/20 text-cyan",
      ip_range: "bg-yellow/20 text-yellow",
      url: "bg-green/20 text-green",
      wildcard_domain: "bg-primary/20 text-primary",
    };
    return map[t];
  };

  return (
    <div className="space-y-6">
      {/* Add target */}
      <div className="flex gap-2 items-end">
        <div className="flex-1">
          <Input
            placeholder="e.g. *.example.com"
            value={value}
            onChange={(e) => setValue(e.target.value)}
            className="bg-background"
          />
        </div>
        <Select value={type} onValueChange={(v) => setType(v as TargetType)}>
          <SelectTrigger className="w-40 bg-background">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="wildcard_domain">Wildcard Domain</SelectItem>
            <SelectItem value="ip">IP Address</SelectItem>
            <SelectItem value="ip_range">IP Range</SelectItem>
            <SelectItem value="url">URL</SelectItem>
          </SelectContent>
        </Select>
        <Select value={direction} onValueChange={(v) => setDirection(v as ScopeDirection)}>
          <SelectTrigger className="w-32 bg-background">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="in_scope">In Scope</SelectItem>
            <SelectItem value="out_of_scope">Out of Scope</SelectItem>
          </SelectContent>
        </Select>
        <Button onClick={handleAdd} className="bg-green text-background hover:bg-green/90">
          <Plus className="w-4 h-4" />
        </Button>
      </div>

      {/* Two columns */}
      <div className="grid grid-cols-2 gap-4">
        <div>
          <h3 className="text-sm font-bold text-green mb-2">In Scope</h3>
          <div className="space-y-1">
            {inScope.map((t) => (
              <div key={t.id} className="flex items-center justify-between bg-surface p-2 rounded">
                <div className="flex items-center gap-2">
                  <Badge className={typeBadgeColor(t.target_type)}>{t.target_type}</Badge>
                  <span className="text-sm">{t.value}</span>
                </div>
                <Button variant="ghost" size="icon" className="h-6 w-6 text-text-muted hover:text-red" onClick={() => onRemove(t.id)}>
                  <Trash2 className="w-3 h-3" />
                </Button>
              </div>
            ))}
            {inScope.length === 0 && <p className="text-text-muted text-sm">No in-scope targets</p>}
          </div>
        </div>
        <div>
          <h3 className="text-sm font-bold text-red mb-2">Out of Scope</h3>
          <div className="space-y-1">
            {outScope.map((t) => (
              <div key={t.id} className="flex items-center justify-between bg-surface p-2 rounded">
                <div className="flex items-center gap-2">
                  <Badge className={typeBadgeColor(t.target_type)}>{t.target_type}</Badge>
                  <span className="text-sm">{t.value}</span>
                </div>
                <Button variant="ghost" size="icon" className="h-6 w-6 text-text-muted hover:text-red" onClick={() => onRemove(t.id)}>
                  <Trash2 className="w-3 h-3" />
                </Button>
              </div>
            ))}
            {outScope.length === 0 && <p className="text-text-muted text-sm">No out-of-scope targets</p>}
          </div>
        </div>
      </div>

      {/* Scope tester */}
      <div className="border border-border rounded p-4 bg-surface">
        <h3 className="text-sm font-bold text-text mb-2">Scope Tester</h3>
        <div className="flex gap-2">
          <Input
            placeholder="test.example.com, admin.example.com"
            value={testValue}
            onChange={(e) => setTestValue(e.target.value)}
            className="bg-background"
          />
          <Button onClick={handleTest} variant="secondary">
            <Search className="w-4 h-4 mr-1" /> Test
          </Button>
        </div>
        {testResult && (
          <div className="mt-3 grid grid-cols-2 gap-2 text-sm">
            <div>
              <span className="text-green">In scope:</span>
              {testResult.in_scope.map((v) => (
                <div key={v} className="text-green ml-2">{v}</div>
              ))}
              {testResult.in_scope.length === 0 && <div className="text-text-muted ml-2">none</div>}
            </div>
            <div>
              <span className="text-red">Out of scope:</span>
              {testResult.out_of_scope.map((v) => (
                <div key={v} className="text-red ml-2">{v}</div>
              ))}
              {testResult.out_of_scope.length === 0 && <div className="text-text-muted ml-2">none</div>}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
