import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Plus } from "lucide-react";
import { ApiKeyRow } from "./ApiKeyRow";
import { useApiKeys } from "@/hooks/useApiKeys";

const PROVIDERS = [
  "securitytrails",
  "shodan",
  "censys",
  "github",
  "virustotal",
  "chaos",
];

interface Props {
  projectId: number;
}

export function ApiKeyVault({ projectId }: Props) {
  const { keys, add, remove, test } = useApiKeys(projectId);
  const [provider, setProvider] = useState(PROVIDERS[0]);
  const [keyValue, setKeyValue] = useState("");

  const handleAdd = async () => {
    if (!keyValue.trim()) return;
    await add(provider, keyValue.trim());
    setKeyValue("");
  };

  return (
    <div className="space-y-4">
      <div className="flex gap-2">
        <Select value={provider} onValueChange={(v) => setProvider(v ?? "")}>
          <SelectTrigger className="w-40 bg-background">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            {PROVIDERS.map((p) => (
              <SelectItem key={p} value={p}>{p}</SelectItem>
            ))}
          </SelectContent>
        </Select>
        <Input
          type="password"
          placeholder="Paste API key"
          value={keyValue}
          onChange={(e) => setKeyValue(e.target.value)}
          className="flex-1 bg-background"
        />
        <Button onClick={handleAdd} className="bg-green text-background hover:bg-green/90">
          <Plus className="w-4 h-4 mr-1" /> Add
        </Button>
      </div>
      <div className="space-y-2">
        {keys.map((k) => (
          <ApiKeyRow
            key={k.id}
            apiKey={k}
            onTest={async (id) => { await test(id); }}
            onDelete={remove}
          />
        ))}
        {keys.length === 0 && (
          <p className="text-text-muted text-sm py-4 text-center">
            No API keys added yet.
          </p>
        )}
      </div>
    </div>
  );
}
