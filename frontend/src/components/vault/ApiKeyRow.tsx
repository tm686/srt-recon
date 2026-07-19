import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Trash2, FlaskConical, Loader2 } from "lucide-react";
import type { ApiKey } from "@/types/apiKey";

interface Props {
  apiKey: ApiKey;
  onTest: (id: number) => Promise<void>;
  onDelete: (id: number) => void;
}

export function ApiKeyRow({ apiKey, onTest, onDelete }: Props) {
  const [testing, setTesting] = useState(false);

  const handleTest = async () => {
    setTesting(true);
    try {
      await onTest(apiKey.id);
    } finally {
      setTesting(false);
    }
  };

  return (
    <div className="flex items-center justify-between bg-surface p-3 rounded">
      <div className="flex items-center gap-3">
        <span className="text-sm font-medium w-28">{apiKey.provider}</span>
        <code className="text-xs text-text-muted">{apiKey.masked_key}</code>
        <Badge className={apiKey.is_valid ? "bg-green/20 text-green" : "bg-text-muted/20 text-text-muted"}>
          {apiKey.is_valid ? "valid" : "untested"}
        </Badge>
      </div>
      <div className="flex gap-1">
        <Button variant="ghost" size="icon" className="h-7 w-7" onClick={handleTest} disabled={testing}>
          {testing ? <Loader2 className="w-3 h-3 animate-spin" /> : <FlaskConical className="w-3 h-3" />}
        </Button>
        <Button variant="ghost" size="icon" className="h-7 w-7 text-text-muted hover:text-red" onClick={() => onDelete(apiKey.id)}>
          <Trash2 className="w-3 h-3" />
        </Button>
      </div>
    </div>
  );
}
