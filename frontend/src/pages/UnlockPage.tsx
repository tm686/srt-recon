import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Lock } from "lucide-react";
import api from "@/lib/api";

export function UnlockPage() {
  const navigate = useNavigate();
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");
    setLoading(true);
    try {
      await api.post("/auth/unlock", { password });
      navigate("/projects");
    } catch {
      setError("Invalid password");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-background">
      <Card className="w-full max-w-md bg-surface">
        <CardHeader className="text-center">
          <div className="flex justify-center mb-2">
            <Lock className="w-10 h-10 text-cyan" />
          </div>
          <CardTitle>Unlock Vault</CardTitle>
          <p className="text-sm text-text-muted mt-1">
            Enter your master password to unlock the API key vault.
          </p>
        </CardHeader>
        <CardContent>
          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <Label htmlFor="pw">Master Password</Label>
              <Input
                id="pw"
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="bg-background"
                autoFocus
              />
            </div>
            {error && <p className="text-red text-sm">{error}</p>}
            <Button
              type="submit"
              disabled={loading || !password}
              className="w-full bg-cyan text-background hover:bg-cyan/90"
            >
              {loading ? "Unlocking..." : "Unlock"}
            </Button>
          </form>
        </CardContent>
      </Card>
    </div>
  );
}
