import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Shield } from "lucide-react";
import api from "@/lib/api";

export function SetupPage() {
  const navigate = useNavigate();
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");

    if (password.length < 12) {
      setError("Password must be at least 12 characters");
      return;
    }
    if (password !== confirm) {
      setError("Passwords do not match");
      return;
    }

    setLoading(true);
    try {
      await api.post("/setup/master-password", {
        password,
        confirm_password: confirm,
      });
      navigate("/projects");
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Setup failed";
      setError(msg);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-background">
      <Card className="w-full max-w-md bg-surface">
        <CardHeader className="text-center">
          <div className="flex justify-center mb-2">
            <Shield className="w-10 h-10 text-green" />
          </div>
          <CardTitle>SRT-Recon Setup</CardTitle>
          <p className="text-sm text-text-muted mt-1">
            Set a master password to encrypt your API keys.
          </p>
        </CardHeader>
        <CardContent>
          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <Label htmlFor="pw">Master Password (min 12 chars)</Label>
              <Input
                id="pw"
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="bg-background"
                autoFocus
              />
            </div>
            <div>
              <Label htmlFor="confirm">Confirm Password</Label>
              <Input
                id="confirm"
                type="password"
                value={confirm}
                onChange={(e) => setConfirm(e.target.value)}
                className="bg-background"
              />
            </div>
            {error && <p className="text-red text-sm">{error}</p>}
            <Button
              type="submit"
              disabled={loading}
              className="w-full bg-green text-background hover:bg-green/90"
            >
              {loading ? "Setting up..." : "Set Master Password"}
            </Button>
          </form>
        </CardContent>
      </Card>
    </div>
  );
}
