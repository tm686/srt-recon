import { useParams, useNavigate } from "react-router-dom";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Button } from "@/components/ui/button";
import { ArrowLeft } from "lucide-react";
import { ScopeEditor } from "@/components/projects/ScopeEditor";
import { ApiKeyVault } from "@/components/vault/ApiKeyVault";
import { useProject } from "@/hooks/useProjects";

export function ProjectDetailPage() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const projectId = Number(id);
  const { project, loading, addTarget, removeTarget, validateScope } = useProject(projectId);

  if (loading || !project) {
    return <div className="text-text-muted">Loading...</div>;
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-3">
        <Button variant="ghost" size="icon" onClick={() => navigate("/projects")}>
          <ArrowLeft className="w-4 h-4" />
        </Button>
        <div>
          <h1 className="text-lg font-bold">{project.name}</h1>
          {project.description && (
            <p className="text-sm text-text-muted">{project.description}</p>
          )}
        </div>
      </div>

      <Tabs defaultValue="scope">
        <TabsList className="bg-surface">
          <TabsTrigger value="scope">Scope</TabsTrigger>
          <TabsTrigger value="scans">Scan History</TabsTrigger>
          <TabsTrigger value="keys">API Keys</TabsTrigger>
        </TabsList>

        <TabsContent value="scope" className="mt-4">
          <ScopeEditor
            targets={project.targets}
            onAdd={addTarget}
            onRemove={removeTarget}
            onValidate={validateScope}
          />
        </TabsContent>

        <TabsContent value="scans" className="mt-4">
          <p className="text-text-muted text-sm">Scan history will appear here once scans are run.</p>
        </TabsContent>

        <TabsContent value="keys" className="mt-4">
          <ApiKeyVault projectId={projectId} />
        </TabsContent>
      </Tabs>
    </div>
  );
}
