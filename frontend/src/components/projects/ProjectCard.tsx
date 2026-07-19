import { useNavigate } from "react-router-dom";
import { Card, CardHeader, CardTitle, CardDescription, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Trash2, Globe, Server, Cpu, Network } from "lucide-react";
import type { ProjectListItem } from "@/types/project";
import type { ProjectCategory } from "@/types/project";

const CATEGORY_LABELS: Record<ProjectCategory, { label: string; icon: React.ReactNode; color: string }> = {
  wildcard_domain: { label: "Wildcard", icon: <Globe className="w-3 h-3" />, color: "bg-cyan/15 text-cyan" },
  single_host: { label: "Host", icon: <Server className="w-3 h-3" />, color: "bg-green/15 text-green" },
  single_ip: { label: "IP", icon: <Cpu className="w-3 h-3" />, color: "bg-purple-400/15 text-purple-400" },
  cidr_range: { label: "CIDR", icon: <Network className="w-3 h-3" />, color: "bg-orange-400/15 text-orange-400" },
};

interface Props {
  project: ProjectListItem;
  onDelete: (id: number) => void;
}

export function ProjectCard({ project, onDelete }: Props) {
  const navigate = useNavigate();

  return (
    <Card
      className="cursor-pointer hover:border-cyan transition-colors bg-surface"
      onClick={() => navigate(`/projects/${project.id}`)}
    >
      <CardHeader className="pb-2">
        <div className="flex items-start justify-between">
          <CardTitle className="text-sm">{project.name}</CardTitle>
          <Button
            variant="ghost"
            size="icon"
            className="h-6 w-6 text-text-muted hover:text-red"
            onClick={(e) => {
              e.stopPropagation();
              onDelete(project.id);
            }}
          >
            <Trash2 className="w-3 h-3" />
          </Button>
        </div>
        <CardDescription className="text-xs text-text-muted">
          {project.description || "No description"}
        </CardDescription>
      </CardHeader>
      <CardContent>
        <div className="flex items-center gap-2 flex-wrap">
          {project.category && CATEGORY_LABELS[project.category] && (
            <Badge className={`text-[10px] gap-1 ${CATEGORY_LABELS[project.category].color}`}>
              {CATEGORY_LABELS[project.category].icon}
              {CATEGORY_LABELS[project.category].label}
            </Badge>
          )}
          <Badge variant="secondary" className="text-xs">
            {project.target_count} targets
          </Badge>
          <span className="text-xs text-text-muted">
            {new Date(project.updated_at).toLocaleDateString()}
          </span>
        </div>
        {project.target_value && (
          <p className="text-xs font-mono text-text-muted mt-2 truncate">{project.target_value}</p>
        )}
      </CardContent>
    </Card>
  );
}
