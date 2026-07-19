import { ProjectCard } from "./ProjectCard";
import { CreateProjectDialog } from "./CreateProjectDialog";
import type { ProjectListItem, ProjectCategory } from "@/types/project";

interface Props {
  projects: ProjectListItem[];
  onCreate: (name: string, description: string, category: ProjectCategory, targetValue: string) => Promise<void>;
  onDelete: (id: number) => void;
}

export function ProjectList({ projects, onCreate, onDelete }: Props) {
  return (
    <div>
      <div className="flex items-center justify-between mb-6">
        <h1 className="text-lg font-bold text-text">Projects</h1>
        <CreateProjectDialog onCreate={onCreate} />
      </div>
      {projects.length === 0 ? (
        <div className="text-center py-12 text-text-muted">
          No projects yet. Create one to get started.
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {projects.map((p) => (
            <ProjectCard key={p.id} project={p} onDelete={onDelete} />
          ))}
        </div>
      )}
    </div>
  );
}
