import { ProjectList } from "@/components/projects/ProjectList";
import { useProjects } from "@/hooks/useProjects";

export function ProjectsPage() {
  const { projects, create, remove } = useProjects();

  return (
    <ProjectList
      projects={projects}
      onCreate={async (name, desc, category, targetValue) => { await create(name, desc, category, targetValue); }}
      onDelete={remove}
    />
  );
}
