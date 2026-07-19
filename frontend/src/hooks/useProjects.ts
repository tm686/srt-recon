import { useCallback, useEffect, useState } from "react";
import api from "@/lib/api";
import type { Project, ProjectCategory, ProjectListItem, Target } from "@/types/project";

export function useProjects() {
  const [projects, setProjects] = useState<ProjectListItem[]>([]);
  const [loading, setLoading] = useState(true);

  const fetch = useCallback(async () => {
    setLoading(true);
    try {
      const { data } = await api.get<ProjectListItem[]>("/projects");
      setProjects(data);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { fetch(); }, [fetch]);

  const create = async (name: string, description: string, category: ProjectCategory, targetValue: string) => {
    const { data } = await api.post<Project>("/projects", {
      name, description, category, target_value: targetValue,
    });
    await fetch();
    return data;
  };

  const remove = async (id: number) => {
    await api.delete(`/projects/${id}`);
    await fetch();
  };

  return { projects, loading, refresh: fetch, create, remove };
}

export function useProject(id: number) {
  const [project, setProject] = useState<Project | null>(null);
  const [loading, setLoading] = useState(true);

  const fetch = useCallback(async () => {
    setLoading(true);
    try {
      const { data } = await api.get<Project>(`/projects/${id}`);
      setProject(data);
    } finally {
      setLoading(false);
    }
  }, [id]);

  useEffect(() => { fetch(); }, [fetch]);

  const addTarget = async (target: Omit<Target, "id" | "project_id">) => {
    await api.post(`/projects/${id}/targets`, target);
    await fetch();
  };

  const removeTarget = async (targetId: number) => {
    await api.delete(`/projects/${id}/targets/${targetId}`);
    await fetch();
  };

  const validateScope = async (values: string[]) => {
    const { data } = await api.post(`/projects/${id}/targets/validate`, { values });
    return data;
  };

  return { project, loading, refresh: fetch, addTarget, removeTarget, validateScope };
}
