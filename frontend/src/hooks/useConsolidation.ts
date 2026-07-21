import { useCallback, useEffect, useState } from "react";
import api from "@/lib/api";
import type { ConsolidationResponse } from "@/types/scan";

export interface ConsolidationFilters {
  result_type?: string;
  status_class?: string;
  priority?: string;
  search?: string;
  sort_by?: string;
  sort_dir?: string;
  limit?: number;
  offset?: number;
}

export function useConsolidation(projectId: number, filters: ConsolidationFilters = {}) {
  const [data, setData] = useState<ConsolidationResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [consolidating, setConsolidating] = useState(false);

  const fetchData = useCallback(async () => {
    if (projectId <= 0) return;
    setLoading(true);
    try {
      const params = new URLSearchParams();
      if (filters.result_type) params.set("result_type", filters.result_type);
      if (filters.status_class) params.set("status_class", filters.status_class);
      if (filters.priority) params.set("priority", filters.priority);
      if (filters.search) params.set("search", filters.search);
      if (filters.sort_by) params.set("sort_by", filters.sort_by);
      if (filters.sort_dir) params.set("sort_dir", filters.sort_dir);
      if (filters.limit) params.set("limit", String(filters.limit));
      if (filters.offset) params.set("offset", String(filters.offset));

      const { data: resp } = await api.get<ConsolidationResponse>(
        `/projects/${projectId}/consolidation?${params}`
      );
      setData(resp);
    } catch {
      // Project may not exist yet
    } finally {
      setLoading(false);
    }
  }, [
    projectId,
    filters.result_type,
    filters.status_class,
    filters.priority,
    filters.search,
    filters.sort_by,
    filters.sort_dir,
    filters.limit,
    filters.offset,
  ]);

  useEffect(() => {
    fetchData();
  }, [fetchData]);

  const runConsolidation = async (runScreenshots = false, threads = 10) => {
    if (projectId <= 0) return;
    setConsolidating(true);
    try {
      await api.post(`/projects/${projectId}/consolidate`, {
        run_screenshots: runScreenshots,
        threads,
      });
      // Refresh after a short delay to let httpx start producing results
      setTimeout(fetchData, 3000);
    } finally {
      setConsolidating(false);
    }
  };

  return { data, loading, consolidating, refresh: fetchData, runConsolidation };
}
