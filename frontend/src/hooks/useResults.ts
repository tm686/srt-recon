import { useCallback, useEffect, useState } from "react";
import api from "@/lib/api";
import type { AggregatedResult, ResultStats } from "@/types/scan";

export function useResults(projectId: number, resultType?: string, search?: string) {
  const [results, setResults] = useState<AggregatedResult[]>([]);
  const [stats, setStats] = useState<ResultStats | null>(null);
  const [loading, setLoading] = useState(true);

  const fetchResults = useCallback(async () => {
    setLoading(true);
    try {
      const params = new URLSearchParams();
      if (resultType) params.set("result_type", resultType);
      if (search) params.set("search", search);
      params.set("limit", "500");

      const { data } = await api.get<AggregatedResult[]>(
        `/projects/${projectId}/results?${params}`
      );
      setResults(data);
    } finally {
      setLoading(false);
    }
  }, [projectId, resultType, search]);

  const fetchStats = useCallback(async () => {
    const { data } = await api.get<ResultStats>(
      `/projects/${projectId}/results/stats`
    );
    setStats(data);
  }, [projectId]);

  useEffect(() => {
    fetchResults();
    fetchStats();
  }, [fetchResults, fetchStats]);

  const clearResults = async () => {
    await api.delete(`/projects/${projectId}/results`);
    await fetchResults();
    await fetchStats();
  };

  return { results, stats, loading, refresh: fetchResults, refreshStats: fetchStats, clearResults };
}
