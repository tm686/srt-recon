import { useCallback, useEffect, useState } from "react";
import api from "@/lib/api";
import type { ApiKey, ApiKeyTestResult } from "@/types/apiKey";

export function useApiKeys(projectId: number) {
  const [keys, setKeys] = useState<ApiKey[]>([]);
  const [loading, setLoading] = useState(true);

  const fetch = useCallback(async () => {
    setLoading(true);
    try {
      const { data } = await api.get<ApiKey[]>(`/projects/${projectId}/keys`);
      setKeys(data);
    } catch {
      setKeys([]);
    } finally {
      setLoading(false);
    }
  }, [projectId]);

  useEffect(() => { fetch(); }, [fetch]);

  const add = async (provider: string, key: string) => {
    await api.post(`/projects/${projectId}/keys`, { provider, key });
    await fetch();
  };

  const remove = async (keyId: number) => {
    await api.delete(`/projects/${projectId}/keys/${keyId}`);
    await fetch();
  };

  const test = async (keyId: number): Promise<ApiKeyTestResult> => {
    const { data } = await api.post<ApiKeyTestResult>(
      `/projects/${projectId}/keys/${keyId}/test`
    );
    await fetch();
    return data;
  };

  return { keys, loading, refresh: fetch, add, remove, test };
}
