import { useCallback, useEffect, useState } from "react";
import api from "@/lib/api";
import type { Settings, SetupStatus, ToolStatus, WordlistOption } from "@/types/settings";

export function useSettings() {
  const [settings, setSettings] = useState<Settings | null>(null);
  const [loading, setLoading] = useState(true);

  const fetch = useCallback(async () => {
    setLoading(true);
    try {
      const { data } = await api.get<Settings>("/settings");
      setSettings(data);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { fetch(); }, [fetch]);

  const update = async (updates: Partial<Settings>) => {
    await api.put("/settings", updates);
    await fetch();
  };

  return { settings, loading, refresh: fetch, update };
}

export function useSetupStatus() {
  const [status, setStatus] = useState<SetupStatus | null>(null);
  const [loading, setLoading] = useState(true);

  const fetch = useCallback(async () => {
    setLoading(true);
    try {
      const { data } = await api.get<SetupStatus>("/setup/status");
      setStatus(data);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { fetch(); }, [fetch]);

  return { status, loading, refresh: fetch };
}

export function useTools() {
  const [tools, setTools] = useState<ToolStatus[]>([]);
  const [loading, setLoading] = useState(true);

  const fetch = useCallback(async () => {
    setLoading(true);
    try {
      const { data } = await api.get<ToolStatus[]>("/settings/tools");
      setTools(data);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { fetch(); }, [fetch]);

  return { tools, loading, refresh: fetch };
}

export function useWordlists() {
  const [wordlists, setWordlists] = useState<WordlistOption[]>([]);
  const [loading, setLoading] = useState(true);

  const fetch = useCallback(async () => {
    setLoading(true);
    try {
      const { data } = await api.get<WordlistOption[]>("/settings/wordlists");
      setWordlists(data);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { fetch(); }, [fetch]);

  return { wordlists, loading, refresh: fetch };
}
