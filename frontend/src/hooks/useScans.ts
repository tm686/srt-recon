import { useCallback, useEffect, useState } from "react";
import api from "@/lib/api";
import type { Scan, ScanListResponse } from "@/types/scan";

export function useScans(projectId: number) {
  const [scans, setScans] = useState<Scan[]>([]);
  const [runningCount, setRunningCount] = useState(0);
  const [loading, setLoading] = useState(true);

  const fetch = useCallback(async () => {
    try {
      const { data } = await api.get<ScanListResponse>(
        `/projects/${projectId}/scans`
      );
      setScans(data.scans);
      setRunningCount(data.running_count);
    } finally {
      setLoading(false);
    }
  }, [projectId]);

  useEffect(() => {
    fetch();
    // Poll while scans are running
    const interval = setInterval(fetch, 3000);
    return () => clearInterval(interval);
  }, [fetch]);

  const startScan = async (
    toolName: string,
    scanType: string,
    options: Record<string, unknown> = {},
    targetOverride?: string
  ) => {
    await api.post(`/projects/${projectId}/scans`, {
      tool_name: toolName,
      scan_type: scanType,
      options,
      target_override: targetOverride || null,
    });
    await fetch();
  };

  const cancelScan = async (scanId: number) => {
    await api.post(`/projects/${projectId}/scans/${scanId}/cancel`);
    await fetch();
  };

  const deleteScan = async (scanId: number) => {
    await api.delete(`/projects/${projectId}/scans/${scanId}`);
    await fetch();
  };

  const autoScan = async (ports?: string, scanSpeed?: string) => {
    const body: Record<string, string> = {};
    if (ports) body.ports = ports;
    if (scanSpeed) body.scan_speed = scanSpeed;
    await api.post(`/projects/${projectId}/scans/auto`, body);
    await fetch();
  };

  const quickScan = async (ports?: string, scanSpeed?: string) => {
    const body: Record<string, string> = {};
    if (ports) body.ports = ports;
    if (scanSpeed) body.scan_speed = scanSpeed;
    await api.post(`/projects/${projectId}/scans/quick`, body);
    await fetch();
  };

  const deepScan = async (ports?: string, scanSpeed?: string) => {
    const body: Record<string, string> = {};
    if (ports) body.ports = ports;
    if (scanSpeed) body.scan_speed = scanSpeed;
    await api.post(`/projects/${projectId}/scans/deep`, body);
    await fetch();
  };

  return { scans, runningCount, loading, refresh: fetch, startScan, cancelScan, deleteScan, autoScan, quickScan, deepScan };
}
