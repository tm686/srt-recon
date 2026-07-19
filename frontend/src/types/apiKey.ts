export interface ApiKey {
  id: number;
  project_id: number;
  provider: string;
  masked_key: string;
  is_valid: boolean;
  last_tested_at: string | null;
}

export interface ApiKeyTestResult {
  id: number;
  provider: string;
  is_valid: boolean;
  message: string;
}
