export type Aggressiveness = "conservative" | "normal" | "aggressive";

export interface Settings {
  seclists_path: string;
  go_tools_path: string;
  default_threads: number;
  aggressiveness: Aggressiveness;
  wordlist_ffuf: string;
  setup_complete: boolean;
}

export interface WordlistOption {
  name: string;
  path: string;
  size_kb: number;
  source: string;
}

export interface SetupStatus {
  setup_complete: boolean;
  vault_unlocked: boolean;
}

export interface ToolStatus {
  name: string;
  installed: boolean;
  path: string | null;
}

export interface PathValidation {
  path: string;
  exists: boolean;
  is_directory: boolean;
}
