import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Download, Search, Trash2 } from "lucide-react";
import { useProjects } from "@/hooks/useProjects";
import { useResults } from "@/hooks/useResults";

const RESULT_TYPES = [
  { value: "", label: "All Types" },
  { value: "subdomain", label: "Subdomains" },
  { value: "live_host", label: "Live Hosts" },
  { value: "url", label: "URLs" },
  { value: "port", label: "Ports" },
  { value: "directory", label: "Directories" },
  { value: "vulnerability", label: "Vulnerabilities" },
  { value: "dns_record", label: "DNS Records" },
];

export function ResultsPage() {
  const { projects } = useProjects();
  const [selectedProject, setSelectedProject] = useState<string>("");
  const [resultType, setResultType] = useState("");
  const [search, setSearch] = useState("");
  const [searchInput, setSearchInput] = useState("");

  const projectId = selectedProject ? Number(selectedProject) : 0;
  const { results, stats, loading, clearResults } = useResults(
    projectId || -1,
    resultType || undefined,
    search || undefined
  );

  const handleSearch = () => setSearch(searchInput);

  const exportUrl = (format: string) => {
    const params = new URLSearchParams();
    if (resultType) params.set("result_type", resultType);
    return `/api/projects/${projectId}/export/${format}?${params}`;
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-lg font-bold">Results</h1>
        {projectId > 0 && (
          <div className="flex gap-2">
            <a href={exportUrl("json")} download>
              <Button variant="secondary" size="sm">
                <Download className="w-3 h-3 mr-1" /> JSON
              </Button>
            </a>
            <a href={exportUrl("csv")} download>
              <Button variant="secondary" size="sm">
                <Download className="w-3 h-3 mr-1" /> CSV
              </Button>
            </a>
            <a href={exportUrl("markdown")} download>
              <Button variant="secondary" size="sm">
                <Download className="w-3 h-3 mr-1" /> Report
              </Button>
            </a>
            <Button
              variant="secondary"
              size="sm"
              className="text-red hover:text-red"
              onClick={clearResults}
            >
              <Trash2 className="w-3 h-3 mr-1" /> Clear
            </Button>
          </div>
        )}
      </div>

      {/* Filters */}
      <div className="flex gap-3 items-end">
        <div>
          <Select value={selectedProject} onValueChange={(v) => setSelectedProject(v ?? "")}>
            <SelectTrigger className="w-48 bg-surface">
              <SelectValue placeholder="Select project" />
            </SelectTrigger>
            <SelectContent>
              {projects.map((p) => (
                <SelectItem key={p.id} value={String(p.id)}>
                  {p.name}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
        <div>
          <Select value={resultType} onValueChange={(v) => setResultType(v ?? "")}>
            <SelectTrigger className="w-40 bg-surface">
              <SelectValue placeholder="All Types" />
            </SelectTrigger>
            <SelectContent>
              {RESULT_TYPES.map((t) => (
                <SelectItem key={t.value} value={t.value}>
                  {t.label}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
        <div className="flex gap-1 flex-1">
          <Input
            placeholder="Search results..."
            value={searchInput}
            onChange={(e) => setSearchInput(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && handleSearch()}
            className="bg-surface"
          />
          <Button variant="secondary" onClick={handleSearch}>
            <Search className="w-4 h-4" />
          </Button>
        </div>
      </div>

      {/* Stats */}
      {projectId > 0 && stats && (
        <div className="grid grid-cols-4 md:grid-cols-7 gap-2">
          {[
            { label: "Subdomains", count: stats.subdomains, color: "text-cyan" },
            { label: "Live Hosts", count: stats.live_hosts, color: "text-green" },
            { label: "URLs", count: stats.urls, color: "text-primary" },
            { label: "Ports", count: stats.ports, color: "text-yellow" },
            { label: "Dirs", count: stats.directories, color: "text-text" },
            { label: "Vulns", count: stats.vulnerabilities, color: "text-red" },
            { label: "DNS", count: stats.dns_records, color: "text-text-muted" },
          ].map((s) => (
            <Card key={s.label} className="bg-surface">
              <CardContent className="p-3 text-center">
                <div className={`text-xl font-bold ${s.color}`}>{s.count}</div>
                <div className="text-xs text-text-muted">{s.label}</div>
              </CardContent>
            </Card>
          ))}
        </div>
      )}

      {/* Results table */}
      {projectId > 0 && (
        <Card className="bg-surface">
          <CardHeader>
            <CardTitle className="text-sm">
              {loading ? "Loading..." : `${results.length} results`}
            </CardTitle>
          </CardHeader>
          <CardContent>
            {results.length === 0 ? (
              <p className="text-text-muted text-sm py-4 text-center">
                No results yet. Run scans to collect data.
              </p>
            ) : (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Value</TableHead>
                    <TableHead>Type</TableHead>
                    <TableHead>Seen</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {results.map((r, i) => (
                    <TableRow key={`${r.value}-${i}`}>
                      <TableCell className="font-mono text-sm max-w-md truncate">
                        {r.value}
                      </TableCell>
                      <TableCell>
                        <Badge variant="secondary" className="text-xs">
                          {r.result_type}
                        </Badge>
                      </TableCell>
                      <TableCell className="text-text-muted">{r.count}x</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            )}
          </CardContent>
        </Card>
      )}
    </div>
  );
}
