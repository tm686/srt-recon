import { NavLink } from "react-router-dom";
import { FolderOpen, Crosshair, FileText, Settings, Shield } from "lucide-react";

const links = [
  { to: "/projects", label: "Projects", icon: FolderOpen },
  { to: "/scan", label: "Active Scan", icon: Crosshair },
  { to: "/results", label: "Results", icon: FileText },
  { to: "/settings", label: "Settings", icon: Settings },
];

export function Sidebar() {
  return (
    <aside className="w-56 border-r border-border bg-surface flex flex-col min-h-screen">
      <div className="p-4 border-b border-border flex items-center gap-2">
        <Shield className="w-5 h-5 text-green" />
        <span className="text-sm font-bold text-green">SRT-Recon</span>
      </div>
      <nav className="flex-1 p-2 space-y-1">
        {links.map(({ to, label, icon: Icon }) => (
          <NavLink
            key={to}
            to={to}
            className={({ isActive }) =>
              `flex items-center gap-2 px-3 py-2 rounded-md text-sm transition-colors ${
                isActive
                  ? "bg-accent text-cyan"
                  : "text-text-muted hover:text-text hover:bg-surface"
              }`
            }
          >
            <Icon className="w-4 h-4" />
            {label}
          </NavLink>
        ))}
      </nav>
      <div className="p-4 border-t border-border text-xs text-text-muted">
        v0.1.0
      </div>
    </aside>
  );
}
