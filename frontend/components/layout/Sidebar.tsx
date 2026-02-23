"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { Shield, LayoutDashboard, History, FileText, Activity } from "lucide-react";

const navLinks = [
  { href: "/dashboard", label: "Dashboard", icon: LayoutDashboard },
  { href: "/history", label: "Scan History", icon: History },
  { href: "/reports", label: "Reports", icon: FileText },
  { href: "/status", label: "System Status", icon: Activity },
];

export default function Sidebar() {
  const pathname = usePathname();

  return (
    <aside className="hidden md:flex w-64 flex-col bg-slate-900 text-white flex-shrink-0">
      <div className="flex items-center gap-3 px-6 py-5 border-b border-slate-700">
        <Shield className="h-7 w-7 text-blue-400" />
        <span className="text-lg font-bold tracking-tight">PenTest AI</span>
      </div>
      <nav className="flex-1 px-3 py-4 space-y-1">
        {navLinks.map(({ href, label, icon: Icon }) => {
          const isActive = pathname === href || pathname.startsWith(href + "/");
          return (
            <Link
              key={href}
              href={href}
              className={`flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-colors ${
                isActive
                  ? "bg-blue-600 text-white"
                  : "text-slate-300 hover:bg-slate-800 hover:text-white"
              }`}
            >
              <Icon className="h-4 w-4 flex-shrink-0" />
              {label}
            </Link>
          );
        })}
      </nav>
      <div className="px-6 py-4 border-t border-slate-700">
        <p className="text-xs text-slate-500">AI Pentest Dashboard v1.0</p>
      </div>
    </aside>
  );
}
