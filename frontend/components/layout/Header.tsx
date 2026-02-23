"use client";

import { useEffect, useState } from "react";
import { checkHealth } from "@/services/api";

export default function Header() {
  const [online, setOnline] = useState<boolean | null>(null);

  useEffect(() => {
    checkHealth()
      .then(() => setOnline(true))
      .catch(() => setOnline(false));
  }, []);

  return (
    <header className="bg-white border-b border-slate-200 h-14 flex items-center px-6 gap-4 flex-shrink-0">
      <div className="flex-1">
        <h1 className="text-sm font-semibold text-slate-700">
          AI-Assisted Information Systems Audit &amp; Penetration Testing Platform
        </h1>
      </div>
      <div className="flex items-center gap-2">
        <span
          className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium ${
            online === null
              ? "bg-slate-100 text-slate-500"
              : online
              ? "bg-green-100 text-green-700"
              : "bg-red-100 text-red-700"
          }`}
        >
          <span
            className={`h-1.5 w-1.5 rounded-full ${
              online === null ? "bg-slate-400" : online ? "bg-green-500" : "bg-red-500"
            }`}
          />
          {online === null ? "Checking…" : online ? "Online" : "Offline"}
        </span>
      </div>
    </header>
  );
}
