# Frontend — AI-Assisted Pentest Dashboard

This directory contains the Next.js 14 frontend for the AI-Assisted Penetration Testing Platform.

For full project documentation, installation instructions, and API reference, see the [root README](../README.md).

## Quick Start

```bash
# From the repository root, install dependencies:
cd frontend && npm install

# Start the development server (default port 4000):
npm run dev -- -p 4000

# Production build:
npm run build
```

## Pages

| Route | Description |
|-------|-------------|
| `/dashboard` | Scan control, metric cards, vulnerability table, charts |
| `/history` | Scan history list |
| `/history/[id]` | Scan detail view |
| `/reports` | Report management and PDF downloads |
| `/status` | System health and API status |

The dashboard expects the backend API to be running at `http://localhost:3000`.  
Override this with the `NEXT_PUBLIC_API_URL` environment variable.
