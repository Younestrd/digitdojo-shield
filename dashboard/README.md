# DigitDojo Shield Console

The console is a Next.js App Router frontend for a running DigitDojo Shield daemon.

## Runtime configuration

Copy `.env.example` to `.env.local` and set `SHIELD_API_URL` to the daemon API address. The dashboard proxy keeps daemon API tokens out of browser JavaScript.

## Installation and validation

```bash
npm install
npm run typecheck
npm run lint
npm run build
```

Start the console with `npm run dev`. Sign in using a Shield API token; the console verifies it against `/stats` and retains it only in an HTTP-only session cookie.

## Backend capabilities

The dashboard displays live telemetry from `/stats`, current blocks from `/blocked`, and real daemon events from `/events`. Screens whose daemon APIs do not yet exist identify that limitation rather than inventing data.
