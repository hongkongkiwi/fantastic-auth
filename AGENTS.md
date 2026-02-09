# Agent Context

## Package Manager Policy

- Use `pnpm` for all JavaScript/TypeScript work in this repository.
- Do not use `npm` for install, run, test, build, or audit commands in `packages/apps/web-platform`, `packages/apps/web-tenant`, or `packages/apps/web-user`.
- Prefer `pnpm install --frozen-lockfile` in CI/non-interactive environments.
- Keep lockfiles per app (`packages/apps/*/pnpm-lock.yaml`); do not introduce a shared root workspace lockfile for these three apps.

## Web Apps

- `packages/apps/web-platform`
- `packages/apps/web-tenant`
- `packages/apps/web-user`

## Common Commands

- Install deps: `pnpm install`
- Start dev: `pnpm dev`
- Lint: `pnpm lint`
- Typecheck: `pnpm typecheck`
- Test: `pnpm test`
- Build: `pnpm build`
- Run commands inside each app directory.
