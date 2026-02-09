import { createEnv } from "@t3-oss/env-core";
import { z } from "zod";
const env = createEnv({
  server: {
    NODE_ENV: z.enum(["development", "production", "test"]).default("development"),
    INTERNAL_API_BASE_URL: z.string().url().optional(),
    INTERNAL_API_KEY: z.string().min(1).optional(),
    INTERNAL_UI_TOKEN: z.string().min(1).optional(),
    INTERNAL_UI_PASSWORD: z.string().min(1).optional(),
    INTERNAL_UI_EMAIL: z.string().email().optional(),
    INTERNAL_UI_AUDIT_STORAGE: z.enum(["file"]).optional(),
    LOG_LEVEL: z.enum(["trace", "debug", "info", "warn", "error", "fatal"]).optional(),
    REDIS_URL: z.string().url().optional(),
    UPSTASH_REDIS_REST_URL: z.string().url().optional(),
    UPSTASH_REDIS_REST_TOKEN: z.string().optional(),
    SENTRY_DSN: z.string().url().optional()
  },
  runtimeEnv: process.env,
  emptyStringAsUndefined: true
});
export {
  env as e
};
