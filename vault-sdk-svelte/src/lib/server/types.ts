/**
 * Server Types
 * 
 * TypeScript types for SvelteKit server integration.
 */

import type { Handle, ServerLoad } from '@sveltejs/kit';
import type { User, Session } from '../types.js';

export interface VaultLocals {
  user: User | null;
  session: Session | null;
  token: string | null;
}

// Extend SvelteKit's Locals interface
declare global {
  namespace App {
    interface Locals extends VaultLocals {}
  }
}

export type VaultHandle = Handle;
export type VaultServerLoad = ServerLoad;
