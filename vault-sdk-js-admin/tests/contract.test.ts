import { describe, expect, it } from 'vitest';
import { VaultAdminClient } from '../src/client';

describe('VaultAdminClient request contract', () => {
  it('serializes query params to snake_case and parses list users response', async () => {
    const calls: Array<{ url: string; method: string }> = [];

    const client = new VaultAdminClient({
      baseUrl: 'https://api.example.com/api/v1',
      token: 'token',
      tenantId: 'tenant_123',
      fetch: async (input, init) => {
        calls.push({ url: String(input), method: String(init?.method ?? 'GET') });
        return new Response(
          JSON.stringify({
            users: [
              {
                id: 'usr_1',
                email: 'a@example.com',
                name: 'A',
                status: 'active',
              },
            ],
            total: 1,
            page: 1,
            per_page: 25,
          }),
          {
            status: 200,
            headers: { 'content-type': 'application/json' },
          }
        );
      },
    });

    const result = await client.listUsers({ page: 1, perPage: 25, orgId: 'org_1', email: 'a@' });

    expect(result.users).toHaveLength(1);
    expect(calls).toMatchInlineSnapshot(`
      [
        {
          "method": "GET",
          "url": "https://api.example.com/api/v1/admin/users?page=1&per_page=25&org_id=org_1&email=a%40",
        },
      ]
    `);
  });

  it('supports blob response type for downloads', async () => {
    const client = new VaultAdminClient({
      baseUrl: 'https://api.example.com/api/v1',
      token: 'token',
      tenantId: 'tenant_123',
      fetch: async () =>
        new Response('id,name\n1,a\n', {
          status: 200,
          headers: { 'content-type': 'text/csv' },
        }),
    });

    const blob = await client.downloadBulkExportFile('job_1');
    expect(await blob.text()).toContain('id,name');
  });

  it('sends FormData without forcing application/json content-type', async () => {
    let sentContentType = '';

    const client = new VaultAdminClient({
      baseUrl: 'https://api.example.com/api/v1',
      token: 'token',
      tenantId: 'tenant_123',
      fetch: async (_input, init) => {
        const headers = init?.headers as Record<string, string>;
        sentContentType = headers['Content-Type'] ?? headers['content-type'] ?? '';

        return new Response(JSON.stringify({ id: 'job_1', status: 'queued' }), {
          status: 200,
          headers: { 'content-type': 'application/json' },
        });
      },
    });

    const formData = new FormData();
    formData.append('file', new Blob(['email\nuser@example.com']));

    await client.startBulkImport(formData);
    expect(sentContentType).toBe('');
  });

  it('iterates paginated users correctly', async () => {
    const pages = [
      {
        users: [
          { id: 'u1', email: 'u1@example.com', status: 'active' },
          { id: 'u2', email: 'u2@example.com', status: 'active' },
        ],
        total: 3,
        page: 1,
        per_page: 2,
      },
      {
        users: [{ id: 'u3', email: 'u3@example.com', status: 'suspended' }],
        total: 3,
        page: 2,
        per_page: 2,
      },
    ];

    let idx = 0;
    const client = new VaultAdminClient({
      baseUrl: 'https://api.example.com/api/v1',
      token: 'token',
      tenantId: 'tenant_123',
      fetch: async () =>
        new Response(JSON.stringify(pages[idx++]), {
          status: 200,
          headers: { 'content-type': 'application/json' },
        }),
    });

    const ids: string[] = [];
    for await (const user of client.iterateUsers()) {
      ids.push(user.id);
    }

    expect(ids).toEqual(['u1', 'u2', 'u3']);
  });
});
