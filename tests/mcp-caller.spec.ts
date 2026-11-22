/**
 * tests/mcp-caller.spec.ts
 *
 * Keyed callers on the hosted MCP endpoint (#2209): an agent presenting an API
 * key is counted as that key, with its tier's limits, instead of as the IP its
 * cloud egress happens to use.
 */
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { NextRequest } from 'next/server';
import type { AuthInfo } from '@modelcontextprotocol/sdk/server/auth/types.js';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { POST } from '@/app/api/mcp/route';
import { clearRateLimitStore } from '@/lib/api/rate-limit';
import {
  MCP_TOOL_RATE_LIMIT_BUCKET,
  RATE_LIMITED_META_KEY,
  applyToolRateLimit,
  resolveClientId,
} from '@/lib/mcp/rate-limit';
import { resolveCaller } from '@/lib/auth/mcp-caller';

const MCP_ACCEPT = 'application/json, text/event-stream';
const VALID_KEY = 'sk_test_agent_1';
const KEY_STORE = JSON.stringify({
  [VALID_KEY]: {
    id: 'agent-1',
    tier: 'standard',
    scopes: ['tools:read'],
    maxIntentAmount: '100',
  },
});

interface JsonRpcResponse {
  jsonrpc: string;
  id: number | string | null;
  result?: Record<string, unknown>;
  error?: { code: number; message: string };
}

function mcpRequest(body: unknown, headers: Record<string, string> = {}): NextRequest {
  return new NextRequest('http://localhost/api/mcp', {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      accept: MCP_ACCEPT,
      ...headers,
    },
    body: JSON.stringify(body),
  });
}

const INITIALIZE = {
  jsonrpc: '2.0',
  id: 1,
  method: 'initialize',
  params: {
    protocolVersion: '2025-06-18',
    capabilities: {},
    clientInfo: { name: 'keyed-test-client', version: '0.0.0' },
  },
};

async function readJsonRpc(response: Response): Promise<JsonRpcResponse> {
  const text = await response.text();
  const line = text
    .split('\n')
    .map((l) => l.trim())
    .find((l) => l.startsWith('data:'));
  return JSON.parse(line ? line.slice('data:'.length).trim() : text) as JsonRpcResponse;
}

beforeEach(() => {
  clearRateLimitStore();
  vi.stubEnv('MCP_API_KEYS', KEY_STORE);
});

afterEach(() => {
  vi.unstubAllEnvs();
});

describe('POST /api/mcp — API key callers', () => {
  it('rejects an invalid key with a JSON-RPC 401', async () => {
    const response = await POST(
      mcpRequest(INITIALIZE, { authorization: 'Bearer not-a-configured-key' })
    );

    expect(response.status).toBe(401);
    expect(response.headers.get('WWW-Authenticate')).toBe(
      'Bearer realm="stellar-intel", error="invalid_token"'
    );

    const body = await readJsonRpc(response);
    expect(body.jsonrpc).toBe('2.0');
    expect(body.id).toBeNull();
    expect(body.error?.code).toBe(-32001);
    expect(body.error?.message).toBe('Invalid API key');
  });

  it('initializes and lists tools for a valid key', async () => {
    const init = await POST(mcpRequest(INITIALIZE, { authorization: `Bearer ${VALID_KEY}` }));
    expect(init.status).toBe(200);
    const initBody = await readJsonRpc(init);
    expect(initBody.error).toBeUndefined();
    expect(initBody.result?.serverInfo).toBeDefined();

    const list = await POST(
      mcpRequest(
        { jsonrpc: '2.0', id: 2, method: 'tools/list', params: {} },
        { authorization: `Bearer ${VALID_KEY}` }
      )
    );
    expect(list.status).toBe(200);
    const listBody = await readJsonRpc(list);
    expect(listBody.error).toBeUndefined();
    expect((listBody.result?.tools as Array<{ name: string }>).length).toBeGreaterThan(0);
  });
});

describe('resolveCaller', () => {
  it('treats a request without Authorization as anonymous, counted by IP', () => {
    const result = resolveCaller(new Headers({ 'x-forwarded-for': '203.0.113.7' }));
    expect(result.ok).toBe(true);
    if (!result.ok) return;

    expect(result.caller.kind).toBe('anonymous');
    expect(result.caller.tier).toBe('anonymous');
    expect(result.caller.rateLimitKey).toBe('ip:203.0.113.7');
  });

  it('resolves a configured key to its identity, tier, scopes and key limit', () => {
    const result = resolveCaller(new Headers({ authorization: `Bearer ${VALID_KEY}` }));
    expect(result.ok).toBe(true);
    if (!result.ok) return;

    expect(result.caller).toEqual({
      kind: 'key',
      id: 'agent-1',
      tier: 'standard',
      scopes: ['tools:read'],
      rateLimitKey: 'key:agent-1',
      maxIntentAmount: '100',
    });
  });

  it('rejects a non-Bearer authorization header', () => {
    const result = resolveCaller(new Headers({ authorization: 'Basic abc' }));
    expect(result.ok).toBe(false);
  });
});

describe('resolveClientId with authInfo', () => {
  const authInfo: AuthInfo = {
    token: '',
    clientId: 'agent-1',
    scopes: [],
    extra: { tier: 'standard', rateLimitKey: 'key:agent-1' },
  };

  it('prefers a keyed rateLimitKey over the forwarded IP', () => {
    expect(
      resolveClientId({
        authInfo,
        requestInfo: { headers: { 'x-forwarded-for': '203.0.113.7' } },
      })
    ).toBe('key:agent-1');
  });

  it('keeps the existing IP fallback when there is no authInfo', () => {
    expect(
      resolveClientId({ requestInfo: { headers: { 'x-forwarded-for': '203.0.113.7' } } })
    ).toBe('ip:203.0.113.7');
  });
});

describe('applyToolRateLimit with a tiered caller', () => {
  type ToolResult = {
    isError?: boolean;
    content?: Array<{ type: string; text?: string }>;
    _meta?: Record<string, unknown>;
  };

  const authInfo: AuthInfo = {
    token: '',
    clientId: 'agent-1',
    scopes: [],
    extra: { tier: 'standard', rateLimitKey: 'key:agent-1' },
  };

  it('multiplies the tool cap by the tier and rejects the call past it', async () => {
    const server = new McpServer({ name: 'tier-test', version: '0.0.0' });
    // One call for an anonymous caller; five for a standard key.
    applyToolRateLimit(server, { maxRequests: 1 });
    server.registerTool('echo', { description: 'echoes' }, async () => ({
      content: [{ type: 'text', text: 'ok' }],
    }));

    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    // Every message from this client carries the caller's authInfo, which is
    // what the hosted route does with `handleRequest(request, { authInfo })`.
    const send = clientTransport.send.bind(clientTransport);
    clientTransport.send = ((message, options) =>
      send(message, { ...options, authInfo })) as typeof clientTransport.send;

    const client = new Client({ name: 'tier-test-client', version: '0.0.0' });
    await Promise.all([client.connect(clientTransport), server.connect(serverTransport)]);

    for (let i = 0; i < 5; i += 1) {
      const result = (await client.callTool({ name: 'echo', arguments: {} })) as ToolResult;
      expect(result.isError).toBeFalsy();
    }

    const limited = (await client.callTool({ name: 'echo', arguments: {} })) as ToolResult;
    expect(limited.isError).toBe(true);
    expect(limited._meta?.[RATE_LIMITED_META_KEY]).toEqual(
      expect.objectContaining({
        code: 'RATE_LIMITED',
        tool: 'echo',
        limit: 5,
      })
    );
    expect(MCP_TOOL_RATE_LIMIT_BUCKET).toBe('mcp.tools');

    await client.close();
  });
});
