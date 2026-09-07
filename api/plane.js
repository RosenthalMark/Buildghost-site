// Vercel Serverless Function: Plane API Proxy & Auto-Provisioner
export default async function handler(req, res) {
  // CORS & Security headers
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PATCH, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, x-api-key');

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  const apiKey = process.env.PLANE_API_KEY;
  const workspace = process.env.PLANE_WORKSPACE || 'buildghost';
  const projectId = process.env.PLANE_PROJECT_ID || '68b3bc6d-0cc1-4b33-8a62-a2be11cb724f';
  const baseUrl = (process.env.PLANE_API_URL || 'https://app.plane.so/api/v1').replace(/\/+$/, '');

  if (!apiKey) {
    return res.status(500).json({
      error: 'PLANE_API_KEY is not configured in Vercel environment variables.',
    });
  }

  // Extract path from query or URL
  const { path } = req.query || {};
  let subPath = '';
  if (Array.isArray(path)) {
    subPath = path.join('/');
  } else if (typeof path === 'string' && path.trim()) {
    subPath = path;
  } else {
    const urlObj = new URL(req.url || '', 'http://localhost');
    subPath = urlObj.pathname.replace(/^\/api\/plane\/?/, '');
  }
  subPath = (subPath || '').replace(/^\/+/, '');

  const headers = {
    'x-api-key': apiKey,
    'Content-Type': 'application/json',
  };

  try {
    // ─── Special Route: /api/plane/init (Auto-provision Custom Properties) ───
    if (subPath === 'init') {
      const propUrl = `${baseUrl}/workspaces/${workspace}/projects/${projectId}/custom-properties/`;
      
      // Desired custom properties schema
      const requiredProps = [
        { name: 'blocker_active', display_name: 'Blocker Active', property_type: 'boolean' },
        { name: 'blocker_text', display_name: 'Blocker Reason', property_type: 'text' },
        { name: 'blocker_resolved_text', display_name: 'Blocker Resolved Notes', property_type: 'text' },
        { name: 'ac_json', display_name: 'Acceptance Criteria JSON', property_type: 'text' },
        { name: 'affected_platforms', display_name: 'Affected Platforms', property_type: 'text' },
      ];

      // Fetch existing properties
      const existingRes = await fetch(propUrl, { headers });
      const existingData = existingRes.ok ? await existingRes.json() : [];
      const existingNames = new Set(
        Array.isArray(existingData) ? existingData.map((p) => p.name) : (existingData.results || []).map((p) => p.name)
      );

      const created = [];
      for (const prop of requiredProps) {
        if (!existingNames.has(prop.name)) {
          try {
            const createRes = await fetch(propUrl, {
              method: 'POST',
              headers,
              body: JSON.stringify(prop),
            });
            if (createRes.ok) {
              created.push(prop.name);
            }
          } catch (e) {
            console.warn(`Failed to create property ${prop.name}`, e);
          }
        }
      }

      return res.status(200).json({
        status: 'initialized',
        workspace,
        projectId,
        existingProperties: Array.from(existingNames),
        createdProperties: created,
      });
    }

    // ─── Special Route: /api/plane/seed (Seed ONLY SP-101) ─────────────────
    if (subPath === 'seed') {
      const issuesUrl = `${baseUrl}/workspaces/${workspace}/projects/${projectId}/issues/`;
      
      const seedTicket = {
        name: 'PLACEHOLDER: ISSUE 1 — Intermittent Media Unlock Timeout Under Peak Concurrency',
        description_html: '<p>High-latency WebSocket handshake during peak traffic causes creator media unlock state to stall before payment receipt acknowledgement.</p>',
        priority: 'urgent', // maps to P0
        extra_data: {
          affected_platforms: 'Web, Mobile Web, API Gateway, iOS Safari',
          blocker_active: false,
          blocker_text: '',
          blocker_resolved_text: '',
          ac_json: JSON.stringify([
            'Deterministic idempotent transaction tokens attached to unlock payload.',
            'Client-side optimistic unlock state verified with automated rollback on failed webhook.',
            'Synthetic Playwright test simulates 100 concurrent unlocks with zero stalled UI states.',
          ]),
          steps: [
            'Initiate concurrent unlock requests (50+ simultaneous fan users) on paywalled video vault.',
            "Observe client state stalls on 'Processing Unlock' while billing webhook resolves asynchronously.",
            'User refreshes page, triggering duplicate transaction prompt.',
          ],
          remediation: 'Added Redis-backed mutex locks on unlock transactions and deployed automated K6 load test gate in CI/CD pipeline to reject merges that breach 120ms latency ceiling.',
          creator_name: 'DevOps Engineer',
          creator_email: process.env.ADMIN_EMAIL || 'devops@buildghost.site',
          watchers: [],
        },
      };

      const seedRes = await fetch(issuesUrl, {
        method: 'POST',
        headers,
        body: JSON.stringify(seedTicket),
      });

      const seedData = seedRes.ok ? await seedRes.json() : await seedRes.text();
      return res.status(seedRes.status).json({
        status: seedRes.ok ? 'seeded_sp_101' : 'seed_error',
        result: seedData,
      });
    }

    // ─── Special Route: /api/plane/reset (Delete ALL Issues in Project) ────
    if (subPath === 'reset') {
      const issuesUrl = `${baseUrl}/workspaces/${workspace}/projects/${projectId}/issues/`;
      const listRes = await fetch(issuesUrl, { headers });
      const listData = listRes.ok ? await listRes.json() : [];
      const issues = Array.isArray(listData) ? listData : (listData.results || []);

      const deletedIds = [];
      const errors = [];

      for (const issue of issues) {
        if (!issue.id) continue;
        try {
          const deleteUrl = `${baseUrl}/workspaces/${workspace}/projects/${projectId}/issues/${issue.id}/`;
          const delRes = await fetch(deleteUrl, {
            method: 'DELETE',
            headers,
          });
          if (delRes.ok || delRes.status === 204 || delRes.status === 200) {
            deletedIds.push(issue.id);
          } else {
            errors.push({ id: issue.id, status: delRes.status });
          }
        } catch (err) {
          errors.push({ id: issue.id, error: err.message });
        }
      }

      return res.status(200).json({
        status: 'reset_completed',
        workspace,
        projectId,
        totalFound: issues.length,
        deletedCount: deletedIds.length,
        deletedIds,
        errors: errors.length > 0 ? errors : undefined,
      });
    }

    // ─── Standard Proxy Target ─────────────────────────────────────────────
    // Examples:
    // issues -> /workspaces/:workspace/projects/:projectId/issues/
    // issues/ID -> /workspaces/:workspace/projects/:projectId/issues/ID/
    // issues/ID/comments -> /workspaces/:workspace/projects/:projectId/issues/ID/comments/
    let targetUrl = `${baseUrl}/workspaces/${workspace}/projects/${projectId}/${subPath}`;
    if (!targetUrl.endsWith('/')) {
      targetUrl += '/';
    }

    const fetchOptions = {
      method: req.method,
      headers,
    };

    if (['POST', 'PATCH', 'PUT'].includes(req.method) && req.body) {
      fetchOptions.body = typeof req.body === 'string' ? req.body : JSON.stringify(req.body);
    }

    const apiRes = await fetch(targetUrl, fetchOptions);
    const contentType = apiRes.headers.get('content-type') || '';

    if (contentType.includes('application/json')) {
      const data = await apiRes.json();
      return res.status(apiRes.status).json(data);
    } else {
      const text = await apiRes.text();
      return res.status(apiRes.status).send(text);
    }
  } catch (error) {
    console.error('Plane proxy error:', error);
    return res.status(500).json({
      error: 'Plane API Proxy Internal Error',
      details: error.message,
    });
  }
}
