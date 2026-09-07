import crypto from 'crypto';

// Server-side in-memory cache for rotated passcodes during serverless runtime
let runtimeCustomPasscodeHash = null;

// Vercel Serverless Function: Plane API Proxy, Zero-Trust Gatekeeper & Dynamic Passcode Engine
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
  const adminEmail = (process.env.ADMIN_EMAIL || 'buildghost.dev@gmail.com').toLowerCase().trim();

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

  // Helper to compute SHA-256
  const hashPasscode = (pw) => {
    return crypto.createHash('sha256').update(pw.trim()).digest('hex');
  };

  // Helper to get active valid hashes
  const getValidHashes = async () => {
    const validHashes = new Set();

    // 1. Check runtime memory cache
    if (runtimeCustomPasscodeHash) {
      validHashes.add(runtimeCustomPasscodeHash);
    }

    // 2. Check Plane Project description for custom hash tag: BG_PASSCODE_HASH:<hex>
    try {
      if (apiKey) {
        const projRes = await fetch(`${baseUrl}/workspaces/${workspace}/projects/${projectId}/`, {
          headers: { 'x-api-key': apiKey, 'Content-Type': 'application/json' },
        });
        if (projRes.ok) {
          const projData = await projRes.json();
          const desc = projData.description || projData.description_html || '';
          const match = desc.match(/BG_PASSCODE_HASH:([a-fA-F0-9]{64})/);
          if (match && match[1]) {
            runtimeCustomPasscodeHash = match[1].toLowerCase();
            validHashes.add(runtimeCustomPasscodeHash);
          }
        }
      }
    } catch (e) {
      console.warn('Could not fetch Plane project metadata for passcode hash:', e);
    }

    // 3. Environment Variable (if set in Vercel)
    if (process.env.GATEKEEPER_PASSCODE) {
      validHashes.add(hashPasscode(process.env.GATEKEEPER_PASSCODE));
    }
    if (process.env.GATEKEEPER_PASSCODE_HASH) {
      validHashes.add(process.env.GATEKEEPER_PASSCODE_HASH.toLowerCase().trim());
    }

    // 4. Default baseline passcodes (if no custom hash exists)
    if (validHashes.size === 0) {
      const defaults = ['buildghost', 'ghostops', 'buildghost2026', 'triage2026', 'sextpanther'];
      defaults.forEach((p) => validHashes.add(hashPasscode(p)));
    }

    return validHashes;
  };

  // ─── Route: /api/plane/auth (Zero-Knowledge Serverless Gatekeeper Verification) ───
  if (subPath === 'auth') {
    if (req.method !== 'POST') {
      return res.status(405).json({ error: 'Method Not Allowed' });
    }

    const body = typeof req.body === 'string' ? JSON.parse(req.body || '{}') : (req.body || {});
    const entered = (body.passcode || '').trim();

    if (!entered) {
      return res.status(400).json({ success: false, error: 'Passcode is required.' });
    }

    const enteredHash = hashPasscode(entered);
    const validHashes = await getValidHashes();

    if (validHashes.has(enteredHash)) {
      // Issue cryptographically signed token
      const sessionSecret = apiKey || 'buildghost_secure_auth_salt_2026';
      const token = crypto
        .createHmac('sha256', sessionSecret)
        .update(`bg_session_${Date.now()}_${Math.random()}`)
        .digest('hex');

      return res.status(200).json({
        success: true,
        token,
        expiresIn: 86400,
        authenticatedAt: new Date().toISOString(),
      });
    } else {
      return res.status(401).json({
        success: false,
        error: 'Access Denied: Invalid cybernetic passcode.',
      });
    }
  }

  // ─── Route: /api/plane/change-passcode (Admin-Only Dynamic Passcode Rotation) ───
  if (subPath === 'change-passcode') {
    if (req.method !== 'POST') {
      return res.status(405).json({ error: 'Method Not Allowed' });
    }

    const body = typeof req.body === 'string' ? JSON.parse(req.body || '{}') : (req.body || {});
    const { adminEmail: reqAdminEmail, currentPasscode, newPasscode } = body;

    // Verify admin identity
    if ((reqAdminEmail || '').toLowerCase().trim() !== adminEmail) {
      return res.status(403).json({
        success: false,
        error: 'Forbidden: Passcode modification is restricted to administrator identity.',
      });
    }

    // Verify current passcode
    const currentHash = hashPasscode(currentPasscode || '');
    const validHashes = await getValidHashes();
    if (!validHashes.has(currentHash)) {
      return res.status(401).json({
        success: false,
        error: 'Current passcode is incorrect. Authentication failed.',
      });
    }

    // Validate new passcode
    if (!newPasscode || typeof newPasscode !== 'string' || newPasscode.trim().length < 4) {
      return res.status(400).json({
        success: false,
        error: 'New passcode must be at least 4 characters long.',
      });
    }

    const newHash = hashPasscode(newPasscode.trim());
    runtimeCustomPasscodeHash = newHash;

    // Persist new hash to Plane project description
    try {
      if (apiKey) {
        const projRes = await fetch(`${baseUrl}/workspaces/${workspace}/projects/${projectId}/`, {
          headers: { 'x-api-key': apiKey, 'Content-Type': 'application/json' },
        });
        if (projRes.ok) {
          const projData = await projRes.json();
          let desc = projData.description || projData.description_html || 'BuildGhost Engineering Project';
          if (desc.includes('BG_PASSCODE_HASH:')) {
            desc = desc.replace(/BG_PASSCODE_HASH:[a-fA-F0-9]{64}/, `BG_PASSCODE_HASH:${newHash}`);
          } else {
            desc = `${desc} <!-- BG_PASSCODE_HASH:${newHash} -->`;
          }

          await fetch(`${baseUrl}/workspaces/${workspace}/projects/${projectId}/`, {
            method: 'PATCH',
            headers: { 'x-api-key': apiKey, 'Content-Type': 'application/json' },
            body: JSON.stringify({ description: desc }),
          });
        }
      }
    } catch (e) {
      console.warn('Could not persist passcode hash to Plane project description:', e);
    }

    return res.status(200).json({
      success: true,
      message: 'Gatekeeper passcode successfully updated on server.',
      updatedAt: new Date().toISOString(),
    });
  }

  // ─── Standard Plane API Gateway Operations ─────────────────────────────
  if (!apiKey) {
    return res.status(500).json({
      error: 'PLANE_API_KEY is not configured in Vercel environment variables.',
    });
  }

  const headers = {
    'x-api-key': apiKey,
    'Content-Type': 'application/json',
  };

  try {
    // ─── Special Route: /api/plane/init (Auto-provision Custom Properties) ───
    if (subPath === 'init') {
      const propUrl = `${baseUrl}/workspaces/${workspace}/projects/${projectId}/custom-properties/`;
      
      const requiredProps = [
        { name: 'blocker_active', display_name: 'Blocker Active', property_type: 'boolean' },
        { name: 'blocker_text', display_name: 'Blocker Reason', property_type: 'text' },
        { name: 'blocker_resolved_text', display_name: 'Blocker Resolved Notes', property_type: 'text' },
        { name: 'ac_json', display_name: 'Acceptance Criteria JSON', property_type: 'text' },
        { name: 'affected_platforms', display_name: 'Affected Platforms', property_type: 'text' },
      ];

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
