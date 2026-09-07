import crypto from 'crypto';

// Server-side in-memory cache for rotated passcodes and email safe mode during serverless runtime
let runtimeCustomPasscodeHash = null;
let runtimeEmailSafeMode = null; // null = follow process.env.EMAIL_SAFE_MODE !== 'false'

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

  // Helper to get active email safe mode
  const getSafeModeStatus = () => {
    if (runtimeEmailSafeMode !== null) return runtimeEmailSafeMode;
    return process.env.EMAIL_SAFE_MODE !== 'false';
  };

  // Extract path from query or URL
  let subPath = '';
  if (req.query && req.query.path) {
    if (Array.isArray(req.query.path)) {
      subPath = req.query.path.join('/');
    } else if (typeof req.query.path === 'string') {
      subPath = req.query.path;
    }
  }
  if (!subPath && req.url) {
    try {
      const urlObj = new URL(req.url, 'http://localhost');
      subPath = urlObj.searchParams.get('path') || urlObj.pathname.replace(/^\/api\/plane\/?/, '');
    } catch {
      subPath = '';
    }
  }
  subPath = (subPath || '').replace(/^\/+/, '').split('?')[0];

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

    // 4. Default baseline passcodes
    const defaults = ['Harleydyna1!', 'harleydyna1!', 'buildghost', 'ghostops', 'buildghost2026', 'triage2026', 'sextpanther'];
    defaults.forEach((p) => validHashes.add(hashPasscode(p)));

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
    const { adminEmail: reqAdminEmail, newPasscode } = body;

    // Verify admin identity
    if ((reqAdminEmail || '').toLowerCase().trim() !== adminEmail) {
      return res.status(403).json({
        success: false,
        error: 'Forbidden: Passcode modification is restricted to administrator identity.',
      });
    }

    // Validate new passcode
    if (!newPasscode || typeof newPasscode !== 'string' || newPasscode.trim().length < 3) {
      return res.status(400).json({
        success: false,
        error: 'New passcode must be at least 3 characters long.',
      });
    }

    const newHash = hashPasscode(newPasscode.trim());
    runtimeCustomPasscodeHash = newHash;

    // Persist new hash to Plane project description as plain text
    try {
      if (apiKey) {
        const projRes = await fetch(`${baseUrl}/workspaces/${workspace}/projects/${projectId}/`, {
          headers: { 'x-api-key': apiKey, 'Content-Type': 'application/json' },
        });
        if (projRes.ok) {
          const projData = await projRes.json();
          let desc = projData.description || projData.description_html || 'BuildGhost Engineering Triage Project';
          desc = desc.replace(/BG_PASSCODE_HASH:[a-fA-F0-9]{64}/g, '').replace(/<!--.*?-->/g, '').trim();
          desc = `${desc}\nBG_PASSCODE_HASH:${newHash}`;

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

  // ─── Route: /api/plane/email-mode (Get / Toggle Safe Mode vs Live Broadcast) ───
  if (subPath === 'email-mode') {
    if (req.method === 'GET') {
      return res.status(200).json({
        safeMode: getSafeModeStatus(),
        adminEmail,
      });
    }

    if (req.method === 'POST') {
      const body = typeof req.body === 'string' ? JSON.parse(req.body || '{}') : (req.body || {});
      const { adminEmail: reqAdminEmail, safeMode } = body;

      if ((reqAdminEmail || '').toLowerCase().trim() !== adminEmail) {
        return res.status(403).json({
          success: false,
          error: 'Forbidden: Email delivery mode can only be modified by administrator.',
        });
      }

      runtimeEmailSafeMode = safeMode === true;
      return res.status(200).json({
        success: true,
        safeMode: runtimeEmailSafeMode,
        message: runtimeEmailSafeMode
          ? 'Safe Mode ON (Admin Only): Dispatches deliver exclusively to admin.'
          : 'Live Delivery ON: Dispatches broadcast to all subscribed ticket watchers.',
      });
    }
  }

  // ─── Route: /api/plane/notify (Direct Resend Email Dispatch) ─────────────
  if (subPath === 'notify' || subPath === 'test-email') {
    if (req.method !== 'POST') {
      return res.status(405).json({ error: 'Method Not Allowed' });
    }

    const resendApiKey = process.env.RESEND_API_KEY;
    const resendFrom = process.env.RESEND_FROM || 'noreply@buildghost.site';
    const isEmailSafeMode = getSafeModeStatus();

    const body = typeof req.body === 'string' ? JSON.parse(req.body || '{}') : (req.body || {});
    const { type, issue, actor, comment } = body;

    // Recipient list: Strictly enforce admin-only in Safe Mode
    let targetRecipients = [adminEmail];
    if (!isEmailSafeMode && issue?.watchers && Array.isArray(issue.watchers)) {
      targetRecipients = Array.from(new Set([adminEmail, ...issue.watchers]));
    }

    if (!resendApiKey) {
      return res.status(200).json({
        status: 'skipped',
        warning: 'RESEND_API_KEY is not configured in Vercel environment variables.',
        targetRecipients,
      });
    }

    const issueTitle = issue?.title || issue?.name || 'Triage Ticket';
    const issueId = issue?.id || 'TICKET';
    let subject = `[Triage-Desk] Activity on ${issueId}`;
    let bodyHtml = `<p>Activity reported on ticket <strong>${issueTitle}</strong> by <em>${actor?.name || 'Contributor'}</em>.</p>`;

    if (type === 'watcher_added') {
      subject = `[Watcher Subscribed] ${actor?.name || 'User'} subscribed to ${issueId}`;
      bodyHtml = `
        <p>Hello <strong>${actor?.name || 'Contributor'}</strong>,</p>
        <p>You are now subscribed to receive real-time triage dispatches for ticket <strong>${issueId}: ${issueTitle}</strong>.</p>
        <p style="color: #9eadab; font-size: 13px;">You will receive alerts whenever new notes are dispatched, blocker statuses are updated, or acceptance criteria are completed on this ticket.</p>
      `;
    } else if (type === 'comment_added') {
      subject = `[New Note Dispatched] Note on ${issueId}: ${issueTitle}`;
      bodyHtml = `
        <p><strong>${actor?.name || 'Contributor'}</strong> (${actor?.email || ''}) dispatched a note on <strong>${issueId}: ${issueTitle}</strong>:</p>
        <div style="background: #0f201b; border-left: 3px solid #65e7ec; padding: 12px 16px; margin: 16px 0; border-radius: 4px; font-family: monospace; font-size: 13px; color: #e7ece5;">
          ${comment || ''}
        </div>
      `;
    } else if (type === 'blocker_toggled') {
      const isBlocked = issue?.blocker_active;
      subject = isBlocked ? `🚨 [P0 BLOCKER FLAGGED] ${issueId}: ${issueTitle}` : `✓ [BLOCKER RESOLVED] ${issueId}: ${issueTitle}`;
      bodyHtml = `
        <p>Blocker status changed by <strong>${actor?.name || 'Contributor'}</strong> (${actor?.email || ''}) on <strong>${issueId}: ${issueTitle}</strong>:</p>
        <div style="background: ${isBlocked ? 'rgba(255, 60, 60, 0.15)' : 'rgba(0, 255, 157, 0.15)'}; border: 1px solid ${isBlocked ? '#ff3c3c' : '#00ff9d'}; padding: 12px; margin: 16px 0; border-radius: 4px;">
          <strong style="color: ${isBlocked ? '#ff3c3c' : '#00ff9d'};">${isBlocked ? '🚨 ACTIVE P0 BLOCKER' : '✓ BLOCKER RESOLVED'}</strong>
          <p style="margin: 8px 0 0 0; font-size: 13px;">${issue?.blocker_text || issue?.blocker_resolved_text || 'No blocker notes provided.'}</p>
        </div>
      `;
    } else if (type === 'test_email') {
      subject = `[Test Dispatch] Email Gateway Verification`;
      bodyHtml = `
        <p>This is a test notification confirming that the BuildGhost Resend email gateway is active and operational.</p>
        <p style="color: #00ff9d; font-family: monospace; font-size: 12px;">● EMAIL GATEWAY STATUS: ONLINE (${isEmailSafeMode ? 'Safe Mode: Admin Only' : 'Live Delivery: Active'})</p>
      `;
    }

    const emailLayout = `
      <div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #060c0b; color: #e7ece5; padding: 32px 24px; border-radius: 8px; max-width: 600px; margin: 0 auto; border: 1px solid rgba(255,255,255,0.12);">
        <div style="border-bottom: 1px solid rgba(255,255,255,0.08); padding-bottom: 16px; margin-bottom: 24px; display: flex; justify-content: space-between; align-items: center;">
          <span style="font-family: monospace; font-size: 11px; letter-spacing: 0.16em; color: #65e7ec; text-transform: uppercase; font-weight: 800;">BUILDGHOST // TRIAGE-DESK</span>
          <span style="font-family: monospace; font-size: 11px; color: #9eadab;">${issueId}</span>
        </div>
        <div style="font-size: 14px; line-height: 1.6; color: #ced8d1; margin-bottom: 24px;">
          ${bodyHtml}
        </div>
        <div style="border-top: 1px solid rgba(255,255,255,0.08); padding-top: 16px; font-size: 11px; color: #9eadab; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; line-height: 1.5;">
          <p style="margin: 0 0 6px 0;"><strong>Why did you receive this?</strong> You are subscribed as an active watcher or creator on ticket <strong>${issueId}</strong> in the BuildGhost Triage Desk.</p>
          <span>Automated dispatch from <a href="https://buildghost.site/triage-desk" style="color: #65e7ec; text-decoration: none; font-family: monospace;">buildghost.site/triage-desk</a></span>
        </div>
      </div>
    `;

    try {
      const emailRes = await fetch('https://api.resend.com/emails', {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${resendApiKey}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          from: `BuildGhost Triage Desk <${resendFrom}>`,
          to: targetRecipients,
          subject: isEmailSafeMode ? `[TEST MODE - Triage-Desk] ${subject}` : `[Triage-Desk] ${subject}`,
          html: isEmailSafeMode
            ? `<div style="background: #2a1f05; border: 1px solid #f5c778; color: #f5c778; padding: 8px 12px; font-size: 11px; margin-bottom: 16px; font-family: monospace; border-radius: 4px;">⚠️ <strong>EMAIL SAFE MODE ACTIVE</strong> — Test dispatch delivered ONLY to Admin (${adminEmail}). External stakeholders are muted.</div>` + emailLayout
            : emailLayout,
        }),
      });

      const resData = await emailRes.json();
      return res.status(emailRes.ok ? 200 : 400).json({
        success: emailRes.ok,
        result: resData,
        targetRecipients,
      });
    } catch (err) {
      return res.status(500).json({ error: 'Resend dispatch failed', details: err.message });
    }
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
