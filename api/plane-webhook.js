// Vercel Serverless Function: Plane Webhook Ingestion & Resend Email Dispatch
export default async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method Not Allowed' });
  }

  const resendApiKey = process.env.RESEND_API_KEY;
  const resendFrom = process.env.RESEND_FROM || 'noreply@buildghost.site';
  const adminEmail = process.env.ADMIN_EMAIL || 'buildghost.dev@gmail.com';
  const isEmailSafeMode = process.env.EMAIL_SAFE_MODE !== 'false';

  const payload = req.body || {};
  const event = payload.event || payload.action || 'issue.updated';
  const data = payload.data || payload;

  console.log(`[Plane Webhook] Ingested event: ${event} | EMAIL_SAFE_MODE: ${isEmailSafeMode}`, { id: data.id });

  // Helper: send email via Resend API
  async function sendEmail({ to, subject, html }) {
    const rawRecipients = Array.from(new Set((Array.isArray(to) ? to : [to]).filter(Boolean)));
    if (rawRecipients.length === 0) return;

    let targetRecipients = rawRecipients;

    // ─── EMAIL SAFE MODE (TEST MODE: ONLY ALLOW process.env.ADMIN_EMAIL) ───
    if (isEmailSafeMode) {
      const blockedRecipients = rawRecipients.filter(
        (addr) => !adminEmail || addr.toLowerCase() !== adminEmail.toLowerCase()
      );

      if (blockedRecipients.length > 0) {
        console.log(
          `[EMAIL_SAFE_MODE=true] BLOCKED recipients: [${blockedRecipients.join(', ')}]. ` +
          `Would-be Subject: "${subject}". Logging dispatch instead of sending.`
        );
      }

      // Strictly allow ONLY adminEmail
      targetRecipients = adminEmail ? [adminEmail] : [];

      if (targetRecipients.length === 0) {
        console.log(`[EMAIL_SAFE_MODE=true] No email sent because ADMIN_EMAIL is not configured.`);
        return;
      }
    }

    if (!resendApiKey) {
      console.warn('[Resend] Skipped delivery: RESEND_API_KEY is not configured.');
      return;
    }

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
            ? `<div style="background: #2a1f05; border: 1px solid #f5c778; color: #f5c778; padding: 8px 12px; font-size: 11px; margin-bottom: 16px; font-family: monospace; border-radius: 4px;">⚠️ <strong>EMAIL SAFE MODE ACTIVE</strong> — Test dispatch delivered ONLY to Admin (${adminEmail}). External stakeholders are muted.</div>` + html
            : html,
        }),
      });

      if (!emailRes.ok) {
        const errText = await emailRes.text();
        console.error('[Resend Error]', errText);
      } else {
        console.log(`[Resend Success] Email delivered to: ${targetRecipients.join(', ')}`);
      }
    } catch (err) {
      console.error('[Resend Exception]', err);
    }
  }

  try {
    const issueTitle = data.name || data.issue_name || data.title || 'Live Triage Ticket';
    const issueId = data.sequence_id ? `SP-${data.sequence_id}` : (data.id ? `TICKET-${data.id.slice(0, 6)}` : 'TICKET');
    const creatorEmail = data.creator_email || data.created_by?.email || adminEmail;
    const watchers = Array.isArray(data.watchers_emails) ? data.watchers_emails : [];

    // Base styled email layout
    const renderHtml = (headline, bodyContent, statusColor = '#65e7ec') => `
      <div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #060c0b; color: #e7ece5; padding: 32px 24px; border-radius: 8px; max-width: 600px; margin: 0 auto; border: 1px solid rgba(255,255,255,0.12);">
        <div style="border-bottom: 1px solid rgba(255,255,255,0.08); padding-bottom: 16px; margin-bottom: 24px; display: flex; justify-content: space-between; align-items: center;">
          <span style="font-family: monospace; font-size: 11px; letter-spacing: 0.16em; color: ${statusColor}; text-transform: uppercase; font-weight: 800;">BUILDGHOST // TRIAGE-DESK</span>
          <span style="font-family: monospace; font-size: 11px; color: #9eadab;">${issueId}</span>
        </div>
        <h2 style="font-size: 20px; font-weight: 700; color: #ffffff; margin: 0 0 12px 0;">${headline}</h2>
        <div style="font-size: 14px; line-height: 1.6; color: #ced8d1; margin-bottom: 24px;">
          ${bodyContent}
        </div>
        <div style="border-top: 1px solid rgba(255,255,255,0.08); padding-top: 16px; font-size: 12px; color: #9eadab; font-family: monospace;">
          <span>Automated dispatch from <a href="https://buildghost.site/triage-desk" style="color: #65e7ec; text-decoration: none;">buildghost.site/triage-desk</a></span>
        </div>
      </div>
    `;

    // Normalize event name (support Plane V1 and V2)
    const normalizedEvent = (event || '').toLowerCase().replace(/-/g, '_');

    // ─── Trigger 1: Issue / Work Item Created ──────────────────────────────
    if (['issue.created', 'work_item.created', 'workitem.created', 'work_item_created'].includes(normalizedEvent)) {
      await sendEmail({
        to: [creatorEmail, adminEmail],
        subject: `[${issueId}] Ticket Created: ${issueTitle}`,
        html: renderHtml(
          `New Triage Ticket Registered: ${issueTitle}`,
          `<p>A new engineering triage ticket has been submitted to the queue.</p>
           <p style="background: rgba(255,255,255,0.04); padding: 12px; border-left: 3px solid #65e7ec; font-family: monospace;">${issueTitle}</p>`,
          '#65e7ec'
        ),
      });
    }

    // ─── Trigger 2 & 5: Watcher / Subscriber Added ─────────────────────────
    else if ([
      'issue.subscriber.created',
      'issue.watcher_added',
      'work_item.subscriber.created',
      'work_item_subscriber_created',
      'work_item.watcher_added',
      'subscriber.created'
    ].includes(normalizedEvent)) {
      const addedWatcher = data.subscriber_email || data.user_email || creatorEmail;
      await sendEmail({
        to: [addedWatcher, creatorEmail],
        subject: `[${issueId}] Added as Watcher: ${issueTitle}`,
        html: renderHtml(
          `You are now watching ${issueId}`,
          `<p>You will receive automated dispatches when comments are posted, blockers are logged, or acceptance criteria are completed.</p>`,
          '#00ff9d'
        ),
      });
    }

    // ─── Trigger 3: Comment Posted ────────────────────────────────────────
    else if ([
      'comment.created',
      'comment_created',
      'work_item_comment.created',
      'work_item_comment_created',
      'workitem_comment.created'
    ].includes(normalizedEvent)) {
      const commentText = data.comment_html || data.comment_json || data.comment || 'New comment added.';
      const commenterEmail = data.actor?.email || data.created_by?.email;
      const allRecipients = [commenterEmail, creatorEmail, adminEmail, ...watchers];

      await sendEmail({
        to: allRecipients,
        subject: `[${issueId}] New Comment on ${issueTitle}`,
        html: renderHtml(
          `New Comment on ${issueId}`,
          `<div style="background: rgba(255,255,255,0.03); padding: 14px; border-radius: 4px; border-left: 3px solid #ff2d6b; color: #fff;">${commentText}</div>`,
          '#ff2d6b'
        ),
      });
    }

    // ─── Trigger 4: All AC Checked & Archived ──────────────────────────────
    else if (
      ['issue.archived', 'work_item.archived', 'workitem.archived'].includes(normalizedEvent) ||
      (['issue.updated', 'work_item.updated', 'workitem.updated'].includes(normalizedEvent) && data.state === 'ARCHIVED')
    ) {
      await sendEmail({
        to: [creatorEmail, adminEmail, ...watchers],
        subject: `[${issueId}] ARCHIVED: All Acceptance Criteria Satisfied`,
        html: renderHtml(
          `Ticket ${issueId} Archived & Verified`,
          `<p>All acceptance criteria and remediation guardrails have been validated and the ticket has been moved to the historical archive.</p>`,
          '#00ff9d'
        ),
      });
    }

    // ─── Trigger 6 & 7: Blocker Added or Resolved ─────────────────────────
    else if (
      normalizedEvent === 'blocker.added' ||
      (['issue.updated', 'work_item.updated', 'workitem.updated'].includes(normalizedEvent) && data.blocker_active === true)
    ) {
      await sendEmail({
        to: [creatorEmail, adminEmail, ...watchers],
        subject: `[${issueId}] BLOCKER DECLARED: ${issueTitle}`,
        html: renderHtml(
          `Active Blocker Declared on ${issueId}`,
          `<p style="color: #ff2d6b; font-weight: bold;">BLOCKER REASON:</p>
           <p style="background: rgba(255,45,107,0.08); border: 1px solid rgba(255,45,107,0.3); padding: 12px; color: #fff;">${data.blocker_text || 'Active regression blockage reported.'}</p>`,
          '#ff2d6b'
        ),
      });
    } else if (
      normalizedEvent === 'blocker.resolved' ||
      (['issue.updated', 'work_item.updated', 'workitem.updated'].includes(normalizedEvent) && data.blocker_active === false && data.blocker_resolved_text)
    ) {
      await sendEmail({
        to: [creatorEmail, adminEmail, ...watchers],
        subject: `[${issueId}] Blocker Resolved: ${issueTitle}`,
        html: renderHtml(
          `Blocker Resolved on ${issueId}`,
          `<p style="color: #00ff9d; font-weight: bold;">RESOLUTION NOTES:</p>
           <p style="background: rgba(0,255,157,0.08); border: 1px solid rgba(0,255,157,0.3); padding: 12px; color: #fff;">${data.blocker_resolved_text}</p>`,
          '#00ff9d'
        ),
      });
    }

    return res.status(200).json({ status: 'webhook_processed', event });
  } catch (error) {
    console.error('Plane webhook processing error:', error);
    return res.status(500).json({ error: 'Webhook processing error', details: error.message });
  }
}
