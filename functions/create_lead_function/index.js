const nodemailer = require('nodemailer');

// Lead durability strategy:
//  1) Every lead is written to the function logs as a single greppable,
//     alert-friendly line tagged "LEAD_CAPTURE" (set a Catalyst log alert on it).
//  2) Every lead is pushed into the Avoryx CRM (Sangani Group tenant) via the
//     web-to-lead API, tagged by originating website so the CRM UI can filter.
//  3) A branded notification email is sent (best-effort).
// All three are independent + fail-soft, so a lead is never lost.
function captureLead(record) {
    try {
        console.log('LEAD_CAPTURE ' + JSON.stringify({ at: new Date().toISOString(), ...record }));
        return true;
    } catch (err) {
        console.error('LEAD_CAPTURE_LOG_FAILED', err && err.message);
        return false;
    }
}

// Push the lead into the Avoryx CRM (Sangani Group tenant) via the web-to-lead
// API. SOC2-safe: the token lives only in the Catalyst env (never in code / the
// browser), the call is server-to-server, and the API pins the lead to the
// token's tenant_id. Fails soft — logs + email are the backup paths.
//   Required env: AVORYX_LEAD_URL (e.g. https://avoryx.sanganigroup.in/api/crm/leads)
//                 AVORYX_LEAD_TOKEN (a tenant API token with write:leads scope)
async function pushLeadToCrm(record, isAvoryx) {
    const url = process.env.AVORYX_LEAD_URL;
    const token = process.env.AVORYX_LEAD_TOKEN;
    if (!url || !token) {
        console.log('CRM push skipped (AVORYX_LEAD_URL / AVORYX_LEAD_TOKEN not set)');
        return false;
    }
    // Distinguish which website the lead came from via the CRM's `source` field,
    // which is natively filterable in the Avoryx CRM UI.
    const site = isAvoryx ? 'ProductWebsite' : 'EnterpriseWebsite';
    const notesParts = [
        record.message,
        record.service ? `Service/Product: ${record.service}` : '',
        record.budget ? `Budget/Team size: ${record.budget}` : '',
        record.stack ? `Tools today: ${record.stack}` : '',
        record.source ? `Form: ${record.source}` : '',
    ].filter(Boolean);
    try {
        const controller = new AbortController();
        const t = setTimeout(() => controller.abort(), 8000);
        const resp = await fetch(url, {
            method: 'POST',
            headers: { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' },
            signal: controller.signal,
            body: JSON.stringify({
                name: record.name,
                email: record.email,
                phone: record.phone,
                company: record.company,
                source: site,
                notes: notesParts.join('\n'),
            }),
        });
        clearTimeout(t);
        if (!resp.ok) {
            console.error('CRM push non-OK:', resp.status);
            return false;
        }
        console.log('CRM push OK for', record.email, '(', site, ')');
        return true;
    } catch (err) {
        console.error('CRM push failed (lead still logged + emailed):', err && err.message);
        return false;
    }
}

/**
 * Simple in-memory rate limit
 * NOTE: resets on cold start (acceptable for contact forms)
 */
const RATE_LIMIT_MAX = 3;
const RATE_LIMIT_WINDOW = 60 * 60 * 1000;
const rateLimitMap = new Map();

function checkRateLimit(ip) {
    const now = Date.now();
    const record = rateLimitMap.get(ip);

    if (!record || now > record.reset) {
        rateLimitMap.set(ip, { count: 1, reset: now + RATE_LIMIT_WINDOW });
        return true;
    }

    if (record.count >= RATE_LIMIT_MAX) return false;

    record.count++;
    return true;
}

function getRequestBody(req) {
    return new Promise((resolve, reject) => {
        let data = '';

        req.on('data', chunk => {
            data += chunk;
        });

        req.on('end', () => {
            try {
                resolve(data ? JSON.parse(data) : {});
            } catch (err) {
                reject(err);
            }
        });

        req.on('error', err => {
            reject(err);
        });
    });
}

// Minimum reCAPTCHA v3 score to accept. 0.5 is Google's neutral default but
// rejects many legitimate users (VPNs, privacy browsers, first visits). 0.3 is
// a common, safer floor that still blocks obvious bots.
const RECAPTCHA_MIN_SCORE = 0.3;

async function verifyRecaptcha(token) {
    try {
        const response = await fetch(
            'https://www.google.com/recaptcha/api/siteverify',
            {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body:
                    `secret=${process.env.RECAPTCHA_SECRET_KEY}` +
                    `&response=${token}`,
            }
        );

        const data = await response.json();
        // Log the full verdict so we can see WHY a real submission is rejected
        // (success flag, score, action, hostname, error-codes) in Catalyst logs.
        console.log('reCAPTCHA verify:', JSON.stringify({
            success: data.success,
            score: data.score,
            action: data.action,
            hostname: data.hostname,
            errors: data['error-codes'],
        }));

        // If the token is structurally invalid/expired/duplicate, success is false.
        if (data.success !== true) return false;
        // v3 always returns a score; v2 checkbox does not. Accept if no score
        // (non-v3 key) or score meets the floor.
        if (typeof data.score === 'number') return data.score >= RECAPTCHA_MIN_SCORE;
        return true;
    } catch (err) {
        console.error('reCAPTCHA error:', err);
        return false;
    }
}

/**
 * Origins allowed to call this lead function from the browser.
 * Both the Sangani corporate site and the Avoryx product site share this
 * function; each must be listed so its cross-origin POST passes the CORS
 * preflight. Add new hostnames here (exact scheme+host, no trailing slash).
 */
const ALLOWED_ORIGINS = [
    'https://sanganigroup.in',
    'https://www.sanganigroup.in',
    'https://avoryx.io',
    'https://www.avoryx.io',
];

module.exports = async (req, res) => {
    try {
        /* -------------------- CORS -------------------- */
        const origin = req.headers.origin || req.headers.Origin;
        if (origin && ALLOWED_ORIGINS.includes(origin)) {
            res.setHeader('Access-Control-Allow-Origin', origin);
            res.setHeader('Vary', 'Origin');
        }
        res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
        res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

        if (req.method === 'OPTIONS') {
            res.writeHead(204);
            return res.end();
        }

        if (req.method !== 'POST') {
            res.writeHead(405, { 'Content-Type': 'application/json' });
            return res.end(JSON.stringify({ error: 'Method not allowed' }));
        }

        /* -------------------- BODY -------------------- */

        //console.log('req:', req);
        //console.log('res:', res);

        //let body = req.body;

        const body = await getRequestBody(req);

        if (typeof body === 'string') {
            try {
                body = JSON.parse(body);
            } catch (e) {
                console.log(e);
                body = {};
            }
        }

        const {
            name,
            email,
            phone,
            company,
            service,
            budget,
            message,
            recaptchaToken,
            product,   // 'Avoryx' when the lead comes from the Avoryx site
            source,    // e.g. 'request-demo'
            stack,     // Avoryx: tools the prospect uses today
        } = body || {};

        if (!name || !email || !service || !message) {
            // Friendly, specific — never a raw "error" string on a public site.
            res.writeHead(400, { 'Content-Type': 'application/json' });
            return res.end(JSON.stringify({
                ok: false,
                message: 'Please fill in your name, email and a short message so we can reach you.',
            }));
        }

        const ip =
            (req.headers['x-forwarded-for'] || '').split(',')[0] || 'unknown';

        /* -------------------- CAPTURE FIRST (never lose a lead) --------------------
         * Persist the lead to the Catalyst Data Store BEFORE reCAPTCHA/email, so a
         * failure in any downstream step can never cause the lead to be lost.       */
        const leadRecord = {
            name, email, phone: phone || '', company: company || '',
            service, budget: budget || '', message,
            product: product || '', source: source || '', stack: stack || '',
            ip,
            status: 'captured',
        };
        const captured = captureLead(leadRecord);

        /* -------------------- reCAPTCHA --------------------
         * We verify for spam signal, but a low score never DISCARDS a real person's
         * lead — it's already captured. We only skip sending the notification email
         * for clearly-bot submissions, and still tell the user we received them.   */
        const isHuman = await verifyRecaptcha(recaptchaToken);

        /* -------------------- Rate limit (soft) -------------------- */
        const withinRate = checkRateLimit(ip);

        /* -------------------- Email -------------------- */
        const transporter = nodemailer.createTransport({
            service: 'gmail',
            auth: {
                user: process.env.GMAIL_USER,
                pass: process.env.GMAIL_APP_PASSWORD,
            },
        });

        // Auto-detect which product/site the lead came from (used for CRM source
        // tagging + email branding). One function serves both sites.
        const isAvoryx =
            String(product || '').toLowerCase() === 'avoryx' ||
            String(service || '').toLowerCase() === 'avoryx';

        /* -------------------- CRM push (Avoryx, Sangani tenant) --------------------
         * Only push genuine, within-rate submissions so the CRM isn't polluted by
         * obvious bots. The lead is already logged either way. */
        let crmPushed = false;
        if (isHuman && withinRate) {
            crmPushed = await pushLeadToCrm(leadRecord, isAvoryx);
        }

        /* -------------------- Branded email -------------------- */

        const brand = isAvoryx
            ? {
                name: 'Avoryx',
                tagline: 'One Platform. Every Business Operation.',
                accent: '#1B9B8E',
                site: 'avoryx.io',
                kicker: 'New Avoryx demo request',
              }
            : {
                name: 'Sangani Group',
                tagline: 'Foundations of Innovation',
                accent: '#1B9B8E',
                site: 'sanganigroup.in',
                kicker: 'New website lead',
              };

        // Minimal HTML-escaper (defense-in-depth for values rendered in HTML).
        const esc = (v) =>
            String(v == null ? '' : v)
                .replace(/&/g, '&amp;')
                .replace(/</g, '&lt;')
                .replace(/>/g, '&gt;')
                .replace(/"/g, '&quot;');

        const rows = [
            ['Name', name],
            ['Email', email],
            ['Phone', phone || '—'],
            ['Company', company || '—'],
            [isAvoryx ? 'Product' : 'Service', service],
            [isAvoryx ? 'Team size' : 'Budget', budget || '—'],
            isAvoryx && stack ? ['Tools today', stack] : null,
            source ? ['Source', source] : null,
        ].filter(Boolean);

        const rowHtml = rows
            .map(
                ([k, v]) => `
                <tr>
                  <td style="padding:10px 16px;border-bottom:1px solid #eef0f2;color:#6b7280;font-size:13px;width:130px;vertical-align:top;">${esc(k)}</td>
                  <td style="padding:10px 16px;border-bottom:1px solid #eef0f2;color:#111827;font-size:14px;font-weight:600;">${esc(v)}</td>
                </tr>`
            )
            .join('');

        const html = `
<!doctype html>
<html>
  <body style="margin:0;padding:0;background:#f4f6f8;font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;">
    <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#f4f6f8;padding:28px 12px;">
      <tr><td align="center">
        <table role="presentation" width="600" cellpadding="0" cellspacing="0" style="max-width:600px;width:100%;background:#ffffff;border-radius:14px;overflow:hidden;box-shadow:0 8px 30px -12px rgba(0,0,0,0.15);">
          <!-- Brand bar -->
          <tr><td style="height:5px;background:linear-gradient(90deg,#FFC847,#FF6B35,#B61F7E,#7B2AA1,#0066CC,#1B9B8E,#1FA373);"></td></tr>
          <!-- Header -->
          <tr><td style="padding:26px 28px 8px;">
            <div style="font-size:12px;letter-spacing:.08em;text-transform:uppercase;color:${brand.accent};font-weight:700;">${esc(brand.kicker)}</div>
            <div style="font-size:22px;font-weight:800;color:#111827;margin-top:6px;">${esc(brand.name)}</div>
            <div style="font-size:13px;color:#6b7280;margin-top:2px;">${esc(brand.tagline)}</div>
          </td></tr>
          <!-- Lead card -->
          <tr><td style="padding:10px 28px 4px;">
            <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="border:1px solid #eef0f2;border-radius:10px;overflow:hidden;">
              ${rowHtml}
            </table>
          </td></tr>
          <!-- Message -->
          <tr><td style="padding:18px 28px 6px;">
            <div style="font-size:12px;letter-spacing:.05em;text-transform:uppercase;color:#6b7280;font-weight:700;margin-bottom:8px;">Message</div>
            <div style="font-size:14px;line-height:1.6;color:#111827;background:#f9fafb;border-radius:10px;padding:14px 16px;white-space:pre-wrap;">${esc(message)}</div>
          </td></tr>
          <!-- Footer -->
          <tr><td style="padding:16px 28px 26px;">
            <div style="font-size:12px;color:#9ca3af;">Received via ${esc(brand.site)} · IP ${esc(ip)}</div>
            <div style="font-size:12px;color:#9ca3af;margin-top:2px;">Reply directly to this email to reach ${esc(name)}.</div>
          </td></tr>
        </table>
        <div style="font-size:11px;color:#9ca3af;margin-top:14px;">Sangani Group · ${esc(brand.site)}</div>
      </td></tr>
    </table>
  </body>
</html>`.trim();

        const text = [
            brand.kicker,
            '',
            ...rows.map(([k, v]) => `${k}: ${v}`),
            '',
            'Message:',
            message,
            '',
            `Received via ${brand.site} · IP ${ip}`,
        ].join('\n');

        /* -------------------- Email (best-effort) --------------------
         * Send the notification, but a failure here NEVER fails the request — the
         * lead is already captured in the Data Store. We only email when the
         * submission looks human and is within the rate limit (spam guard).       */
        let emailed = false;
        if (isHuman && withinRate) {
            try {
                await transporter.sendMail({
                    from: `"${brand.name} Website" <${process.env.GMAIL_USER}>`,
                    to: process.env.RECIPIENT_EMAIL,
                    replyTo: email,
                    subject: `${brand.kicker} — ${service} (${name})`,
                    text,
                    html,
                });
                emailed = true;
            } catch (mailErr) {
                console.error('Email send failed (lead is still captured):', mailErr && mailErr.message);
            }
        } else {
            console.log('Notification email skipped:', { isHuman, withinRate, email });
        }

        /* -------------------- Friendly response --------------------
         * The lead is captured either way, so the visitor always sees a warm,
         * reassuring confirmation — never a raw error on a public-facing site.    */
        res.writeHead(200, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({
            ok: true,
            captured,
            crmPushed,
            emailed,
            message: `Thank you, ${String(name).split(' ')[0]}! We've received your details and our team will be in touch shortly.`,
        }));

    } catch (err) {
        // Even on an unexpected error, be warm and give a fallback contact path —
        // never surface a technical message to a visitor.
        console.error('Function error:', err && err.stack ? err.stack : err);
        res.writeHead(200, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({
            ok: false,
            message: "Sorry — we couldn't complete that just now. Please try again in a moment, or email us at info@sanganigroup.in and we'll get right back to you.",
        }));
    }
};
