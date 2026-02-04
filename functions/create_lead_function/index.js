const nodemailer = require('nodemailer');

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
        return data.success === true && data.score >= 0.5;
    } catch (err) {
        console.error('reCAPTCHA error:', err);
        return false;
    }
}

module.exports = async (req, res) => {
    try {
        /* -------------------- CORS -------------------- */       
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

        console.log('PARSED BODY:', body);

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
        } = body || {};   

        console.log(name);
        console.log(service);
        console.log(message);
        console.log(recaptchaToken);

        if (!name || !email || !service || !message || !recaptchaToken) {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            return res.end(JSON.stringify({ error: 'Missing required fields' }));
        }

        /* -------------------- reCAPTCHA -------------------- */
        const isHuman = await verifyRecaptcha(recaptchaToken);
        if (!isHuman) {
            res.writeHead(403, { 'Content-Type': 'application/json' });
            return res.end(JSON.stringify({ error: 'reCAPTCHA verification failed' }));
        }

        /* -------------------- Rate limit -------------------- */
        const ip =
            (req.headers['x-forwarded-for'] || '').split(',')[0] || 'unknown';

        if (!checkRateLimit(ip)) {
            res.writeHead(429, { 'Content-Type': 'application/json' });
            return res.end(
                JSON.stringify({ error: 'Too many requests. Try again later.' })
            );
        }

        /* -------------------- Email -------------------- */
        const transporter = nodemailer.createTransport({
            service: 'gmail',
            auth: {
                user: process.env.GMAIL_USER,
                pass: process.env.GMAIL_APP_PASSWORD,
            },
        });

        await transporter.sendMail({
            from: `"Sangani Group Website" <${process.env.GMAIL_USER}>`,
            to: process.env.RECIPIENT_EMAIL,
            replyTo: email,
            subject: `New Lead - ${service} (${name})`,
            text: `
Name: ${name}
Email: ${email}
Phone: ${phone || 'N/A'}
Company: ${company || 'N/A'}
Service: ${service}
Budget: ${budget || 'N/A'}

Message:
${message}

IP: ${ip}
      `.trim(),
                });

        /* -------------------- Success -------------------- */
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: true, message: 'Lead created' }));

    } catch (err) {
        console.error('Function error:', err);

        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(
            JSON.stringify({ error: 'Internal server error. Please try later.' })
        );
    }
};
