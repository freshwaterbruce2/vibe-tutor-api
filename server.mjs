import { GoogleGenAI } from '@google/genai';
import cors from 'cors';
import crypto from 'crypto';
import dotenv from 'dotenv';
import express from 'express';
import helmet from 'helmet';
import fs from 'node:fs';
import path from 'node:path';

dotenv.config();

const app = express();

// Security headers (relaxed for API-only service)
app.use(helmet({ contentSecurityPolicy: false }));
const PORT = process.env.PORT || 3001;

// ============== CONFIGURATION ==============

// Google Gemini (Primary AI provider)
const GEMINI_CONFIG = {
  model: 'gemini-2.0-flash', // Fast, cheap, great for education
  systemInstruction: `You are Vibe Tutor, a friendly and patient AI learning companion designed for children and young learners. You specialize in making education fun, engaging, and accessible.

Key behaviors:
- Use simple, encouraging language appropriate for children
- Break complex topics into small, digestible steps
- Celebrate effort and progress, not just correct answers
- Use analogies, examples, and gentle humor
- If a child seems frustrated, offer encouragement and a different approach
- Never use sarcasm, condescension, or inappropriate content
- Keep responses concise (2-3 paragraphs max unless explaining a complex topic)
- Use emoji sparingly to keep things fun 🌟`,
};

// OpenRouter (Fallback provider)
const OPENROUTER_CONFIG = {
  baseURL: 'https://openrouter.ai/api/v1',
  model: 'deepseek/deepseek-chat',
  timeout: 30000,
};

// Initialize Gemini client (lazy — only if key is present)
const geminiClient = process.env.GEMINI_API_KEY
  ? new GoogleGenAI({ apiKey: process.env.GEMINI_API_KEY })
  : null;

// Rate limiting
const rateLimit = new Map();
const RATE_LIMIT_WINDOW = 60000; // 1 minute
const MAX_REQUESTS_PER_WINDOW = 30;

// Content filter for child safety
const INAPPROPRIATE_PATTERNS = [
  /\b(violence|violent|kill|death|die|dead|suicide|drug|alcohol|sex|nude|porn)\b/gi,
  /\b(hate|racist|discrimination)\b/gi,
  /\b(damn|hell|shit|fuck|ass|bitch)\b/gi,
];

function filterInappropriateContent(text) {
  for (const pattern of INAPPROPRIATE_PATTERNS) {
    if (pattern.test(text)) {
      return { safe: false, reason: 'Content contains inappropriate material' };
    }
  }
  return { safe: true };
}

// ============== MIDDLEWARE ==============

// CORS: Allow Capacitor app, localhost dev, and any custom origins via env
const extraOrigins = process.env.ALLOWED_ORIGINS ? process.env.ALLOWED_ORIGINS.split(',') : [];

app.use(
  cors({
    origin: function (origin, callback) {
      const allowedOrigins = [
        'http://localhost:5173',
        'http://localhost:5174',
        'http://localhost:5175',
        'http://localhost:3000',
        'http://127.0.0.1:5173',
        'capacitor://localhost',
        'ionic://localhost',
        'http://localhost',
        'https://vibe-tutor-api.onrender.com',
        ...extraOrigins,
      ];

      // No origin = same-origin, Capacitor native HTTP, or server-to-server
      if (!origin) return callback(null, true);
      if (allowedOrigins.includes(origin)) return callback(null, true);

      // Allow any capacitor/ionic origin
      if (origin.startsWith('capacitor://') || origin.startsWith('ionic://')) {
        return callback(null, true);
      }

      return callback(new Error('Not allowed by CORS'));
    },
    credentials: true,
  }),
);

app.use(express.json());

// ============== ANALYTICS LOGGING ==============

// Optional: save lightweight analytics events for debugging.
// In managed hosts (Render), this writes to ephemeral disk by default.
app.post('/api/analytics/log', validateSession, (req, res) => {
  try {
    const { event, data } = req.body || {};

    const logDir = process.env.ANALYTICS_LOG_DIR || path.join(process.cwd(), 'logs');
    if (!fs.existsSync(logDir)) {
      fs.mkdirSync(logDir, { recursive: true });
    }

    const logFile = path.join(logDir, `analytics-${new Date().toISOString().split('T')[0]}.log`);
    const logEntry = `${JSON.stringify({
      timestamp: new Date().toISOString(),
      session: req.headers.authorization?.replace('Bearer ', '').substring(0, 8),
      event,
      data,
    })}\n`;

    fs.appendFileSync(logFile, logEntry);
    res.json({ status: 'success' });
  } catch (error) {
    console.error('[Analytics] Logging failed:', error);
    // Never break the app flow for analytics.
    res.json({ status: 'ignored' });
  }
});

// Rate limiting middleware
app.use((req, res, next) => {
  const clientId = req.ip;
  const now = Date.now();

  if (!rateLimit.has(clientId)) {
    rateLimit.set(clientId, { count: 1, resetTime: now + RATE_LIMIT_WINDOW });
    next();
    return;
  }

  const limit = rateLimit.get(clientId);

  if (now > limit.resetTime) {
    limit.count = 1;
    limit.resetTime = now + RATE_LIMIT_WINDOW;
    rateLimit.set(clientId, limit);
    next();
    return;
  }

  if (limit.count >= MAX_REQUESTS_PER_WINDOW) {
    res.status(429).json({
      error: 'Too many requests. Please try again later.',
      retryAfter: Math.ceil((limit.resetTime - now) / 1000),
    });
    return;
  }

  limit.count++;
  rateLimit.set(clientId, limit);
  next();
});

// ============== SESSION MANAGEMENT ==============

const sessions = new Map();
const SESSION_DURATION = 30 * 60 * 1000; // 30 minutes

// Rate limiting for session initialization (prevent DoS/enumeration attacks)
const sessionInitRateLimit = new Map();
const SESSION_INIT_LIMIT = 50; // Max 50 sessions per IP per hour (was 5 — too restrictive for dev/retries)
const SESSION_INIT_WINDOW = 60 * 60 * 1000; // 1 hour

function generateSessionToken() {
  return crypto.randomBytes(32).toString('hex');
}

// Initialize session endpoint (with rate limiting)
app.post('/api/session/init', (req, res) => {
  const clientIp = req.ip;
  const now = Date.now();

  // Check session creation rate limit
  if (sessionInitRateLimit.has(clientIp)) {
    const limit = sessionInitRateLimit.get(clientIp);
    if (now < limit.resetTime) {
      if (limit.count >= SESSION_INIT_LIMIT) {
        res.status(429).json({
          error: 'Too many session requests. Please try again later.',
          retryAfter: Math.ceil((limit.resetTime - now) / 1000),
        });
        return;
      }
      limit.count++;
    } else {
      limit.count = 1;
      limit.resetTime = now + SESSION_INIT_WINDOW;
    }
    sessionInitRateLimit.set(clientIp, limit);
  } else {
    sessionInitRateLimit.set(clientIp, { count: 1, resetTime: now + SESSION_INIT_WINDOW });
  }

  const token = generateSessionToken();
  const sessionData = {
    createdAt: Date.now(),
    requestCount: 0,
    dailyUsage: 0,
  };

  sessions.set(token, sessionData);

  // Clean old sessions
  for (const [key, value] of sessions.entries()) {
    if (Date.now() - value.createdAt > SESSION_DURATION) {
      sessions.delete(key);
    }
  }

  res.json({
    token,
    expiresIn: SESSION_DURATION / 1000,
  });
});

// Validate session middleware
function validateSession(req, res, next) {
  const token = req.headers.authorization?.replace('Bearer ', '');

  if (!token || !sessions.has(token)) {
    res.status(401).json({ error: 'Invalid or expired session' });
    return;
  }

  const session = sessions.get(token);

  if (Date.now() - session.createdAt > SESSION_DURATION) {
    sessions.delete(token);
    res.status(401).json({ error: 'Session expired' });
    return;
  }

  session.requestCount++;

  // Daily usage limit (150 requests per day)
  const dayStart = new Date().setHours(0, 0, 0, 0);
  if (session.createdAt >= dayStart) {
    session.dailyUsage++;
    if (session.dailyUsage > 150) {
      res.status(429).json({
        error: 'Daily usage limit reached. Please try again tomorrow.',
      });
      return;
    }
  } else {
    session.dailyUsage = 1;
  }

  req.session = session; // eslint-disable-line no-param-reassign
  next();
}

// ============== GEMINI API (Primary) ==============

/** Convert OpenAI-style messages to Gemini format */
function toGeminiContents(messages) {
  return messages
    .filter((m) => m.role !== 'system') // system handled via systemInstruction
    .map((m) => ({
      role: m.role === 'assistant' ? 'model' : 'user',
      parts: [{ text: m.content }],
    }));
}

async function callGemini(messages) {
  if (!geminiClient) throw new Error('GEMINI_API_KEY not configured');

  // Extract client-sent system prompt (from AI_TUTOR_PROMPT / AI_FRIEND_PROMPT)
  // and use it as Gemini's systemInstruction. Fall back to server default.
  const clientSystemMsg = messages.find((m) => m.role === 'system');
  const systemInstruction = clientSystemMsg?.content || GEMINI_CONFIG.systemInstruction;

  /* eslint-disable no-console */
  console.log('[Gemini] System prompt source:', clientSystemMsg ? 'CLIENT' : 'SERVER-DEFAULT');
  console.log('[Gemini] System prompt preview:', `${systemInstruction.slice(0, 80)}...`);
  /* eslint-enable no-console */

  const contents = toGeminiContents(messages);

  const response = await geminiClient.models.generateContent({
    model: GEMINI_CONFIG.model,
    contents,
    config: {
      systemInstruction,
      maxOutputTokens: 2000,
      temperature: 0.7,
      topP: 0.95,
      // Explicitly disable Google Search grounding to prevent external citations
      tools: [],
      safetySettings: [
        { category: 'HARM_CATEGORY_HARASSMENT', threshold: 'BLOCK_LOW_AND_ABOVE' },
        { category: 'HARM_CATEGORY_HATE_SPEECH', threshold: 'BLOCK_LOW_AND_ABOVE' },
        { category: 'HARM_CATEGORY_SEXUALLY_EXPLICIT', threshold: 'BLOCK_LOW_AND_ABOVE' },
        { category: 'HARM_CATEGORY_DANGEROUS_CONTENT', threshold: 'BLOCK_LOW_AND_ABOVE' },
      ],
    },
  });

  const text = response.text ?? '';
  return text;
}

// ============== OPENROUTER API (Fallback) ==============

async function callOpenRouter(messages) {
  const apiKey = process.env.OPENROUTER_API_KEY;
  if (!apiKey) throw new Error('OPENROUTER_API_KEY not configured');

  const response = await fetch(`${OPENROUTER_CONFIG.baseURL}/chat/completions`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${apiKey}`,
      'HTTP-Referer': 'https://vibe-tutor.app',
      'X-Title': 'Vibe Tutor',
    },
    body: JSON.stringify({
      model: OPENROUTER_CONFIG.model,
      messages,
      temperature: 0.7,
      max_tokens: 2000,
    }),
  });

  if (!response.ok) {
    const errorText = await response.text();
    console.error(`[OpenRouter] Error ${response.status}:`, errorText);
    throw new Error(`OpenRouter API error: ${response.status}`);
  }

  const data = await response.json();
  return data.choices?.[0]?.message?.content ?? '';
}

// ============== UNIFIED CHAT ENDPOINT ==============

/** Try Gemini first, fallback to OpenRouter */
async function getAIResponse(messages) {
  // Try Gemini (primary)
  if (geminiClient) {
    try {
      return { text: await callGemini(messages), provider: 'gemini' };
    } catch (err) {
      console.warn('[AI] Gemini failed, trying fallback:', err.message);
    }
  }

  // Try OpenRouter (fallback)
  if (process.env.OPENROUTER_API_KEY) {
    try {
      return { text: await callOpenRouter(messages), provider: 'openrouter' };
    } catch (err) {
      console.error('[AI] OpenRouter fallback failed:', err.message);
    }
  }

  throw new Error('No AI provider available');
}

// Primary chat endpoint — used by both /api/chat and /api/openrouter/chat
app.post(['/api/chat', '/api/openrouter/chat'], validateSession, async (req, res) => {
  try {
    const { messages } = req.body;

    if (!messages || !Array.isArray(messages)) {
      res.status(400).json({ error: 'Invalid request format' });
      return;
    }

    // Content safety check on user input
    const lastMessage = messages[messages.length - 1];
    if (lastMessage?.role === 'user') {
      const check = filterInappropriateContent(lastMessage.content);
      if (!check.safe) {
        res.status(400).json({ error: 'Request blocked', reason: check.reason });
        return;
      }
    }

    const { text, provider } = await getAIResponse(messages);

    // Filter AI response
    const responseCheck = filterInappropriateContent(text);
    const safeText = responseCheck.safe
      ? text
      : "I cannot provide that information. Let's focus on your learning instead!";

    // Return in OpenAI-compatible format for frontend compatibility
    res.json({
      choices: [{ message: { role: 'assistant', content: safeText } }],
      message: safeText,
      provider,
    });
  } catch (error) {
    console.error('[Chat] Error:', error.message);
    res.status(500).json({ error: 'Service error', message: 'Please try again later' });
  }
});

// ============== UTILITY ENDPOINTS ==============

// Privacy Policy (required for Play Store)
app.get('/privacy', (req, res) => {
  res.send(`<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Vibe Tutor - Privacy Policy</title>
<style>body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;max-width:760px;margin:0 auto;padding:24px;line-height:1.65;color:#2b2b2b}h1{color:#1a1a2e;border-bottom:2px solid #0c7b93;padding-bottom:8px}h2{color:#0c7b93;margin-top:32px}.updated{color:#666;font-style:italic}.summary{background:#f3f8fa;border-left:4px solid #0c7b93;padding:12px 16px}ul{padding-left:22px}li{margin:8px 0}a{color:#086779}</style></head><body>
<h1>Vibe Tutor — Privacy Policy</h1>
<p class="updated">Effective September 5, 2026</p>

<div class="summary"><strong>What parents and teens should know first:</strong> Vibe Tutor is homework help for teens ages 13–17 in the United States. It is available on Google Play for a one-time price of $2.99. It has no ads, subscription, or in-app purchases. Tutor and Buddy use third-party AI services, so do not enter information you would not want sent to an AI provider.</div>

<h2>Scope and accounts</h2>
<p>This policy explains how Vibe Tutor and its backend service handle information. Vibe Tutor does not require a Vibe Tutor account, and the backend does not maintain a long-term personal profile for each learner. The service is not directed to children under 13.</p>

<h2>AI processing</h2>
<p>When you use Tutor or Buddy, the message text and conversation context supplied with the request are sent through our backend to Google Gemini, our primary AI provider. If Gemini is unavailable, the backend may send the same request to OpenRouter as a fallback. The provider's response is returned to the app.</p>
<p>The backend does not write chat conversations to its own conversation-history database. Google and OpenRouter may process or retain requests under their own terms and privacy practices. Avoid entering names, contact details, health information, passwords, or other sensitive information in AI chats.</p>

<h2>Information handled by the backend</h2>
<ul>
  <li><strong>Chat requests:</strong> Message text, system instructions, and conversation context needed to generate a response.</li>
  <li><strong>Temporary sessions:</strong> A random session token and request counters are held in server memory. Sessions expire after about 30 minutes and are not a permanent account or profile.</li>
  <li><strong>Network information:</strong> The service uses the requesting IP address in memory for rate limiting. Our hosting provider may also process IP addresses, request times, user-agent details, and similar infrastructure logs.</li>
  <li><strong>Operational analytics:</strong> The app may submit an event name and event data. The backend writes the timestamp, the first eight characters of the session token, the event name, and the submitted event data to a daily log file. These events are intended for reliability and product improvement, not advertising. Because the event payload comes from the app, information included in that payload could appear in the operational log.</li>
</ul>

<h2>Retention</h2>
<p>Chat content is processed for the response and is not intentionally saved by this backend as chat history. Temporary session records are kept in memory for about 30 minutes. Operational analytics files may remain on the running service's filesystem for the life of that service instance; we do not promise a fixed deletion time for those files. Hosting and AI providers may keep their own service or security records under their policies.</p>

<h2>On-device data and voice</h2>
<p>Study data, preferences, and chat history may be stored locally by the app. Clearing the app's data or uninstalling it removes the app's local copy, subject to Android or device backup settings. If you choose voice input, your device or speech service converts audio to transcript text. Vibe Tutor sends the resulting text to the backend for the feature you selected; this backend does not receive microphone audio through the chat endpoint.</p>

<h2>Google Play</h2>
<p>Google Play processes the purchase and may perform licensing or integrity checks under Google's privacy practices. The current Vibe Tutor backend does not receive or store your Google Play payment-card details.</p>

<h2>Safety filtering</h2>
<p>The backend checks the latest user message and the generated response with automated content filters. Gemini also applies its configured safety controls. These measures reduce risk but cannot guarantee that every response will be accurate, appropriate, or error-free. A parent or guardian should review important educational, health, or safety information.</p>

<h2>Sharing and business practices</h2>
<p>We use service providers as needed to operate the features you choose, including our hosting provider, Google Gemini, OpenRouter, Google Play, and any device or speech service used for optional voice input. We do not sell personal information, serve targeted advertising, or use chat content to build advertising profiles.</p>

<h2>Your choices</h2>
<ul>
  <li>You may avoid the optional AI and voice features.</li>
  <li>You may clear local app data or uninstall the app.</li>
  <li>You may contact us with a privacy question or request. Because the backend does not use named accounts, we may not be able to identify a particular pseudonymous session or log entry without enough information to locate it.</li>
</ul>

<h2>Security</h2>
<p>The production service uses HTTPS/TLS in transit and applies random session tokens, rate limits, and content filtering. No system can guarantee absolute security.</p>

<h2>Changes</h2>
<p>We may update this policy when the app, providers, pricing, or data practices change. The effective date above will show the latest revision.</p>

<h2>Contact</h2>
<p>Privacy questions: <strong><a href="mailto:support@vibe-tech.org">support@vibe-tech.org</a></strong></p>
<p>Vibe Tech LLC</p>
</body></html>`);
});

// ============== RADIO STREAM PROXY ==============
// Proxies radio stream URLs to bypass Android WebView CSP restrictions

/** Allowed radio stream domains (security: prevents open proxy abuse) */
const ALLOWED_RADIO_DOMAINS = [
  'listen.moe',
  'ice.somafm.com',
  'ice1.somafm.com',
  'ice2.somafm.com',
  'ice3.somafm.com',
  'ice4.somafm.com',
  'ice6.somafm.com',
  'fm997.wqxr.org',
  'stream.wqxr.org',
  'liveradio.swr.de',
  'stream.srg-ssr.ch',
  'streams.kqed.org',
  'playerservices.streamtheworld.com',
  'stream.radioparadise.com',
  'audio-edge-es6pf.fra.h.radiomast.io',
  'streams.fluxfm.de',
  'stream.laut.fm',
  // Jamendo music API + audio CDN
  'api.jamendo.com',
  'mp3d.jamendo.com',
  'mp3l.jamendo.com',
  // AnimeNfo Radio
  'radionomy.com',
  'streamow6.radionomy.com',
];

app.get('/api/radio/stream', async (req, res) => {
  const streamUrl = req.query.url;

  if (!streamUrl || typeof streamUrl !== 'string') {
    res.status(400).json({ error: 'Missing `url` query parameter' });
    return;
  }

  let parsed;
  try {
    parsed = new URL(streamUrl);
  } catch {
    res.status(400).json({ error: 'Invalid URL' });
    return;
  }

  // Security: only proxy known radio domains
  const isDomainAllowed = ALLOWED_RADIO_DOMAINS.some(
    (d) => parsed.hostname === d || parsed.hostname.endsWith(`.${d}`),
  );

  if (!isDomainAllowed) {
    res.status(403).json({ error: 'Domain not allowed', hostname: parsed.hostname });
    return;
  }

  try {
    const upstream = await fetch(streamUrl, {
      headers: {
        'User-Agent': 'VibeTutor/1.0',
        Accept: 'audio/*,*/*',
        ...(req.headers.range ? { Range: req.headers.range } : {}),
      },
      signal: AbortSignal.timeout(60000),
    });

    if (!upstream.ok && upstream.status !== 206) {
      res.status(upstream.status).json({ error: `Upstream error: ${upstream.status}` });
      return;
    }

    // Forward essential headers for audio playback
    const contentType = upstream.headers.get('content-type');
    if (contentType) res.setHeader('Content-Type', contentType);

    const contentLength = upstream.headers.get('content-length');
    if (contentLength) res.setHeader('Content-Length', contentLength);

    const acceptRanges = upstream.headers.get('accept-ranges');
    if (acceptRanges) res.setHeader('Accept-Ranges', acceptRanges);

    const contentRange = upstream.headers.get('content-range');
    if (contentRange) res.setHeader('Content-Range', contentRange);

    res.setHeader('Cache-Control', 'no-cache, no-store');
    res.setHeader('Access-Control-Allow-Origin', '*');

    res.status(upstream.status);

    // Pipe the stream (Node 18+ ReadableStream)
    const { Readable } = await import('node:stream');
    const nodeStream = Readable.fromWeb(upstream.body);
    nodeStream.pipe(res);

    // Clean up when client disconnects
    req.on('close', () => {
      nodeStream.destroy();
    });
  } catch (err) {
    if (!res.headersSent) {
      res.status(502).json({ error: 'Failed to connect to radio stream', details: err.message });
    }
  }
});

// Root endpoint
app.get('/', (req, res) => {
  res.json({ service: 'Vibe Tutor API', status: 'running', docs: '/api/health' });
});

// Health check
app.get('/api/health', (req, res) => {
  res.json({
    status: 'healthy',
    timestamp: new Date().toISOString(),
    providers: {
      gemini: !!process.env.GEMINI_API_KEY,
      openrouter: !!process.env.OPENROUTER_API_KEY,
    },
    models: {
      primary: GEMINI_CONFIG.model,
      fallback: OPENROUTER_CONFIG.model,
    },
  });
});

// Usage stats
app.get('/api/stats/:token', (req, res) => {
  const { token } = req.params;

  if (!sessions.has(token)) {
    res.status(404).json({ error: 'Session not found' });
    return;
  }

  const session = sessions.get(token);
  res.json({
    requestCount: session.requestCount,
    dailyUsage: session.dailyUsage,
    sessionAge: Math.floor((Date.now() - session.createdAt) / 1000 / 60),
  });
});

// ============== SERVER START ==============

app.listen(PORT, () => {
  /* eslint-disable no-console */
  console.log(`\n[OK] Vibe-Tutor API server running on port ${PORT}`);
  console.log('[OK] Primary:', GEMINI_CONFIG.model, process.env.GEMINI_API_KEY ? '✓' : '✗');
  console.log(
    '[OK] Fallback:',
    OPENROUTER_CONFIG.model,
    process.env.OPENROUTER_API_KEY ? '✓' : '✗',
  );
  console.log('[OK] Rate limiting: 30/min | Content filtering: active\n');
  /* eslint-enable no-console */
});
