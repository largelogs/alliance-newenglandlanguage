import express from 'express';
import axios from 'axios';
import cors from 'cors';
import rateLimit from 'express-rate-limit';
import morgan from 'morgan';
import { setDefaultResultOrder } from 'dns';

// =====================
// CRITICAL RAILWAY FIXES
// =====================
setDefaultResultOrder('ipv4first'); // Force IPv4 connections only

// =====================
// APP CONFIGURATION
// =====================
const app = express();
const PORT = process.env.PORT || 8080;

// =====================
// ENHANCED MIDDLEWARE
// =====================
app.set('trust proxy', 1); // Trust Railway's proxy
app.use(cors({
  origin: process.env.FRONTEND_URL || '*',
  credentials: true
}));
app.use(express.json());
app.use(morgan('combined')); // Production logging

// Rate limiting with better headers
app.use(rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 100,
  standardHeaders: true,
  legacyHeaders: false
}));

// =====================
// RELIABILITY IMPROVEMENTS
// =====================

// Enhanced health check (Railway requires this)
app.get('/health', (req, res) => {
  res.status(200).json({
    status: 'ready',
    timestamp: new Date().toISOString(),
    ipMode: 'ipv4-only', // Confirm IPv4 enforcement
    services: {
      recaptcha: !!process.env.RECAPTCHA_SECRET,
      database: false // Add if you add a DB later
    }
  });
});

// reCAPTCHA Verification (With Connection Timeout Fix)
app.post('/verify-token', async (req, res) => {
  const { token, email } = req.body;
  const secret = process.env.RECAPTCHA_SECRET;

  // Validate token format
  if (typeof token !== 'string' || token.length < 10) {
    return res.status(400).json({
      success: false,
      error: 'Invalid token format'
    });
  }

  if (!secret) {
    console.error('❌ RECAPTCHA_SECRET missing');
    return res.status(500).json({
      success: false,
      error: 'Server configuration error'
    });
  }

  try {
    // Verify with Google (with timeout)
    const response = await axios.post(
      'https://www.google.com/recaptcha/api/siteverify',
      new URLSearchParams({ secret, response: token }),
      {
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        timeout: 2500 // 2.5 second timeout
      }
    );

    const { success, score, 'error-codes': errors = [] } = response.data;

    if (!success || score < 0.5) {
      return res.status(403).json({
        success: false,
        reason: success ? 'Low score' : 'Verification failed',
        score,
        errors
      });
    }

    // Build redirect URL with email if provided
    let redirectUrl = process.env.REDIRECT_URL || 'https://default-redirect.com';
    if (email) {
      redirectUrl = `${redirectUrl.replace(/\/$/, '')}/${encodeURIComponent(email)}`;
    }

    return res.json({
      success: true,
      redirect: redirectUrl,
      score
    });

  } catch (err) {
    console.error('reCAPTCHA API Error:', {
      message: err.message,
      code: err.code,
      timeout: err.code === 'ECONNABORTED'
    });

    return res.status(502).json({
      success: false,
      error: 'Verification service unavailable',
      retry: true
    });
  }
});

// =====================
// SERVER STARTUP (CRITICAL FOR RAILWAY)
// =====================
const server = app.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 Server running on http://0.0.0.0:${PORT}`);
  console.log('Active Configuration:', {
    nodeEnv: process.env.NODE_ENV,
    recaptchaReady: !!process.env.RECAPTCHA_SECRET,
    ipMode: 'ipv4-only'
  });
});

// Railway-specific optimizations
server.keepAliveTimeout = 60000; // 60s
server.headersTimeout = 65000; // 65s

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('🛑 Received shutdown signal');
  server.close(() => {
    console.log('✅ Server terminated cleanly');
    process.exit(0);
  });
});
