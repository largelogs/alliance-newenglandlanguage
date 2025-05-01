import express from 'express';
import axios from 'axios';
import cors from 'cors';
import rateLimit from 'express-rate-limit';
import morgan from 'morgan';
import { setDefaultResultOrder } from 'dns';

// =====================
// INITIALIZATION
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

// Rate limiting (100 requests/minute)
app.use(rateLimit({
  windowMs: 60 * 1000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false
}));

// =====================
// ROUTES
// =====================

// Health Check (Required for Railway)
app.get('/health', (req, res) => {
  res.status(200).json({
    status: 'healthy',
    timestamp: new Date().toISOString(),
    services: {
      recaptcha: !!process.env.RECAPTCHA_SECRET,
      redis: false
    }
  });
});

// reCAPTCHA Verification Endpoint
app.post('/verify-token', async (req, res) => {
  const { token } = req.body;
  const secret = process.env.RECAPTCHA_SECRET;

  // Input validation
  if (!token || !secret) {
    return res.status(400).json({ 
      success: false,
      error: token ? 'Server misconfigured' : 'Token required'
    });
  }

  try {
    // Verify with Google
    const response = await axios.post(
      'https://www.google.com/recaptcha/api/siteverify',
      new URLSearchParams({ secret, response: token }),
      {
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        timeout: 3000
      }
    );

    const { success, score, 'error-codes': errorCodes = [] } = response.data;

    // Debug logging
    console.log('reCAPTCHA Result:', { success, score, errorCodes });

    if (!success) {
      return res.status(403).json({
        success: false,
        reason: 'reCAPTCHA verification failed',
        errors: errorCodes,
        score
      });
    }

    if (score < 0.5) {
      return res.status(403).json({
        success: false,
        reason: 'Suspicious activity detected',
        score
      });
    }

    // Successful verification
    return res.json({
      success: true,
      redirect: process.env.REDIRECT_URL || 'https://default-redirect.com',
      score
    });

  } catch (err) {
    console.error('API Error:', {
      message: err.message,
      code: err.code,
      response: err.response?.data
    });

    return res.status(500).json({
      success: false,
      error: 'Verification service unavailable'
    });
  }
});

// =====================
// SERVER STARTUP
// =====================
const server = app.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 Server running on http://0.0.0.0:${PORT}`);
  console.log('Configuration:', {
    nodeEnv: process.env.NODE_ENV,
    recaptchaReady: !!process.env.RECAPTCHA_SECRET,
    redirectUrl: process.env.REDIRECT_URL || 'using_default'
  });
});

// Railway optimizations
server.keepAliveTimeout = 60000;
server.headersTimeout = 65000;

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('🛑 Received termination signal');
  server.close(() => {
    console.log('✅ Server terminated');
    process.exit(0);
  });
});