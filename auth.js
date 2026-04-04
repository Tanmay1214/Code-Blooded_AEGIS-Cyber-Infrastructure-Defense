/**
 * auth.js — AEGIS JWT Authentication Module
 * Handles login, token storage, auth guards, and logout.
 * Auto-detects local vs production API URL.
 */

// ── API URL Detection ──────────────────────────────────────────
const API_URL = (
  window.location.hostname === 'localhost' ||
  window.location.hostname === '127.0.0.1' ||
  window.location.hostname === ''
)
  ? 'http://127.0.0.1:8000'
  : 'https://aegis-api-65i8.onrender.com';

// ── Token Helpers ──────────────────────────────────────────────

function getToken() {
  return localStorage.getItem('access_token');
}

function checkAuth() {
  const token = getToken();
  const isLoginPage = window.location.pathname.endsWith('login.html') || 
                      window.location.pathname === '/login' ||
                      window.location.pathname === '/';
  
  console.log(`[AUTH_GUARD] Path: ${window.location.pathname} | Token: ${token ? 'PRESENT' : 'MISSING'}`);

  if (!token && !isLoginPage) {
    // If we're on a local file, give it a moment to stabilize before redirecting
    if (window.location.protocol === 'file:') {
      console.warn("[AUTH_GUARD] Local file detected. Ensuring persistence...");
      // Optional: Relax guard for local development if needed
      // return; 
    }
    window.location.href = 'login.html';
  }
}

function logout() {
  localStorage.removeItem('access_token');
  window.location.href = 'login.html';
}

// ── Login Form Handler ─────────────────────────────────────────

async function initAuth() {
  // Bind login form if it exists on this page
  const form = document.getElementById('login-form');
  if (!form || form.dataset.bound) return;
  form.dataset.bound = "true";

  form.addEventListener('submit', async (e) => {
    e.preventDefault();

    const username = document.getElementById('username').value.trim();
    const password = document.getElementById('password').value.trim();
    const errorEl = document.getElementById('error-msg');
    const submitBtn = form.querySelector('button[type="submit"]');

    // Reset error state
    if (errorEl) errorEl.style.display = 'none';

    // Loading state
    if (submitBtn) {
      submitBtn.disabled = true;
      submitBtn.textContent = 'AUTHENTICATING...';
    }

    try {
      const body = new URLSearchParams();
      body.append('username', username);
      body.append('password', password);

      const response = await fetch(`${API_URL}/api/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: body.toString(),
      });

      if (response.ok) {
        const data = await response.json();
        localStorage.setItem('access_token', data.access_token);
        // Brief success flash before redirect
        if (submitBtn) submitBtn.textContent = 'ACCESS GRANTED ✓';
        setTimeout(() => {
          window.location.href = 'dashboard.html';
        }, 400);
      } else {
        if (errorEl) {
          errorEl.textContent = 'ACCESS DENIED — Invalid Credentials';
          errorEl.style.display = 'block';
        }
        if (submitBtn) {
          submitBtn.disabled = false;
          submitBtn.textContent = 'AUTHENTICATE';
        }
      }
    } catch (err) {
      console.error('Login error:', err);
      if (errorEl) {
        errorEl.textContent = 'CONNECTION FAILED — Backend Unreachable';
        errorEl.style.display = 'block';
      }
      if (submitBtn) {
        submitBtn.disabled = false;
        submitBtn.textContent = 'AUTHENTICATE';
      }
    }
  });
}

// Initialize auth logic
document.addEventListener('DOMContentLoaded', () => {
  const isLoginPage = window.location.pathname.endsWith('login.html') ||
                      window.location.pathname === '/login';

  // Guard protected pages
  if (!isLoginPage) {
    checkAuth();
  }

  // Bind login form if we're on login page
  initAuth();
});
