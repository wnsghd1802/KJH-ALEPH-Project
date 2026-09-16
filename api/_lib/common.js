import crypto from 'node:crypto';
import { createClient } from '@supabase/supabase-js';

let client;

export function getDB() {
  if (client) return client;
  const url = process.env.SUPABASE_URL;
  const serviceRoleKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
  if (!url || !serviceRoleKey) {
    throw new Error('SUPABASE_URL 또는 SUPABASE_SERVICE_ROLE_KEY 환경 변수가 없습니다.');
  }
  client = createClient(url, serviceRoleKey, {
    auth: { persistSession: false, autoRefreshToken: false, detectSessionInUrl: false },
  });
  return client;
}

export const OWNER_ID = 'portfolio-owner';
export const RP_NAME = 'Network Security Profile';
export const CHALLENGE_TTL_MS = 5 * 60 * 1000;
export const REMOTE_LOGIN_TTL_MS = 2 * 60 * 1000;
export const SESSION_COOKIE = 'task8_session';
export const SESSION_TTL_MS = 8 * 60 * 60 * 1000;

export function getWebAuthnConfig(req) {
  const forwardedHost = req.headers['x-forwarded-host'];
  const host = forwardedHost || req.headers.host;
  if (!host) throw new Error('요청 Host를 확인할 수 없습니다.');
  const forwardedProto = req.headers['x-forwarded-proto'];
  const local = host.startsWith('localhost') || host.startsWith('127.0.0.1');
  const protocol = forwardedProto || (local ? 'http' : 'https');
  const rpID = process.env.WEBAUTHN_RP_ID || host.split(':')[0];
  const origin = process.env.WEBAUTHN_ORIGIN || `${protocol}://${host}`;
  return { rpID, origin };
}

export function noStore(res) {
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate');
}

export function jsonError(res, status, error, message) {
  return res.status(status).json({ ok: false, error, message });
}

export function createSessionToken() {
  return crypto.randomBytes(32).toString('base64url');
}

export function hashSessionToken(token) {
  return crypto.createHash('sha256').update(String(token || ''), 'utf8').digest('hex');
}

export function readCookie(req, name) {
  const raw = String(req.headers.cookie || '');
  if (!raw) return null;
  for (const part of raw.split(';')) {
    const [key, ...rest] = part.trim().split('=');
    if (key === name) return decodeURIComponent(rest.join('='));
  }
  return null;
}

function isHttps(req) {
  const forwardedProto = String(req.headers['x-forwarded-proto'] || '').split(',')[0].trim();
  if (forwardedProto) return forwardedProto === 'https';
  return !String(req.headers.host || '').startsWith('localhost');
}

export function setSessionCookie(req, res, token, maxAgeSeconds = Math.floor(SESSION_TTL_MS / 1000)) {
  const parts = [
    `${SESSION_COOKIE}=${encodeURIComponent(token)}`,
    'Path=/', 'HttpOnly', 'SameSite=Lax', `Max-Age=${maxAgeSeconds}`,
  ];
  if (isHttps(req)) parts.push('Secure');
  res.setHeader('Set-Cookie', parts.join('; '));
}

export function clearSessionCookie(req, res) {
  const parts = [`${SESSION_COOKIE}=`, 'Path=/', 'HttpOnly', 'SameSite=Lax', 'Max-Age=0'];
  if (isHttps(req)) parts.push('Secure');
  res.setHeader('Set-Cookie', parts.join('; '));
}

export function createOpaqueSecret(bytes = 32) {
  return crypto.randomBytes(bytes).toString('base64url');
}

export function hashOpaqueSecret(value) {
  return crypto.createHash('sha256').update(String(value || ''), 'utf8').digest('hex');
}

export function safeSecretMatches(rawValue, expectedHash) {
  const actual = hashOpaqueSecret(rawValue);
  const a = Buffer.from(actual, 'utf8');
  const b = Buffer.from(String(expectedHash || ''), 'utf8');
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

export function preview(value, head = 12, tail = 6) {
  const text = String(value || '');
  if (text.length <= head + tail + 1) return text;
  return `${text.slice(0, head)}…${text.slice(-tail)}`;
}
