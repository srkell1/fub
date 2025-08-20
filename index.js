import 'dotenv/config';
import express from 'express';
import rateLimit from 'express-rate-limit';
import helmet from 'helmet';
import bodyParser from 'body-parser';
import crypto from 'crypto';
import Database from 'better-sqlite3';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const PORT = process.env.PORT || 8787;
const DB_PATH = process.env.DB_PATH || './data.db';
const BASIC_AUTH_USER = process.env.BASIC_AUTH_USER || '';
const BASIC_AUTH_PASS = process.env.BASIC_AUTH_PASS || '';
const FUB_API_KEY = process.env.FUB_API_KEY || '';
const FUB_WEBHOOK_SECRET = process.env.FUB_WEBHOOK_SECRET || '';
const CAL_API_KEY = process.env.CAL_API_KEY || '';
const CAL_API_VERSION = process.env.CAL_API_VERSION || '2024-08-13';
const CAL_WEBHOOK_SECRET = process.env.CAL_WEBHOOK_SECRET || '';
const DEFAULT_EVENT_TYPE_ID = Number(process.env.DEFAULT_EVENT_TYPE_ID || 456);
const MAX_RETRIES = Number(process.env.MAX_RETRIES || 3);
const BACKOFF_BASE_MS = Number(process.env.BACKOFF_BASE_MS || 800);

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const PUBLIC_DIR = path.join(__dirname, 'public');

const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');
const schema = fs.readFileSync(new URL('./schema.sql', import.meta.url));
db.exec(schema.toString());

const rowCount = db.prepare('SELECT COUNT(*) as c FROM mapping').get().c;
if (rowCount === 0) {
  const defaults = [
    ['clientshouse', 'Client\'s House', 123],
    ['zoom', 'Zoom', 456],
    ['googlemeet', 'Google Meet', 789],
    ['etobicokeoffice', 'Etobicoke office', 1011],
    ['mississaugaoffice', 'Mississauga office', 1213]
  ];
  const ins = db.prepare('INSERT OR IGNORE INTO mapping (key, label, event_type_id) VALUES (?, ?, ?)');
  defaults.forEach((r) => ins.run(...r));
}

const uid = () => crypto.randomBytes(16).toString('hex');
const now = () => Date.now();

const app = express();
app.disable('x-powered-by');
app.use(helmet());
app.use(rateLimit({ windowMs: 60_000, max: 180 }));

const rawBodySaver = (req, res, buf) => { req.rawBody = buf; };
app.use('/webhooks', bodyParser.raw({ type: '*/*', verify: rawBodySaver }));
app.use(bodyParser.json());

app.use('/public', express.static(PUBLIC_DIR));
app.get(['/','/admin'], (req, res) => {
  res.sendFile(path.join(PUBLIC_DIR, 'admin.html'));
});

const needAuth = BASIC_AUTH_USER && BASIC_AUTH_PASS;
function basicAuth(req, res, next) {
  if (!needAuth) return next();
  const header = req.headers.authorization || '';
  const [scheme, credentials] = header.split(' ');
  if (scheme !== 'Basic' || !credentials) return unauthorized();
  const [user, pass] = Buffer.from(credentials, 'base64').toString().split(':');
  if (user === BASIC_AUTH_USER && pass === BASIC_AUTH_PASS) return next();
  return unauthorized();
  function unauthorized(){
    res.set('WWW-Authenticate', 'Basic realm="admin"');
    res.status(401).send('Unauthorized');
  }
}
app.use(['/api','/admin'], basicAuth);

const logStmt = db.prepare('INSERT INTO logs (id, ts, direction, action, message) VALUES (?, ?, ?, ?, ?)');
function log({ direction, action, message }) {
  logStmt.run(uid(), now(), direction, action, message);
}

const insertJob = db.prepare('INSERT INTO jobs (id, kind, payload, attempts, next_attempt_at, status, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)');
function enqueue(kind, payloadObj, delayMs = 0) {
  const id = uid();
  insertJob.run(id, kind, JSON.stringify(payloadObj), 0, now() + delayMs, 'pending', now(), now());
  return id;
}
const pickJob = db.prepare("SELECT * FROM jobs WHERE status = 'pending' AND next_attempt_at <= ? ORDER BY next_attempt_at ASC LIMIT 1");
const updJobAttempt = db.prepare('UPDATE jobs SET attempts = ?, next_attempt_at = ?, updated_at = ? WHERE id = ?');
const finishJob = db.prepare("UPDATE jobs SET status = 'done', updated_at = ? WHERE id = ?");
const failJob = db.prepare("UPDATE jobs SET status = 'failed', last_error = ?, updated_at = ? WHERE id = ?");

const getPairByFub = db.prepare('SELECT * FROM pairings WHERE fub_id = ?');
const getPairByCal = db.prepare('SELECT * FROM pairings WHERE cal_uid = ?');
const upsertPair = db.prepare('INSERT INTO pairings (fub_id, cal_uid, created_at, updated_at) VALUES (?, ?, ?, ?) ON CONFLICT(fub_id) DO UPDATE SET cal_uid = excluded.cal_uid, updated_at = excluded.updated_at');

const getMapping = db.prepare('SELECT key, label, event_type_id FROM mapping ORDER BY key');
const setMapping = db.prepare('INSERT INTO mapping (key, label, event_type_id) VALUES (?, ?, ?) ON CONFLICT(key) DO UPDATE SET label = excluded.label, event_type_id = excluded.event_type_id');

function normalizeKey(s) {
  return (s || '').toLowerCase().replace(/[\s\.,_\-]+/g, '').trim();
}

function mapLocation(locRaw) {
  const candidates = new Map();
  for (const row of getMapping.all()) candidates.set(row.key, { id: row.event_type_id, label: row.label });
  const synonyms = new Map([
    ['etob', 'etobicokeoffice'],
    ['eto', 'etobicokeoffice'],
    ['gmeet', 'googlemeet'],
    ['gm', 'googlemeet']
  ]);
  const k0 = normalizeKey(locRaw);
  const k = synonyms.get(k0) || k0;
  const rec = candidates.get(k) || { id: DEFAULT_EVENT_TYPE_ID, label: 'Zoom' };
  if (!candidates.get(k)) {
    log({ direction: 'App', action: 'mapping-default', message: `Unmapped location '${locRaw}' → default ${rec.id}` });
  }
  return { eventTypeId: rec.id, eventTypeLabel: rec.label, key: k };
}

function verifyHmacSHA256(raw, secret, signature) {
  if (!secret) return true;
  if (!signature) return false;
  const mac = crypto.createHmac('sha256', secret).update(raw).digest('hex');
  const sig = signature.replace(/^sha256=/, '');
  try {
    return crypto.timingSafeEqual(Buffer.from(mac, 'hex'), Buffer.from(sig, 'hex'));
  } catch { return false; }
}

app.post('/webhooks/cal', (req, res) => {
  const sig = req.header('x-cal-signature-256');
  if (!verifyHmacSHA256(req.rawBody || Buffer.from(''), CAL_WEBHOOK_SECRET, sig)) {
    return res.status(401).send('Invalid signature');
  }
  try {
    const payload = JSON.parse((req.rawBody || Buffer.from('{}')).toString('utf8'));
    const kind = payload?.type || payload?.event || payload?.kind || 'UNKNOWN';
    const uid = payload?.booking?.uid || payload?.uid;
    const when = payload?.booking?.start || payload?.newStartUTC || null;
    if (!uid) return res.status(400).send('Missing booking uid');
    enqueue('CAL_EVENT', { kind, calUid: uid, newStartUTC: when });
    log({ direction: 'Cal→App', action: kind, message: `Webhook enqueued for uid ${uid}` });
    res.sendStatus(200);
  } catch (e) {
    res.status(400).send('Bad JSON');
  }
});

app.post('/webhooks/fub', (req, res) => {
  const sig = req.header('x-fub-signature-256');
  if (FUB_WEBHOOK_SECRET && !verifyHmacSHA256(req.rawBody || Buffer.from(''), FUB_WEBHOOK_SECRET, sig)) {
    return res.status(401).send('Invalid signature');
  }
  try {
    const payload = JSON.parse((req.rawBody || Buffer.from('{}')).toString('utf8'));
    const type = payload?.type || payload?.event || 'UNKNOWN';
    const appointmentId = payload?.appointmentId || payload?.id;
    if (!appointmentId) return res.status(400).send('Missing appointment id');
    enqueue('FUB_APPT_UPSERT', { appointmentId, source: type });
    log({ direction: 'FUB→App', action: type, message: `Webhook enqueued for appt ${appointmentId}` });
    res.sendStatus(200);
  } catch (e) {
    res.status(400).send('Bad JSON');
  }
});

app.get('/api/healthz', (req, res) => res.json({ ok: true }));

app.get('/api/status', (req, res) => {
  const jobsPending = db.prepare("SELECT COUNT(*) as c FROM jobs WHERE status='pending'").get().c;
  const jobsFailed = db.prepare("SELECT COUNT(*) as c FROM jobs WHERE status='failed'").get().c;
  const jobsDone = db.prepare("SELECT COUNT(*) as c FROM jobs WHERE status='done'").get().c;
  const pairs = db.prepare('SELECT COUNT(*) as c FROM pairings').get().c;
  res.json({ ok: true, jobsPending, jobsFailed, jobsDone, pairs, time: new Date().toISOString() });
});

app.get('/api/logs', (req, res) => {
  const rows = db.prepare('SELECT * FROM logs ORDER BY ts DESC LIMIT 200').all();
  res.json(rows);
});

app.get('/api/jobs', (req, res) => {
  const rows = db.prepare('SELECT * FROM jobs ORDER BY created_at DESC LIMIT 200').all();
  res.json(rows.map(r => ({ ...r, payload: JSON.parse(r.payload) })));
});

app.post('/api/jobs/replay/:id', (req, res) => {
  const j = db.prepare('SELECT * FROM jobs WHERE id = ?').get(req.params.id);
  if (!j) return res.status(404).json({ error: 'not found' });
  if (j.status !== 'failed') return res.status(400).json({ error: 'only failed jobs can be replayed' });
  db.prepare("UPDATE jobs SET status='pending', attempts=0, next_attempt_at=?, updated_at=? WHERE id=?").run(now(), now(), j.id);
  res.json({ ok: true });
});

app.get('/api/pairs', (req, res) => {
  const rows = db.prepare('SELECT * FROM pairings ORDER BY created_at DESC LIMIT 200').all();
  res.json(rows);
});

app.get('/api/mapping', (req, res) => {
  const rows = getMapping.all();
  res.json(rows);
});

app.put('/api/mapping', express.json(), (req, res) => {
  const list = req.body;
  if (!Array.isArray(list)) return res.status(400).json({ error: 'array expected' });
  const tx = db.transaction((items) => {
    items.forEach(({ key, label, event_type_id }) => setMapping.run(String(key), String(label || ''), Number(event_type_id)));
  });
  tx(list);
  res.json({ ok: true });
});

app.post('/api/fub/sync/:id', (req, res) => {
  enqueue('FUB_APPT_UPSERT', { appointmentId: req.params.id, source: 'manual' });
  res.json({ ok: true });
});

async function fubGetAppointment(id) {
  const r = await fetch(`https://api.followupboss.com/v1/appointments/${id}`, {
    headers: { Authorization: 'Basic ' + Buffer.from(`${FUB_API_KEY}:`).toString('base64') }
  });
  if (!r.ok) throw new Error(`FUB GET ${id} ${r.status}`);
  return r.json();
}

async function fubUpdateAppointment(id, body) {
  const r = await fetch(`https://api.followupboss.com/v1/appointments/${id}`, {
    method: 'PUT',
    headers: {
      'Content-Type': 'application/json',
      Authorization: 'Basic ' + Buffer.from(`${FUB_API_KEY}:`).toString('base64')
    },
    body: JSON.stringify(body)
  });
  if (!r.ok) throw new Error(`FUB PUT ${id} ${r.status}`);
  return r.json();
}

async function calCreateBooking(payload) {
  const r = await fetch('https://api.cal.com/v2/bookings', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${CAL_API_KEY}`,
      'cal-api-version': CAL_API_VERSION
    },
    body: JSON.stringify(payload)
  });
  if (!r.ok) throw new Error(`Cal POST /bookings ${r.status}`);
  return r.json();
}

async function calCancelBooking(uid) {
  const r = await fetch(`https://api.cal.com/v2/bookings/${uid}/cancel`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${CAL_API_KEY}`,
      'cal-api-version': CAL_API_VERSION
    }
  });
  if (!r.ok) throw new Error(`Cal cancel ${uid} ${r.status}`);
  return r.json();
}

async function processJob(job) {
  const payload = JSON.parse(job.payload);
  try {
    if (job.kind === 'FUB_APPT_UPSERT') {
      const apptId = String(payload.appointmentId);
      const appt = await fubGetAppointment(apptId);
      const contact = appt?.person || appt?.contact || {};
      const name = contact.name || `${contact.firstName || ''} ${contact.lastName || ''}`.trim();
      const email = contact.email || (Array.isArray(contact.emails) ? contact.emails[0] : '');
      const phone = contact.phone || (Array.isArray(contact.phones) ? contact.phones[0] : '');
      const locationRaw = appt.location || appt.address || appt.title || '';
      const startISO = appt.start || appt.startTime || appt.startsAt;
      const endISO = appt.end || appt.endTime || appt.endsAt;
      const lengthMin = startISO && endISO ? Math.round((new Date(endISO) - new Date(startISO)) / 60000) : (appt.lengthInMinutes || 60);
      const tz = appt.timezone || 'America/Toronto';
      const { eventTypeId, eventTypeLabel, key } = mapLocation(locationRaw);
      const existing = getPairByFub.get(apptId);
      if (!existing) {
        const created = await calCreateBooking({
          start: startISO,
          lengthInMinutes: lengthMin,
          eventTypeId,
          attendee: { name, email, phoneNumber: phone, timeZone: tz },
          metadata: { fubAppointmentId: apptId, eventTypeId, eventTypeLabel, locationKey: key }
        });
        const calUid = created?.booking?.uid || created?.uid || created?.id;
        if (!calUid) throw new Error('Cal response missing uid');
        upsertPair.run(apptId, calUid, now(), now());
        try { await fubUpdateAppointment(apptId, { description: `${appt.description || ''}\nCalUID: ${calUid}`.trim() }); } catch {}
        log({ direction: 'FUB→Cal', action: 'create', message: `Created booking ${calUid} (type ${eventTypeId}/${eventTypeLabel}) for FUB ${apptId} [loc:${key}]` });
      } else {
        try { await calCancelBooking(existing.cal_uid); } catch {}
        const created = await calCreateBooking({
          start: startISO, lengthInMinutes: lengthMin, eventTypeId,
          attendee: { name, email, phoneNumber: phone, timeZone: tz },
          metadata: { fubAppointmentId: apptId, eventTypeId, eventTypeLabel, locationKey: key }
        });
        const calUid = created?.booking?.uid || created?.uid || created?.id;
        upsertPair.run(apptId, calUid, now(), now());
        try { await fubUpdateAppointment(apptId, { description: `${appt.description || ''}\nCalUID: ${calUid}`.trim() }); } catch {}
        log({ direction: 'FUB→Cal', action: 'update', message: `Replaced booking ${existing.cal_uid} → ${calUid} for FUB ${apptId}` });
      }
    }
    if (job.kind === 'CAL_EVENT') {
      const { kind, calUid, newStartUTC } = payload;
      const pair = getPairByCal.get(calUid);
      if (!pair) { log({ direction: 'Cal→App', action: 'orphan', message: `No pairing for ${calUid}` }); return; }
      const fubId = pair.fub_id;
      if (String(kind).toUpperCase().includes('RESCHEDULE')) {
        await fubUpdateAppointment(fubId, { start: newStartUTC });
        log({ direction: 'Cal→FUB', action: 'reschedule', message: `Updated FUB ${fubId} from Cal ${calUid}` });
      } else if (String(kind).toUpperCase().includes('CANCEL')) {
        await fubUpdateAppointment(fubId, { status: 'cancelled' });
        log({ direction: 'Cal→FUB', action: 'cancel', message: `Cancelled FUB ${fubId} from Cal ${calUid}` });
      } else {
        log({ direction: 'Cal→FUB', action: 'ignore', message: `Unhandled Cal event ${kind} for ${calUid}` });
      }
    }
  } catch (e) {
    throw e;
  }
}

async function workerLoop() {
  try {
    const job = pickJob.get(now());
    if (!job) return;
    try {
      await processJob(job);
      finishJob.run(now(), job.id);
    } catch (err) {
      const attempts = job.attempts + 1;
      if (attempts > MAX_RETRIES) {
        failJob.run(String(err), now(), job.id);
        log({ direction: 'App', action: 'DLQ', message: `Job ${job.id} failed permanently: ${err}` });
      } else {
        const delay = BACKOFF_BASE_MS * Math.pow(2, attempts - 1) + Math.floor(Math.random() * 200);
        updJobAttempt.run(attempts, now() + delay, now(), job.id);
      }
    }
  } catch (e) {}
}
setInterval(workerLoop, 300);

app.listen(PORT, () => {
  console.log(`FUB↔Cal server listening on :${PORT}`);
});
