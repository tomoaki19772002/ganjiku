const crypto = require('crypto');

const REDIS_URL = process.env.UPSTASH_REDIS_REST_URL || process.env.KV_REST_API_URL;
const REDIS_TOKEN = process.env.UPSTASH_REDIS_REST_TOKEN || process.env.KV_REST_API_TOKEN;
const ACCESS_KEY = process.env.ACCESS_KEY;
const DATA_KEY = process.env.DATA_KEY;

async function redis(cmd) {
  const r = await fetch(REDIS_URL, {
    method: 'POST',
    headers: { Authorization: 'Bearer ' + REDIS_TOKEN, 'Content-Type': 'application/json' },
    body: JSON.stringify(cmd),
  });
  const j = await r.json();
  if (!r.ok || j.error) throw new Error(j.error || 'redis ' + r.status);
  return j.result;
}

const sha = (s) => crypto.createHash('sha256').update(s).digest();
const sameKey = (a, b) => crypto.timingSafeEqual(sha(a), sha(b));
const recordKey = (id) => 'ganjiku:' + crypto.createHmac('sha256', DATA_KEY).update(id).digest('hex');

function encrypt(obj) {
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', sha('enc:' + DATA_KEY), iv);
  const ct = Buffer.concat([c.update(JSON.stringify(obj), 'utf8'), c.final()]);
  return Buffer.concat([iv, c.getAuthTag(), ct]).toString('base64');
}
function decrypt(b64) {
  const buf = Buffer.from(b64, 'base64');
  const d = crypto.createDecipheriv('aes-256-gcm', sha('enc:' + DATA_KEY), buf.subarray(0, 12));
  d.setAuthTag(buf.subarray(12, 28));
  return JSON.parse(Buffer.concat([d.update(buf.subarray(28)), d.final()]).toString('utf8'));
}

const str = (v, n) => String(v == null ? '' : v).slice(0, n);
function clean(rec) {
  const rows = Array.isArray(rec.rows) ? rec.rows.slice(0, 100) : [];
  return {
    sex: rec.sex === 'f' ? 'f' : 'm',
    name: str(rec.name, 60),
    birth: str(rec.birth, 10),
    treat: str(rec.treat, 100),
    startId: Number.isFinite(rec.startId) ? rec.startId : null,
    next: Number.isFinite(rec.next) ? rec.next : rows.length + 1,
    rows: rows.map((r) => ({ id: Number(r.id) || 0, ym: str(r.ym, 7), r: str(r.r, 8), l: str(r.l, 8) })),
  };
}

module.exports = async (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  const missing = [
    ['ACCESS_KEY', ACCESS_KEY], ['DATA_KEY', DATA_KEY], ['REDIS_URL', REDIS_URL], ['REDIS_TOKEN', REDIS_TOKEN],
  ].filter((x) => !x[1]).map((x) => x[0]);
  if (missing.length) return res.status(500).json({ error: '環境変数が未設定です: ' + missing.join(', ') });

  const given = req.headers['x-access-key'];
  if (typeof given !== 'string' || !sameKey(given, ACCESS_KEY)) return res.status(401).json({ error: 'unauthorized' });

  try {
    if (req.method === 'GET') {
      const id = String(req.query.id || '');
      if (!/^[A-Za-z0-9_-]{1,32}$/.test(id)) return res.status(400).json({ error: 'IDは英数字・-・_ の32文字以内です' });
      const v = await redis(['GET', recordKey(id)]);
      if (!v) return res.status(404).json({ error: 'not_found' });
      return res.status(200).json({ record: decrypt(v) });
    }
    if (req.method === 'PUT') {
      const body = typeof req.body === 'string' ? JSON.parse(req.body) : req.body || {};
      const id = String(body.id || '');
      if (!/^[A-Za-z0-9_-]{1,32}$/.test(id)) return res.status(400).json({ error: 'IDは英数字・-・_ の32文字以内です' });
      if (!body.record || typeof body.record !== 'object') return res.status(400).json({ error: 'record がありません' });
      const key = recordKey(id);
      const cur = await redis(['GET', key]);
      const curRec = cur ? decrypt(cur) : null;
      if (curRec && Number(body.baseRev) !== curRec.rev) return res.status(409).json({ error: 'conflict' });
      const rec = { ...clean(body.record), rev: (curRec ? curRec.rev : 0) + 1, updatedAt: new Date().toISOString() };
      await redis(['SET', key, encrypt(rec)]);
      return res.status(200).json({ rev: rec.rev, updatedAt: rec.updatedAt });
    }
    res.setHeader('Allow', 'GET, PUT');
    return res.status(405).json({ error: 'method not allowed' });
  } catch (e) {
    return res.status(500).json({ error: 'server error' });
  }
};
