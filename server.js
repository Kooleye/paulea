'use strict'

/**
 * Telegram Mini App — витрина магазина одежды.
 * Заказы без онлайн-оплаты: клиент оставляет заявку, менеджер связывается сам.
 *
 * Зависимостей нет. Нужен только Node.js 18+.
 * Запуск:  node server.js
 */

const http = require('node:http')
const fs = require('node:fs')
const path = require('node:path')
const crypto = require('node:crypto')
const zlib = require('node:zlib')

const ROOT = __dirname
const PUBLIC_DIR = path.join(ROOT, 'public')
const DATA_DIR = path.join(ROOT, 'data')
const DB_PATH = path.join(DATA_DIR, 'db.json')

// ---------------------------------------------------------------- окружение

function loadEnv() {
  const file = path.join(ROOT, '.env')
  if (!fs.existsSync(file)) return
  for (const rawLine of fs.readFileSync(file, 'utf8').split('\n')) {
    const line = rawLine.trim()
    if (!line || line.startsWith('#')) continue
    const eq = line.indexOf('=')
    if (eq === -1) continue
    const key = line.slice(0, eq).trim()
    let value = line.slice(eq + 1).trim()
    if (
      (value.startsWith('"') && value.endsWith('"')) ||
      (value.startsWith("'") && value.endsWith("'"))
    ) {
      value = value.slice(1, -1)
    }
    if (!(key in process.env)) process.env[key] = value
  }
}

loadEnv()

const PORT = Number(process.env.PORT || 3000)
const BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN || ''
const MANAGER_CHAT_ID = process.env.TELEGRAM_MANAGER_CHAT_ID || ''
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'admin'
const ALLOW_BROWSER = String(process.env.ALLOW_BROWSER || 'true') === 'true'

// ---------------------------------------------------------------- S3-хранилище
// Фото товаров, баннеры и база db.json могут храниться в облачном S3-хранилище
// (Timeweb S3 или любое S3-совместимое). Это нужно, чтобы данные НЕ пропадали
// при пересборке приложения на App Platform (там контейнер пересоздаётся с нуля).
//
// Бакет держим ПРИВАТНЫМ: в базе есть телефоны и заявки клиентов — они не должны
// быть доступны публично. Картинки отдаём не напрямую из S3, а через наш сервер
// (маршруты /photos/... и /banners/...), подписывая запросы к приватному бакету.
//
// Если переменные S3 не заданы — всё работает по-старому, из локальных файлов.

const S3 = {
  endpoint: (process.env.S3_ENDPOINT || 'https://s3.twcstorage.ru').replace(/\/+$/, ''),
  region: process.env.S3_REGION || 'ru-1',
  bucket: process.env.S3_BUCKET || '',
  accessKey: process.env.S3_ACCESS_KEY || '',
  secretKey: process.env.S3_SECRET_KEY || '',
}
const S3_ENABLED = Boolean(S3.endpoint && S3.bucket && S3.accessKey && S3.secretKey)

function sha256hex(data) {
  return crypto.createHash('sha256').update(data).digest('hex')
}
function hmac(key, data) {
  return crypto.createHmac('sha256', key).update(data).digest()
}

// Подпись запроса к S3 по протоколу AWS Signature V4 — без сторонних библиотек.
async function s3Request(method, key, { body = '', contentType, query = '' } = {}) {
  const host = new URL(S3.endpoint).host
  const amzDate = new Date().toISOString().replace(/[:-]|\.\d{3}/g, '') // YYYYMMDDTHHMMSSZ
  const dateStamp = amzDate.slice(0, 8)

  const payload = Buffer.isBuffer(body) ? body : Buffer.from(body)
  const payloadHash = sha256hex(payload)

  const encodedKey = String(key).split('/').map(encodeURIComponent).join('/')
  const canonicalUri = '/' + S3.bucket + '/' + encodedKey

  const headers = {
    host,
    'x-amz-content-sha256': payloadHash,
    'x-amz-date': amzDate,
  }
  if (contentType) headers['content-type'] = contentType

  const sortedNames = Object.keys(headers).sort()
  const signedHeaders = sortedNames.join(';')
  const canonicalHeaders = sortedNames
    .map((h) => h + ':' + String(headers[h]).trim() + '\n')
    .join('')

  const canonicalRequest = [
    method,
    canonicalUri,
    query,
    canonicalHeaders,
    signedHeaders,
    payloadHash,
  ].join('\n')

  const scope = dateStamp + '/' + S3.region + '/s3/aws4_request'
  const stringToSign = ['AWS4-HMAC-SHA256', amzDate, scope, sha256hex(canonicalRequest)].join('\n')

  const kDate = hmac('AWS4' + S3.secretKey, dateStamp)
  const kRegion = hmac(kDate, S3.region)
  const kService = hmac(kRegion, 's3')
  const kSigning = hmac(kService, 'aws4_request')
  const signature = crypto.createHmac('sha256', kSigning).update(stringToSign).digest('hex')

  const authorization =
    'AWS4-HMAC-SHA256 Credential=' + S3.accessKey + '/' + scope +
    ', SignedHeaders=' + signedHeaders +
    ', Signature=' + signature

  const sendHeaders = {
    'x-amz-content-sha256': payloadHash,
    'x-amz-date': amzDate,
    Authorization: authorization,
  }
  if (contentType) sendHeaders['content-type'] = contentType

  const url = S3.endpoint + canonicalUri + (query ? '?' + query : '')
  return fetch(url, {
    method,
    headers: sendHeaders,
    body: method === 'GET' || method === 'DELETE' ? undefined : payload,
  })
}

async function s3Put(key, buffer, contentType) {
  const res = await s3Request('PUT', key, { body: buffer, contentType })
  if (!res.ok) {
    const text = await res.text().catch(() => '')
    throw new Error('S3 PUT ' + key + ' → ' + res.status + ' ' + text.slice(0, 200))
  }
}
async function s3Get(key) {
  const res = await s3Request('GET', key)
  if (res.status === 404 || res.status === 403) return null
  if (!res.ok) throw new Error('S3 GET ' + key + ' → ' + res.status)
  return Buffer.from(await res.arrayBuffer())
}
async function s3Delete(key) {
  const res = await s3Request('DELETE', key)
  if (!res.ok && res.status !== 404) throw new Error('S3 DELETE ' + key + ' → ' + res.status)
}
async function s3List(prefix) {
  const res = await s3Request('GET', '', { query: 'list-type=2&prefix=' + encodeURIComponent(prefix) })
  if (!res.ok) throw new Error('S3 LIST → ' + res.status)
  const xml = await res.text()
  const keys = []
  const re = /<Key>([^<]+)<\/Key>/g
  let m
  while ((m = re.exec(xml))) keys.push(m[1])
  return keys
}

// Отдаём картинку из приватного S3 через наш сервер (с кэшированием в браузере).
// Если объекта в S3 нет — пробуем локальный файл (например, placeholder.svg).
async function serveS3Object(req, res, pathname) {
  const key = decodeURIComponent(pathname.replace(/^\//, ''))
  try {
    const s3res = await s3Request('GET', key)
    if (!s3res.ok) return serveStatic(req, res, pathname)
    const buf = Buffer.from(await s3res.arrayBuffer())
    const ext = path.extname(key).toLowerCase()
    const mime = MIME[ext] || s3res.headers.get('content-type') || 'application/octet-stream'
    const etag = s3res.headers.get('etag') || '"' + sha256hex(buf).slice(0, 24) + '"'
    if (req.headers['if-none-match'] === etag) {
      res.writeHead(304, { ETag: etag, 'Cache-Control': 'public, max-age=86400' })
      return res.end()
    }
    res.writeHead(200, {
      'Content-Type': mime,
      'Cache-Control': 'public, max-age=86400',
      ETag: etag,
      'Content-Length': buf.length,
    })
    res.end(buf)
  } catch (err) {
    console.error('S3 proxy:', err.message)
    if (!res.writableEnded) res.writeHead(502).end('Storage error')
  }
}

// ---------------------------------------------------------------- база (JSON)

// Стартовая база: используется, если файла data/db.json ещё нет.
// Так витрина никогда не падает с ошибкой на пустом сервере.
function defaultDb() {
  return {
    shop: {
      name: 'PAULEA',
      currency: '₽',
      contactTelegram: '',
      address: '',
      workingHours: '',
      delivery: '',
      lastSizeBadge: { enabled: true, text: 'Последний размер' },
    },
    categories: [{ id: 'cat_start', name: 'Новинки', sortOrder: 1, isActive: true }],
    products: [],
    banners: [],
    orders: [],
    orderCounter: 0,
  }
}

function ensureDataDir() {
  if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true })
}

let db = null

// Загружаем базу при старте. В режиме S3 читаем db.json из хранилища,
// иначе — из локального файла. Вызывается один раз перед запуском сервера.
async function initDb() {
  if (S3_ENABLED) {
    try {
      const buf = await s3Get('db.json')
      if (buf) {
        db = JSON.parse(buf.toString('utf8'))
        console.log('  ☁️   База загружена из S3-хранилища.')
      } else {
        db = defaultDb()
        await s3Put('db.json', Buffer.from(JSON.stringify(db, null, 2)), 'application/json; charset=utf-8')
        console.log('  ☁️   В S3 создана новая база db.json.')
      }
      return
    } catch (err) {
      console.error('  ⚠️   Не удалось прочитать базу из S3:', err.message)
      console.error('       Работаю на локальной базе — данные могут не сохраниться между пересборками!')
    }
  }
  readDb()
}

function readDb() {
  if (db) return db
  try {
    db = JSON.parse(fs.readFileSync(DB_PATH, 'utf8'))
  } catch {
    // Файла нет или он повреждён — поднимаем стартовую базу и сохраняем её.
    db = defaultDb()
    try {
      ensureDataDir()
      fs.writeFileSync(DB_PATH, JSON.stringify(db, null, 2), 'utf8')
      console.log('  ℹ️   Создан новый data/db.json (файла не было).')
    } catch (err) {
      console.error('Не удалось создать data/db.json:', err.message)
    }
  }
  return db
}

// Очередь записи в S3, чтобы сохранения не наезжали друг на друга.
let s3SaveChain = Promise.resolve()

function saveDb() {
  // Локальная копия — быстрый кэш в пределах текущего контейнера.
  try {
    ensureDataDir()
    const tmp = DB_PATH + '.tmp'
    fs.writeFileSync(tmp, JSON.stringify(db, null, 2), 'utf8')
    fs.renameSync(tmp, DB_PATH)
  } catch (err) {
    console.error('Локальное сохранение db.json не удалось:', err.message)
  }
  // Постоянное хранение в S3.
  if (S3_ENABLED) {
    const snapshot = Buffer.from(JSON.stringify(db, null, 2))
    s3SaveChain = s3SaveChain
      .then(() => s3Put('db.json', snapshot, 'application/json; charset=utf-8'))
      .catch((err) => console.error('  ⚠️   Сохранение базы в S3 не удалось:', err.message))
  }
}

function nextId(prefix) {
  return prefix + '_' + Date.now().toString(36) + crypto.randomBytes(3).toString('hex')
}

// ------------------------------------------------- проверка подписи Telegram

/**
 * Telegram передаёт в мини-апп строку initData с HMAC-подписью.
 * Ей нельзя доверять без проверки: иначе кто угодно отправит заявку от чужого имени.
 * Документация: https://core.telegram.org/bots/webapps#validating-data-received-via-the-mini-app
 */
function verifyInitData(initData) {
  if (!initData) return null
  if (!BOT_TOKEN) return null

  const params = new URLSearchParams(initData)
  const hash = params.get('hash')
  if (!hash) return null
  params.delete('hash')

  const dataCheckString = [...params.entries()]
    .map(([k, v]) => `${k}=${v}`)
    .sort()
    .join('\n')

  const secretKey = crypto.createHmac('sha256', 'WebAppData').update(BOT_TOKEN).digest()
  const computed = crypto.createHmac('sha256', secretKey).update(dataCheckString).digest('hex')

  if (computed !== hash) return null

  const authDate = Number(params.get('auth_date') || 0)
  if (!authDate || Date.now() / 1000 - authDate > 86400) return null

  try {
    return JSON.parse(params.get('user') || 'null')
  } catch {
    return null
  }
}

// ------------------------------------------------------------- уведомления

function escapeHtml(text) {
  return String(text).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
}

async function sendTelegram(chatId, text) {
  if (!BOT_TOKEN || !chatId) return false
  try {
    const api = 'https' + '://api.telegram.org/bot' + BOT_TOKEN + '/sendMessage'
    const res = await fetch(api, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        chat_id: chatId,
        text,
        parse_mode: 'HTML',
        disable_web_page_preview: true,
      }),
    })
    const json = await res.json()
    if (!json.ok) console.error('Telegram API:', json.description)
    return json.ok === true
  } catch (err) {
    console.error('Не удалось отправить сообщение в Telegram:', err.message)
    return false
  }
}

function formatOrderForManager(order) {
  const lines = []
  lines.push(`<b>🛍 Новая заявка ${escapeHtml(order.number)}</b>`)
  lines.push('')
  for (const item of order.items) {
    lines.push(
      `• ${escapeHtml(item.title)} — размер <b>${escapeHtml(item.size)}</b> × ${item.qty} — ${item.price * item.qty} ₽`,
    )
  }
  lines.push('')
  lines.push(`<b>Итого: ${order.total} ₽</b>`)
  lines.push('')
  lines.push(`Клиент: ${escapeHtml(order.customer.name || '—')}`)
  if (order.customer.username) lines.push(`Telegram: @${escapeHtml(order.customer.username)}`)
  if (order.customer.phone) lines.push(`Телефон: ${escapeHtml(order.customer.phone)}`)
  if (order.customer.telegram) lines.push(`Telegram клиента: ${escapeHtml(order.customer.telegram)}`)
  if (order.comment) lines.push(`Комментарий: ${escapeHtml(order.comment)}`)
  return lines.join('\n')
}

// ------------------------------------------------------------------ хелперы

function json(res, status, payload) {
  const body = JSON.stringify(payload)
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
  })
  res.end(body)
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let raw = ''
    req.on('data', (chunk) => {
      raw += chunk
      if (raw.length > 12_000_000) reject(new Error('Слишком большой запрос'))
    })
    req.on('end', () => {
      try {
        resolve(raw ? JSON.parse(raw) : {})
      } catch {
        reject(new Error('Некорректный JSON'))
      }
    })
    req.on('error', reject)
  })
}

function isAdmin(req) {
  return req.headers['x-admin-password'] === ADMIN_PASSWORD
}

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.webp': 'image/webp',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon',
}

// Текстовые файлы сжимаются хорошо (в 3–5 раз), картинки — нет.
const COMPRESSIBLE = new Set(['.html', '.css', '.js', '.json', '.svg'])
const IMAGE_EXT = new Set(['.png', '.jpg', '.jpeg', '.webp', '.svg', '.ico'])

function serveStatic(req, res, pathname) {
  let rel = decodeURIComponent(pathname)
  if (rel === '/') rel = '/index.html'
  const filePath = path.join(PUBLIC_DIR, rel)
  if (!filePath.startsWith(PUBLIC_DIR)) {
    res.writeHead(403).end('Forbidden')
    return
  }
  fs.stat(filePath, (err, stat) => {
    if (err || !stat.isFile()) {
      res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' })
      res.end('Страница не найдена')
      return
    }

    const ext = path.extname(filePath).toLowerCase()
    const mime = MIME[ext] || 'application/octet-stream'

    // ETag по размеру и времени изменения: браузер не скачивает файл заново,
    // если он не менялся — это сильно ускор��ет ��овторные открытия.
    const etag = '"' + stat.size.toString(16) + '-' + Math.round(stat.mtimeMs).toString(16) + '"'

    // Сколько держать файл в кэше браузера.
    let cacheControl
    if (ext === '.html') {
      cacheControl = 'no-cache' // HTML всегда сверяем с сервером
    } else if (IMAGE_EXT.has(ext)) {
      cacheControl = 'public, max-age=86400' // картинки — сутки
    } else {
      cacheControl = 'public, max-age=3600' // css/js — час
    }

    // У браузера уже есть свежая копия — отвечаем 304 без тела.
    if (req.headers['if-none-match'] === etag) {
      res.writeHead(304, { ETag: etag, 'Cache-Control': cacheControl })
      res.end()
      return
    }

    const headers = {
      'Content-Type': mime,
      'Cache-Control': cacheControl,
      ETag: etag,
    }

    // Сжатие текстовых файлов (gzip/br/deflate) — страница открывается
    // заметно быстрее. Модуль zlib встроен в Node, зависимостей не нужно.
    const acceptEncoding = String(req.headers['accept-encoding'] || '')
    let encoding = null
    if (COMPRESSIBLE.has(ext)) {
      if (/\bbr\b/.test(acceptEncoding)) encoding = 'br'
      else if (/\bgzip\b/.test(acceptEncoding)) encoding = 'gzip'
      else if (/\bdeflate\b/.test(acceptEncoding)) encoding = 'deflate'
    }

    const stream = fs.createReadStream(filePath)
    // Клиент может оборвать соединение (мобильный интернет, VPN) —
    // тихо закрываем поток и не роняем сервер.
    stream.on('error', () => { if (!res.writableEnded) res.end() })
    res.on('close', () => stream.destroy())

    if (encoding) {
      headers['Content-Encoding'] = encoding
      headers['Vary'] = 'Accept-Encoding'
      res.writeHead(200, headers)
      const compressor =
        encoding === 'br'
          ? zlib.createBrotliCompress({ params: { [zlib.constants.BROTLI_PARAM_QUALITY]: 5 } })
          : encoding === 'gzip'
            ? zlib.createGzip()
            : zlib.createDeflate()
      compressor.on('error', () => { if (!res.writableEnded) res.end() })
      stream.pipe(compressor).pipe(res)
    } else {
      headers['Content-Length'] = stat.size
      res.writeHead(200, headers)
      stream.pipe(res)
    }
  })
}

// ------------------------------------------------------------------- каталог

function publicCatalog() {
  const data = readDb()
  const categories = data.categories
    .filter((c) => c.isActive !== false)
    .sort((a, b) => a.sortOrder - b.sortOrder)

  const products = data.products
    .filter((p) => p.isActive !== false)
    .map((p) => ({
      ...p,
      inStock: p.variants.some((v) => v.stock > 0),
    }))

  const banners = (data.banners || []).filter((b) => b.isActive !== false)

  const badge = (data.shop && data.shop.lastSizeBadge) || {}
  const shop = {
    ...data.shop,
    lastSizeBadge: {
      enabled: badge.enabled !== false,
      text: String(badge.text || 'Последний размер').slice(0, 40),
    },
  }

  return { shop, categories, products, banners }
}

// -------------------------------------------------------------------- заявки

async function createOrder(req, res) {
  const body = await readBody(req)
  const data = readDb()

  const tgUser = verifyInitData(body.initData)
  if (!tgUser && !ALLOW_BROWSER) {
    return json(res, 401, { error: 'Откройте приложение внутри Telegram' })
  }

  const items = Array.isArray(body.items) ? body.items : []
  if (items.length === 0) return json(res, 400, { error: 'Корзина пуста' })

  const resolved = []
  for (const line of items) {
    const product = data.products.find((p) => p.id === line.productId)
    if (!product) return json(res, 400, { error: 'Товар не найден' })
    const variant = product.variants.find((v) => v.size === line.size)
    if (!variant) return json(res, 400, { error: 'Размер не найден' })

    const qty = Math.max(1, Math.min(Number(line.qty) || 1, variant.stock || 1))
    if (!variant.stock) {
      return json(res, 409, { error: `«${product.name}» в размере ${variant.size} уже нет в наличии` })
    }

    // Цену всегда берём из базы, а не из корзины клиента.
    resolved.push({
      productId: product.id,
      title: product.name,
      size: variant.size,
      qty,
      price: product.price,
    })
  }

  const total = resolved.reduce((sum, i) => sum + i.price * i.qty, 0)
  const number = '#' + String(data.orderCounter + 1).padStart(4, '0')

  const order = {
    id: nextId('ord'),
    number,
    createdAt: new Date().toISOString(),
    status: 'new',
    customer: {
      tgId: tgUser ? tgUser.id : null,
      name:
        String(body.name || '').trim().slice(0, 80) ||
        (tgUser ? [tgUser.first_name, tgUser.last_name].filter(Boolean).join(' ') : '') ||
        'Без имени',
      username: tgUser ? tgUser.username || '' : '',
      phone: String(body.phone || '').slice(0, 32),
      telegram: String(body.telegram || '').slice(0, 64),
    },
    comment: String(body.comment || '').slice(0, 500),
    items: resolved,
    total,
  }

  // Списываем остатки: купленный размер сразу уходит с витрины
  for (const item of resolved) {
    const product = data.products.find((p) => p.id === item.productId)
    if (!product) continue
    const variant = product.variants.find((v) => v.size === item.size)
    if (!variant) continue
    variant.stock = Math.max(0, (Number(variant.stock) || 0) - item.qty)
  }
  order.stockApplied = true

  data.orders.unshift(order)
  data.orderCounter += 1
  saveDb()

  const sent = await sendTelegram(MANAGER_CHAT_ID, formatOrderForManager(order))
  if (!sent) {
    console.log('\n--- НОВАЯ ЗАЯВКА (Telegram не настроен, показываю здесь) ---')
    console.log(formatOrderForManager(order).replace(/<[^>]+>/g, ''))
    console.log('------------------------------------------------------------\n')
  }

  // Автоответ клиенту в Telegram не отправляем: подтверждение он
  // видит на самой витрине, а в бот уходит только уведомление менеджеру.

  return json(res, 200, { ok: true, number: order.number, total })
}

// ------------------------------------------------------------------- роутинг

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http' + '://' + req.headers.host)
  const { pathname } = url

  try {
    if (pathname === '/api/catalog' && req.method === 'GET') {
      return json(res, 200, publicCatalog())
    }

    if (pathname === '/api/orders' && req.method === 'POST') {
      return await createOrder(req, res)
    }

    // ------------------------------------------------------------- админка
    if (pathname.startsWith('/api/admin/')) {
      if (!isAdmin(req)) return json(res, 401, { error: 'Неверный пароль' })
      const data = readDb()

      if (pathname === '/api/admin/state' && req.method === 'GET') {
        let photos = []
        if (S3_ENABLED) {
          try {
            photos = (await s3List('photos/'))
              .filter((k) => /\.(png|jpe?g|webp)$/i.test(k))
              .map((k) => '/' + k)
          } catch (err) {
            console.error('S3 list photos:', err.message)
          }
        } else if (fs.existsSync(path.join(PUBLIC_DIR, 'photos'))) {
          photos = fs
            .readdirSync(path.join(PUBLIC_DIR, 'photos'))
            .filter((f) => /\.(png|jpe?g|webp)$/i.test(f))
            .map((f) => '/photos/' + f)
        }
        return json(res, 200, {
          shop: data.shop,
          categories: data.categories,
          products: data.products,
          orders: data.orders,
          banners: data.banners || [],
          photos,
          telegramConfigured: Boolean(BOT_TOKEN && MANAGER_CHAT_ID),
        })
      }

      // Настройки плашки «Последний размер»
      if (pathname === '/api/admin/last-size-badge' && req.method === 'POST') {
        const body = await readBody(req)
        data.shop = data.shop || {}
        const text = String(body.text || '').slice(0, 40).trim()
        data.shop.lastSizeBadge = {
          enabled: body.enabled !== false,
          text: text || 'Последний размер',
        }
        saveDb()
        return json(res, 200, { ok: true, lastSizeBadge: data.shop.lastSizeBadge })
      }

      if (pathname === '/api/admin/order-status' && req.method === 'POST') {
        const body = await readBody(req)
        const order = data.orders.find((o) => o.id === body.id)
        if (!order) return json(res, 404, { error: 'Заявка не найдена' })
        const wasCancelled = order.status === 'cancelled'
        order.status = body.status

        // Отменили заявку — вещи возвращаются на витрину
        if (!wasCancelled && order.status === 'cancelled' && order.stockApplied) {
          for (const item of order.items) {
            const product = data.products.find((p) => p.id === item.productId)
            if (!product) continue
            const variant = product.variants.find((v) => v.size === item.size)
            if (!variant) continue
            variant.stock = Math.max(0, (Number(variant.stock) || 0) + item.qty)
          }
          order.stockApplied = false
        }

        // Сняли отмену — снова списываем
        if (wasCancelled && order.status !== 'cancelled' && !order.stockApplied) {
          for (const item of order.items) {
            const product = data.products.find((p) => p.id === item.productId)
            if (!product) continue
            const variant = product.variants.find((v) => v.size === item.size)
            if (!variant) continue
            variant.stock = Math.max(0, (Number(variant.stock) || 0) - item.qty)
          }
          order.stockApplied = true
        }

        saveDb()
        return json(res, 200, { ok: true })
      }

      if (pathname === '/api/admin/product' && req.method === 'POST') {
        const body = await readBody(req)
        const p = body.product
        if (!p || !p.name) return json(res, 400, { error: 'Нужно название товара' })

        const clean = {
          id: p.id || nextId('prd'),
          categoryId: p.categoryId,
          name: String(p.name).slice(0, 120),
          description: String(p.description || '').slice(0, 2000),
          composition: String(p.composition || '').slice(0, 200),
          price: Math.max(0, Number(p.price) || 0),
          oldPrice: p.oldPrice ? Number(p.oldPrice) : null,
          images: Array.isArray(p.images) ? p.images.slice(0, 8) : [],
          variants: (Array.isArray(p.variants) ? p.variants : []).map((v) => ({
            size: String(v.size).slice(0, 24),
            stock: Math.max(0, Number(v.stock) || 0),
          })),
          isActive: p.isActive !== false,
          isHit: p.isHit === true,
          isNew: p.isNew === true,
          color:
            p.color && p.color.name
              ? { name: String(p.color.name).slice(0, 40), hex: String(p.color.hex || '#cccccc').slice(0, 9) }
              : null,
          groupId: p.groupId ? String(p.groupId).slice(0, 40) : null,
        }

        // Мультикарточка: связываем цвета одного фасона в общую группу.
        if (Object.prototype.hasOwnProperty.call(p, 'linkToId')) {
          if (p.linkToId) {
            const other = data.products.find((x) => x.id === p.linkToId && x.id !== clean.id)
            if (other) {
              const gid = other.groupId || clean.groupId || nextId('grp')
              other.groupId = gid
              clean.groupId = gid
            }
          } else {
            clean.groupId = null
          }
        }

        const index = data.products.findIndex((x) => x.id === clean.id)
        if (index === -1) data.products.push(clean)
        else data.products[index] = clean

        saveDb()
        return json(res, 200, { ok: true, product: clean })
      }

      // Загрузка фото товара: браузер присылает картинку в base64.
      if (pathname === '/api/admin/photo-upload' && req.method === 'POST') {
        const body = await readBody(req)
        const match = String(body.dataUrl || '').match(/^data:image\/(png|jpeg|jpg|webp);base64,(.+)$/)
        if (!match) return json(res, 400, { error: 'Подойдёт файл PNG, JPG или WebP' })

        const ext = match[1] === 'jpeg' ? 'jpg' : match[1]
        const buffer = Buffer.from(match[2], 'base64')
        if (buffer.length > 8 * 1024 * 1024) return json(res, 400, { error: 'Файл больше 8 МБ' })

        const fileName = nextId('img') + '.' + ext
        if (S3_ENABLED) {
          await s3Put('photos/' + fileName, buffer, MIME['.' + ext] || 'image/' + match[1])
          return json(res, 200, { ok: true, image: '/photos/' + fileName })
        }

        const dir = path.join(PUBLIC_DIR, 'photos')
        if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true })
        fs.writeFileSync(path.join(dir, fileName), buffer)
        return json(res, 200, { ok: true, image: '/photos/' + fileName })
      }

      // Загрузка баннера с акцией: браузер присылает картинку в base64.
      if (pathname === '/api/admin/banner-upload' && req.method === 'POST') {
        const body = await readBody(req)
        const match = String(body.dataUrl || '').match(/^data:image\/(png|jpeg|jpg|webp);base64,(.+)$/)
        if (!match) return json(res, 400, { error: 'Подойдёт файл PNG, JPG или WebP' })

        const ext = match[1] === 'jpeg' ? 'jpg' : match[1]
        const buffer = Buffer.from(match[2], 'base64')
        if (buffer.length > 8 * 1024 * 1024) return json(res, 400, { error: 'Файл больше 8 МБ' })

        const fileName = nextId('bnr') + '.' + ext
        if (S3_ENABLED) {
          await s3Put('banners/' + fileName, buffer, MIME['.' + ext] || 'image/' + match[1])
        } else {
          const dir = path.join(PUBLIC_DIR, 'banners')
          if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true })
          fs.writeFileSync(path.join(dir, fileName), buffer)
        }

        const banner = {
          id: nextId('ban'),
          image: '/banners/' + fileName,
          link: String(body.link || '').slice(0, 200),
          isActive: true,
        }
        if (!data.banners) data.banners = []
        data.banners.push(banner)
        saveDb()
        return json(res, 200, { ok: true, banner })
      }

      if (pathname === '/api/admin/banner-delete' && req.method === 'POST') {
        const body = await readBody(req)
        const banner = (data.banners || []).find((b) => b.id === body.id)
        if (banner) {
          if (S3_ENABLED) {
            try { await s3Delete(banner.image.replace(/^\//, '')) } catch (err) { console.error('S3 delete:', err.message) }
          } else {
            const file = path.join(PUBLIC_DIR, banner.image.replace(/^\//, ''))
            if (file.startsWith(PUBLIC_DIR) && fs.existsSync(file)) fs.unlinkSync(file)
          }
          data.banners = data.banners.filter((b) => b.id !== body.id)
          saveDb()
        }
        return json(res, 200, { ok: true })
      }

      if (pathname === '/api/admin/product-delete' && req.method === 'POST') {
        const body = await readBody(req)
        data.products = data.products.filter((p) => p.id !== body.id)
        saveDb()
        return json(res, 200, { ok: true })
      }

      // Создание или переименование категории.
      if (pathname === '/api/admin/category' && req.method === 'POST') {
        const body = await readBody(req)
        const c = body.category
        if (!c || !String(c.name || '').trim()) {
          return json(res, 400, { error: 'Нужно название категории' })
        }

        const name = String(c.name).trim().slice(0, 60)
        const existing = data.categories.find((x) => x.id === c.id)

        if (existing) {
          existing.name = name
          if (c.isActive !== undefined) existing.isActive = c.isActive !== false
        } else {
          const maxOrder = data.categories.reduce((m, x) => Math.max(m, Number(x.sortOrder) || 0), 0)
          data.categories.push({
            id: nextId('cat'),
            name,
            sortOrder: maxOrder + 1,
            isActive: c.isActive !== false,
          })
        }

        saveDb()
        return json(res, 200, { ok: true, categories: data.categories })
      }

      // Удаление категории. Если в ней есть товары, нужно сказать, что с ними делать:
      // moveTo = id другой категории, или deleteProducts = true.
      if (pathname === '/api/admin/category-delete' && req.method === 'POST') {
        const body = await readBody(req)
        const category = data.categories.find((c) => c.id === body.id)
        if (!category) return json(res, 404, { error: 'Категория не найдена' })
        if (data.categories.length <= 1) {
          return json(res, 400, { error: 'Нужна хотя бы одна категория' })
        }

        const inside = data.products.filter((p) => p.categoryId === body.id)
        if (inside.length && !body.moveTo && body.deleteProducts !== true) {
          return json(res, 409, {
            error: 'В категории есть товары',
            productCount: inside.length,
          })
        }

        if (inside.length && body.deleteProducts === true) {
          data.products = data.products.filter((p) => p.categoryId !== body.id)
        } else if (inside.length) {
          const target = data.categories.find((c) => c.id === body.moveTo)
          if (!target) return json(res, 400, { error: 'Куда перенести товары?' })
          for (const product of data.products) {
            if (product.categoryId === body.id) product.categoryId = target.id
          }
        }

        data.categories = data.categories.filter((c) => c.id !== body.id)
        saveDb()
        return json(res, 200, { ok: true, categories: data.categories })
      }

      // Порядок категорий в витрине: выше / ниже.
      if (pathname === '/api/admin/category-move' && req.method === 'POST') {
        const body = await readBody(req)
        const sorted = data.categories
          .slice()
          .sort((a, b) => (Number(a.sortOrder) || 0) - (Number(b.sortOrder) || 0))
        const index = sorted.findIndex((c) => c.id === body.id)
        if (index === -1) return json(res, 404, { error: 'Категория не найдена' })

        const target = body.direction === 'up' ? index - 1 : index + 1
        if (target >= 0 && target < sorted.length) {
          const tmp = sorted[index]
          sorted[index] = sorted[target]
          sorted[target] = tmp
        }
        sorted.forEach((c, i) => {
          c.sortOrder = i + 1
        })
        data.categories = sorted
        saveDb()
        return json(res, 200, { ok: true, categories: data.categories })
      }

      return json(res, 404, { error: 'Неизвестный метод' })
    }

    if (
      S3_ENABLED &&
      req.method === 'GET' &&
      (pathname.startsWith('/photos/') || pathname.startsWith('/banners/'))
    ) {
      return await serveS3Object(req, res, pathname)
    }

    if (req.method === 'GET') return serveStatic(req, res, pathname)

    res.writeHead(405).end('Method Not Allowed')
  } catch (err) {
    console.error(err)
    json(res, 500, { error: err.message || 'Внутренняя ошибка' })
  }
})

// Предохранители: логируем непойманные ошибки, но НЕ выключаем сервер,
// чтобы обрыв соединения одного клиента (мобильный интернет, VPN) не ронял сайт для всех.
process.on('uncaughtException', (err) => console.error('uncaughtException:', (err && err.message) || err))
process.on('unhandledRejection', (err) => console.error('unhandledRejection:', (err && err.message) || err))

// Некорректный или оборванный HTTP-запрос — просто закрываем сокет, не падаем.
server.on('clientError', (err, socket) => {
  try { if (socket.writable) socket.end('HTTP/1.1 400 Bad Request\r\n\r\n') } catch {}
})

async function start() {
  await initDb()
  server.listen(PORT, '0.0.0.0', () => {
  console.log('')
  console.log('  ✅  Витрина запущена')
  console.log('')
  console.log(S3_ENABLED
    ? '      ☁️  Хранение файлов: облако S3 (переживает пересборки)'
    : '      💾  Хранение файлов: локальный диск')
  console.log('')
  console.log(`      Магазин:  http://localhost:${PORT}`)
  console.log(`      Админка:  http://localhost:${PORT}/admin.html`)
  console.log(`      Пароль админки: ${ADMIN_PASSWORD}`)
  console.log('')
  if (!BOT_TOKEN || !MANAGER_CHAT_ID) {
    console.log('  ℹ️   Telegram не настроен — заявки будут печататься здесь, в терминале.')
    console.log('      Чтобы включить уведомления, заполните .env (см. README.md).')
    console.log('')
  }
  console.log('  Остановить: Ctrl + C')
  console.log('')
  })
}

start()
