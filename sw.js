// sw.js — decrypts the encrypted test build on the fly. See encrypt.mjs for the layout.
const BASE = '/cs-builds/'
let keyPromise = null
const versions = {}          // branch → cache-buster from the link's ?v=
const manifests = {}         // branch → { at, data }

const idb = () => new Promise((res, rej) => {
  const r = indexedDB.open('cs-test', 1)
  r.onupgradeneeded = () => r.result.createObjectStore('kv')
  r.onsuccess = () => res(r.result); r.onerror = () => rej(r.error)
})
const kvGet = async (k) => { const db = await idb(); return new Promise((res, rej) => { const t = db.transaction('kv').objectStore('kv').get(k); t.onsuccess = () => res(t.result); t.onerror = () => rej(t.error) }) }
const kvSet = async (k, v) => { const db = await idb(); return new Promise((res, rej) => { const t = db.transaction('kv', 'readwrite').objectStore('kv').put(v, k); t.onsuccess = () => res(); t.onerror = () => rej(t.error) }) }
const importKey = (hex) => crypto.subtle.importKey('raw', new Uint8Array(hex.match(/../g).map(h => parseInt(h, 16))), 'AES-GCM', false, ['decrypt'])
const getKey = () => keyPromise || (keyPromise = kvGet('key').then(hex => hex ? importKey(hex) : null))

self.addEventListener('install', () => self.skipWaiting())
self.addEventListener('activate', (e) => e.waitUntil(self.clients.claim()))
self.addEventListener('message', (e) => {
  if (e.data && e.data.type === 'key' && /^[0-9a-f]{64}$/i.test(e.data.key)) {
    keyPromise = importKey(e.data.key)
    for (const b in manifests) delete manifests[b]
    e.waitUntil(kvSet('key', e.data.key).then(() => e.ports[0] && e.ports[0].postMessage('ok')))
  } else if (e.ports[0]) e.ports[0].postMessage('bad')
})

self.addEventListener('fetch', (e) => {
  const url = new URL(e.request.url)
  if (url.origin !== location.origin || !url.pathname.startsWith(BASE)) return
  const rel = url.pathname.slice(BASE.length)
  const i = rel.indexOf('/play/')
  if (i < 0) return
  const branch = rel.slice(0, i)
  let file = decodeURIComponent(rel.slice(i + 6))
  if (file === '' || file.endsWith('/')) file += 'index.html'
  if (e.request.mode === 'navigate' && url.searchParams.get('v')) versions[branch] = url.searchParams.get('v')
  e.respondWith(serve(branch, file))
})

const page = (text, status) => new Response(
  `<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><body style="margin:0;background:#0d1014;color:#ff8a80;font:15px ui-monospace,monospace;display:grid;place-items:center;height:100vh;text-align:center;padding:24px;box-sizing:border-box">${text}</body>`,
  { status, headers: { 'content-type': 'text/html; charset=utf-8' } })

async function decrypt(key, data) {
  return crypto.subtle.decrypt({ name: 'AES-GCM', iv: data.subarray(0, 12) }, key, data.subarray(12))
}

async function manifest(branch, key) {
  const m = manifests[branch]
  if (m && Date.now() - m.at < 30000) return m.data
  const v = versions[branch] ? '?v=' + encodeURIComponent(versions[branch]) : ''
  const r = await fetch(BASE + branch + '/manifest.bin' + v, { cache: 'no-store' })
  if (r.status === 404) throw new Error(`No build called "${branch}" is deployed (yet). Give it a minute and <a href="" style="color:#4fd1d9">try again</a>.`)
  if (!r.ok) throw new Error('manifest: HTTP ' + r.status)
  let plain
  try { plain = await decrypt(key, new Uint8Array(await r.arrayBuffer())) }
  catch { throw new Error('This key does not open this build. Open the newest <b>Play this build</b> link from the pull request.') }
  const data = JSON.parse(new TextDecoder().decode(plain))
  manifests[branch] = { at: Date.now(), data }
  return data
}

async function serve(branch, file) {
  try {
    const key = await getKey()
    if (!key) return page('No key on this device. Open the <b>Play this build</b> link from the pull request comment.', 403)
    const man = await manifest(branch, key)
    const entry = man.files[file]
    if (!entry) return new Response('not part of this build: ' + file, { status: 404 })
    const r = await fetch(BASE + 'blobs/' + entry.b + '.bin')
    if (!r.ok) return new Response('missing blob for ' + file, { status: 502 })
    const plain = await decrypt(key, new Uint8Array(await r.arrayBuffer()))
    return new Response(plain, { headers: { 'content-type': entry.t, 'cache-control': 'no-store' } })
  } catch (err) {
    return page(err && err.message || String(err), 500)
  }
}
