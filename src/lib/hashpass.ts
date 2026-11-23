// Vortex HashPass - Generador de contraseñas, frases de paso,
// evaluador de fortaleza y hashes (MD5 propio + SHA via Web Crypto).
// 100% local en el navegador, sin backend.

// ---------- Generación ----------

const LOWER = 'abcdefghijkmnopqrstuvwxyz'
const UPPER = 'ABCDEFGHJKLMNPQRSTUVWXYZ'
const DIGITS = '23456789'
const AMBIGUOUS = { lower: 'l', upper: 'I', digits: '0' }
const SYMBOLS = '!@#$%^&*()-_=+[]{};:,.?/'

export interface PwOptions {
  length: number
  lower: boolean
  upper: boolean
  digits: boolean
  symbols: boolean
  avoidAmbiguous: boolean
}

/** entero aleatorio uniforme en [0, max) con crypto.getRandomValues */
function randInt(max: number): number {
  const buf = new Uint32Array(1)
  const limit = Math.floor(0x100000000 / max) * max
  let v = 0
  do {
    crypto.getRandomValues(buf)
    v = buf[0]
  } while (v >= limit)
  return v % max
}

function pick(chars: string): string {
  return chars.charAt(randInt(chars.length))
}

export function generatePassword(opts: PwOptions): string {
  let lower = LOWER
  let upper = UPPER
  let digits = DIGITS
  if (!opts.avoidAmbiguous) {
    lower += 'l'
    upper += 'IO'
    digits += '01'
  }
  const pools: string[] = []
  if (opts.lower) pools.push(lower)
  if (opts.upper) pools.push(upper)
  if (opts.digits) pools.push(digits)
  if (opts.symbols) pools.push(SYMBOLS)
  if (!pools.length) pools.push(lower, digits)

  // garantiza al menos uno de cada grupo elegido
  const parts: string[] = pools.map((p) => pick(p))
  const all = pools.join('')
  while (parts.length < opts.length) parts.push(pick(all))
  // Fisher-Yates con crypto
  for (let i = parts.length - 1; i > 0; i--) {
    const j = randInt(i + 1)
    ;[parts[i], parts[j]] = [parts[j], parts[i]]
  }
  return parts.slice(0, opts.length).join('')
}

const WORDLIST = [
  'abeto','árbol','azul','banco','barco','bosque','caballo','cacao','café','camino','canal','canto','carta','castillo','cebra','ceniza','cielo','cinco','cobre','coma','coral','cosmos','cuadro','cubierta','cumbre','dama','danza','delta','diente','domo','duna','eco','enigma','espiga','establo','estrella','falda','faro','fecha','feria','fibra','firma','flota','fondo','fuente','gafas','gaita','gala','ganso','gema','glaciar','golfo','gorra','grada','granja','grillo','guitarra','hada','hamaca','harina','hiedra','higo','hilo','hogar','honra','huerta','idolo','isla','jade','jaula','jilguero','jornada','junco','karate','labio','laguna','lámpara','latón','leche','lejía','lima','lino','loma','lucha','lumbre','luna','madera','madre','maíz','malva','manzana','mapa','marco','marea','melocotón','menta','mesa','miga','mirlo','mojón','molino','moneda','monte','morsa','mosaico','muslo','nata','neblina','nido','nieve','nogal','noria','nube','oasis','obra','ocaso','odisea','olas','onyx','orbe','orca','orgullo','óxido','palma','paloma','panal','pandero','papiro','parque','paso','patio','pecho','pedal','peña','perla','pesca','piano','piedra','pila','pino','pipa','placa','plata','playa','plomo','poema','polen','poncho','portal','prado','prisa','puente','puerta','puma','quena','quimera','rambla','radio','raíz','ramo','rapaz','ratón','rayo','rebaje','regata','remo','resa','río','roble','roma','rosa','ronda','ruta','sable','sagú','salón','salta','sello','selva','senda','sierra','sien','silla','sirena','sobremesa','sol','sonda','soporte','soto','sueño','surco','tabla','tajo','talco','tanda','tapa','tarde','tejado','teles','tema','tendero','terno','tesis','tinte','títere','tono','torre','tosca','tramo','trino','trofeo','tronco','tubería','tulipán','tuno','turbina','umbra','uña','ungüento','urna','vada','vaina','valle','vapor','vara','vaso','vecino','vela','vena','ventisca','verano','verso','vía','vidrio','viento','viñedo','viola','yema','yugo','zafiro','zancajo','zarcillo','zona',
]

export function generatePassphrase(words = 4, separator = '-', capitalize = true, appendDigit = true): string {
  const picked: string[] = []
  for (let i = 0; i < words; i++) {
    const w = WORDLIST[randInt(WORDLIST.length)]
    picked.push(capitalize ? w.charAt(0).toUpperCase() + w.slice(1) : w)
  }
  let out = picked.join(separator)
  if (appendDigit) out += separator + randInt(100).toString().padStart(2, '0')
  return out
}

// ---------- Fortaleza ----------

export interface Strength {
  score: 0 | 1 | 2 | 3 | 4
  label: string
  bits: number
  color: string
  suggestions: string[]
}

export function passwordStrength(pw: string): Strength {
  let pool = 0
  if (/[a-z]/.test(pw)) pool += 26
  if (/[A-Z]/.test(pw)) pool += 26
  if (/[0-9]/.test(pw)) pool += 10
  if (/[^a-zA-Z0-9]/.test(pw)) pool += 32
  const bits = pw.length ? Math.round(pw.length * Math.log2(Math.max(pool, 2))) : 0
  const common = /^(?:123456|password|qwerty|admin|welcome|iloveyou|contraseña|111111|abc123|000000)/i.test(pw)
  let score: 0 | 1 | 2 | 3 | 4 = 0
  if (bits >= 128) score = 4
  else if (bits >= 90) score = 3
  else if (bits >= 60) score = 2
  else if (bits >= 36) score = 1
  if (common) score = 0
  const suggestions: string[] = []
  if (pw.length < 16) suggestions.push('Usa al menos 16 caracteres.')
  if (!/[A-Z]/.test(pw)) suggestions.push('Añade mayúsculas.')
  if (!/[a-z]/.test(pw)) suggestions.push('Añade minúsculas.')
  if (!/[0-9]/.test(pw)) suggestions.push('Añade números.')
  if (!/[^a-zA-Z0-9]/.test(pw)) suggestions.push('Añade símbolos.')
  if (common) suggestions.push('Es una contraseña muy común: cámbiala por completo.')
  const labels = ['Muy débil', 'Débil', 'Aceptable', 'Fuerte', 'Excelente']
  const colors = ['#ef4444', '#f97316', '#eab308', '#84cc16', '#22c55e']
  return { score, label: labels[score], bits, color: colors[score], suggestions }
}

// ---------- Hashes ----------

/** MD5 en JS puro (Web Crypto no lo incluye) sobre bytes */
export function md5Bytes(input: Uint8Array): string {
  const S = [
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
    5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
    4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
    6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
  ]
  const K = new Uint32Array(64)
  for (let i = 0; i < 64; i++) K[i] = Math.floor(Math.abs(Math.sin(i + 1)) * 4294967296)

  const origLen = input.length
  const bitLen = origLen * 8
  const padded = new Uint8Array(((origLen + 8) >> 6 << 6) + 64)
  padded.set(input)
  padded[origLen] = 0x80
  const dv = new DataView(padded.buffer)
  dv.setUint32(padded.length - 8, bitLen >>> 0, true)
  dv.setUint32(padded.length - 4, Math.floor(bitLen / 4294967296), true)

  let a0 = 0x67452301, b0 = 0xefcdab89, c0 = 0x98badcfe, d0 = 0x10325476
  const rl = (x: number, c: number) => (x << c) | (x >>> (32 - c))

  for (let chunk = 0; chunk < padded.length; chunk += 64) {
    const M = new Uint32Array(16)
    const cdv = new DataView(padded.buffer, chunk, 64)
    for (let i = 0; i < 16; i++) M[i] = cdv.getUint32(i * 4, true)
    let A = a0, B = b0, C = c0, D = d0
    for (let i = 0; i < 64; i++) {
      let F: number, g: number
      if (i < 16) { F = (B & C) | (~B & D); g = i }
      else if (i < 32) { F = (D & B) | (~D & C); g = (5 * i + 1) % 16 }
      else if (i < 48) { F = B ^ C ^ D; g = (3 * i + 5) % 16 }
      else { F = C ^ (B | ~D); g = (7 * i) % 16 }
      F = (F + A + K[i] + M[g]) >>> 0
      A = D
      D = C
      C = B
      B = (B + rl(F, S[i])) >>> 0
    }
    a0 = (a0 + A) >>> 0
    b0 = (b0 + B) >>> 0
    c0 = (c0 + C) >>> 0
    d0 = (d0 + D) >>> 0
  }
  const out = new Uint8Array(16)
  const odv = new DataView(out.buffer)
  odv.setUint32(0, a0, true)
  odv.setUint32(4, b0, true)
  odv.setUint32(8, c0, true)
  odv.setUint32(12, d0, true)
  return [...out].map((b) => b.toString(16).padStart(2, '0')).join('')
}

export function md5(text: string): string {
  return md5Bytes(new TextEncoder().encode(text))
}

export type ShaAlgo = 'SHA-1' | 'SHA-256' | 'SHA-384' | 'SHA-512'

export async function shaHex(text: string, algo: ShaAlgo): Promise<string> {
  const data = new TextEncoder().encode(text)
  const digest = await crypto.subtle.digest(algo, data)
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, '0')).join('')
}

export async function shaFile(buf: ArrayBuffer, algo: ShaAlgo): Promise<string> {
  const digest = await crypto.subtle.digest(algo, buf)
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, '0')).join('')
}

export function fmtBytes(n: number): string {
  if (n < 1024) return `${n} B`
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`
  if (n < 1024 * 1024 * 1024) return `${(n / (1024 * 1024)).toFixed(1)} MB`
  return `${(n / (1024 * 1024 * 1024)).toFixed(2)} GB`
}

export async function copyText(text: string): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(text)
    return true
  } catch {
    return false
  }
}
