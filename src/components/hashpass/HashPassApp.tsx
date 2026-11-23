'use client'

// Vortex HashPass - Contraseñas fuertes, frases de paso y hashes.
// Web Crypto + MD5 propio, 100% local en el navegador.

import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import {
  KeyRound,
  RefreshCw,
  Copy,
  Check,
  ShieldCheck,
  FileWarning,
  Hash,
  FileText,
  Upload,
  X,
  Eye,
  EyeOff,
  Type,
} from 'lucide-react'
import {
  PwOptions,
  Strength,
  copyText,
  fmtBytes,
  generatePassphrase,
  generatePassword,
  md5,
  md5Bytes,
  passwordStrength,
  shaFile,
  shaHex,
} from '@/lib/hashpass'

const SUPPORT_EMAIL = 'vortexmusic.soporte.app@gmail.com'
const ACCENT = '#ef4444'
const ACCENT2 = '#f87171'

function VortexLogo({ className = 'w-6 h-6' }: { className?: string }) {
  return (
    <svg viewBox="0 0 48 48" className={className} aria-hidden>
      <rect width="48" height="48" rx="10" fill="#161616" />
      <circle cx="24" cy="24" r="17" fill="none" stroke={ACCENT} strokeWidth="3.5" />
      <path d="M24 10a14 14 0 1 1-9.9 4.1" fill="none" stroke={ACCENT2} strokeWidth="3.5" strokeLinecap="round" />
      <path d="M24 17a7 7 0 1 0 7 7" fill="none" stroke={ACCENT2} strokeWidth="3.5" strokeLinecap="round" />
      <circle cx="24" cy="24" r="3" fill={ACCENT2} />
    </svg>
  )
}

function Footer() {
  return (
    <footer className="mt-auto border-t border-[#2b2b31] bg-[#141416] px-6 py-4">
      <div className="mx-auto flex max-w-3xl flex-col items-center gap-1 text-center">
        <p className="text-[11px] text-[#9b9ba4]">
          Vórtex HashPass · Derechos Reservados © 2026 Vortex Company ·{' '}
          <a href={`mailto:${SUPPORT_EMAIL}`} className="text-[#f87171] hover:underline">
            {SUPPORT_EMAIL}
          </a>
        </p>
        <p className="text-[11px] text-[#9b9ba4]">Gratis · Sin anuncios · 100% local en tu navegador</p>
      </div>
    </footer>
  )
}

const btn =
  'inline-flex items-center justify-center gap-1.5 rounded-lg border border-[#2b2b31] bg-[#1e1e22] px-3 py-2 text-xs font-medium text-[#ececf1] hover:bg-[#26262b] disabled:opacity-40 disabled:cursor-not-allowed transition-colors'

const btnAccent =
  'inline-flex items-center justify-center gap-1.5 rounded-lg px-3 py-2 text-xs font-semibold text-[#0f0f10] transition-colors disabled:opacity-40 disabled:cursor-not-allowed bg-[#ef4444] hover:bg-[#f87171]'

type Tab = 'gen' | 'check' | 'hash'

function CopyBtn({ value, label }: { value: string; label?: string }) {
  const [ok, setOk] = useState(false)
  return (
    <button
      className={`${btn} px-2 py-1.5`}
      title={label ?? 'Copiar'}
      onClick={async () => {
        if (await copyText(value)) {
          setOk(true)
          setTimeout(() => setOk(false), 1200)
        }
      }}
    >
      {ok ? <Check className="h-3.5 w-3.5 text-[#22c55e]" /> : <Copy className="h-3.5 w-3.5" />}
    </button>
  )
}

export default function HashPassApp() {
  const [tab, setTab] = useState<Tab>('gen')

  // ----- generar -----
  const [pw, setPw] = useState('')
  const [showPw, setShowPw] = useState(true)
  const [length, setLength] = useState(20)
  const [opts, setOpts] = useState({ lower: true, upper: true, digits: true, symbols: true, avoidAmbiguous: false })
  const [ppWords, setPpWords] = useState(4)
  const [ppSep, setPpSep] = useState('-')
  const [ppCap, setPpCap] = useState(true)
  const [ppNum, setPpNum] = useState(true)
  const [pp, setPp] = useState('')

  const regen = () => {
    setPw(generatePassword({ length, ...opts } as PwOptions))
    setPp(generatePassphrase(ppWords, ppSep, ppCap, ppNum))
  }

  // primera generación en cliente
  useEffect(() => {
    setPw(generatePassword({ length, ...opts } as PwOptions))
    setPp(generatePassphrase(ppWords, ppSep, ppCap, ppNum))
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  // ----- evaluar -----
  const [toCheck, setToCheck] = useState('')
  const [showCheck, setShowCheck] = useState(false)
  const strength: Strength = useMemo(() => passwordStrength(toCheck), [toCheck])

  // ----- hashes -----
  const [hashText, setHashText] = useState('')
  const [hashes, setHashes] = useState<Record<string, string>>({})
  const [fileInfo, setFileInfo] = useState<{ name: string; size: number } | null>(null)
  const [fileHashes, setFileHashes] = useState<Record<string, string>>({})
  const [hashBusy, setHashBusy] = useState(false)
  const fileRef = useRef<HTMLInputElement>(null)

  const runHashes = useCallback(async () => {
    if (!hashText) {
      setHashes({})
      return
    }
    setHashBusy(true)
    try {
      const [s1, s2, s3, s4] = await Promise.all([
        shaHex(hashText, 'SHA-1'),
        shaHex(hashText, 'SHA-256'),
        shaHex(hashText, 'SHA-384'),
        shaHex(hashText, 'SHA-512'),
      ])
      setHashes({ MD5: md5(hashText), 'SHA-1': s1, 'SHA-256': s2, 'SHA-384': s3, 'SHA-512': s4 })
    } finally {
      setHashBusy(false)
    }
  }, [hashText])

  const onFile = useCallback(async (f: File | null) => {
    if (!f) return
    setFileHashes({})
    setFileInfo({ name: f.name, size: f.size })
    setHashBusy(true)
    try {
      const buf = await f.arrayBuffer()
      const [s1, s2] = await Promise.all([shaFile(buf, 'SHA-256'), shaFile(buf, 'SHA-512')])
      setFileHashes({ 'SHA-256': s1, 'SHA-512': s2, MD5: md5Bytes(new Uint8Array(buf)) })
    } finally {
      setHashBusy(false)
    }
  }, [])

  return (
    <div className="flex min-h-screen flex-col">
      <header className="border-b border-[#2b2b31] bg-[#141416] px-6 py-4">
        <div className="mx-auto flex max-w-5xl items-center gap-3">
          <VortexLogo className="w-9 h-9" />
          <div className="min-w-0">
            <h1 className="truncate text-lg font-bold tracking-tight">
              Vórtex HashPass <span className="font-normal text-[#9b9ba4]">· Contraseñas y hashes, sin límites</span>
            </h1>
            <p className="text-[11px] text-[#9b9ba4]">Generador, evaluador y hashes MD5/SHA · todo se calcula en tu equipo</p>
          </div>
        </div>
      </header>

      <main className="mx-auto w-full max-w-5xl flex-1 px-4 py-6">
        {/* pestañas */}
        <div className="mb-4 flex gap-1 rounded-xl border border-[#2b2b31] bg-[#17171a] p-1">
          {(
            [
              { id: 'gen', label: 'Generar', icon: KeyRound },
              { id: 'check', label: 'Evaluar', icon: ShieldCheck },
              { id: 'hash', label: 'Hashes', icon: Hash },
            ] as const
          ).map((t) => (
            <button
              key={t.id}
              onClick={() => setTab(t.id)}
              className={`flex flex-1 items-center justify-center gap-1.5 rounded-lg px-3 py-2 text-xs font-semibold transition-colors ${
                tab === t.id ? 'bg-[#26262b] text-[#ececf1]' : 'text-[#9b9ba4] hover:text-[#ececf1]'
              }`}
            >
              <t.icon className="h-3.5 w-3.5" /> {t.label}
            </button>
          ))}
        </div>

        {tab === 'gen' && (
          <div className="space-y-4">
            <div className="rounded-2xl border border-[#2b2b31] bg-[#17171a] p-5">
              <p className="mb-3 flex items-center gap-2 text-xs font-semibold uppercase tracking-wide text-[#9b9ba4]">
                <KeyRound className="h-3.5 w-3.5" /> Contraseña aleatoria
              </p>
              <div className="flex items-center gap-2">
                <div className="flex min-w-0 flex-1 items-center gap-2 rounded-xl border border-[#2b2b31] bg-[#0f0f10] px-3 py-2.5">
                  <span className="min-w-0 flex-1 truncate font-mono text-base tracking-wide">
                    {showPw ? pw : '•'.repeat(Math.min(pw.length, 28))}
                  </span>
                  <button className="text-[#9b9ba4] hover:text-[#ececf1]" onClick={() => setShowPw((v) => !v)}>
                    {showPw ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                  </button>
                  <CopyBtn value={pw} />
                </div>
                <button className={btnAccent} onClick={regen}>
                  <RefreshCw className="h-3.5 w-3.5" /> Regenerar
                </button>
              </div>
              <div className="mt-4 grid gap-3 sm:grid-cols-2">
                <label className="text-xs text-[#9b9ba4]">
                  Longitud: <span className="font-mono text-[#ececf1]">{length}</span>
                  <input type="range" min={6} max={64} value={length} onChange={(e) => setLength(parseInt(e.target.value, 10))} className="mt-1.5 w-full" />
                </label>
                <div className="flex flex-wrap items-center gap-3 text-xs">
                  {(
                    [
                      ['lower', 'a-z'],
                      ['upper', 'A-Z'],
                      ['digits', '0-9'],
                      ['symbols', '!@#'],
                      ['avoidAmbiguous', 'sin ambiguos'],
                    ] as const
                  ).map(([key, label]) => (
                    <label key={key} className="flex items-center gap-1.5 text-[#ececf1]">
                      <input
                        type="checkbox"
                        checked={opts[key]}
                        onChange={(e) => setOpts((o) => ({ ...o, [key]: e.target.checked }))}
                        className="accent-[#ef4444]"
                      />
                      {label}
                    </label>
                  ))}
                </div>
              </div>
              <p className="mt-3 text-[11px] text-[#9b9ba4]">
                Entropía estimada ≈ <span className="font-mono text-[#f87171]">{passwordStrength(pw).bits} bits</span> · generada con crypto.getRandomValues
              </p>
            </div>

            <div className="rounded-2xl border border-[#2b2b31] bg-[#17171a] p-5">
              <p className="mb-3 flex items-center gap-2 text-xs font-semibold uppercase tracking-wide text-[#9b9ba4]">
                <Type className="h-3.5 w-3.5" /> Frase de paso
              </p>
              <div className="flex items-center gap-2">
                <div className="flex min-w-0 flex-1 items-center gap-2 rounded-xl border border-[#2b2b31] bg-[#0f0f10] px-3 py-2.5">
                  <span className="min-w-0 flex-1 truncate font-mono text-base tracking-wide">{pp}</span>
                  <CopyBtn value={pp} />
                </div>
                <button className={btnAccent} onClick={regen}>
                  <RefreshCw className="h-3.5 w-3.5" /> Regenerar
                </button>
              </div>
              <div className="mt-4 flex flex-wrap items-center gap-4 text-xs">
                <label className="text-[#9b9ba4]">
                  Palabras: <span className="font-mono text-[#ececf1]">{ppWords}</span>
                  <input type="range" min={3} max={7} value={ppWords} onChange={(e) => setPpWords(parseInt(e.target.value, 10))} className="mt-1.5 ml-2 w-32" />
                </label>
                <label className="flex items-center gap-1.5 text-[#ececf1]">
                  Separador
                  <input value={ppSep} onChange={(e) => setPpSep(e.target.value.slice(0, 1) || '-')} className="w-9 rounded border border-[#2b2b31] bg-[#0f0f10] px-2 py-1 text-center font-mono" />
                </label>
                <label className="flex items-center gap-1.5 text-[#ececf1]">
                  <input type="checkbox" checked={ppCap} onChange={(e) => setPpCap(e.target.checked)} className="accent-[#ef4444]" /> Capitalizar
                </label>
                <label className="flex items-center gap-1.5 text-[#ececf1]">
                  <input type="checkbox" checked={ppNum} onChange={(e) => setPpNum(e.target.checked)} className="accent-[#ef4444]" /> Número final
                </label>
              </div>
            </div>
          </div>
        )}

        {tab === 'check' && (
          <div className="rounded-2xl border border-[#2b2b31] bg-[#17171a] p-5">
            <p className="mb-3 flex items-center gap-2 text-xs font-semibold uppercase tracking-wide text-[#9b9ba4]">
              <ShieldCheck className="h-3.5 w-3.5" /> Evaluar fortaleza
            </p>
            <div className="flex items-center gap-2">
              <input
                type={showCheck ? 'text' : 'password'}
                value={toCheck}
                onChange={(e) => setToCheck(e.target.value)}
                placeholder="Escribe la contraseña a evaluar…"
                className="flex-1 rounded-xl border border-[#2b2b31] bg-[#0f0f10] px-3 py-2.5 font-mono text-sm outline-none focus:border-[#ef4444]"
              />
              <button className={btn} onClick={() => setShowCheck((v) => !v)}>
                {showCheck ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
              </button>
            </div>
            {toCheck && (
              <div className="mt-4">
                <div className="flex items-center justify-between text-xs">
                  <span className="font-semibold" style={{ color: strength.color }}>
                    {strength.label}
                  </span>
                  <span className="text-[#9b9ba4]">
                    ≈ <span className="font-mono">{strength.bits} bits</span> de entropía
                  </span>
                </div>
                <div className="mt-2 flex gap-1.5">
                  {[0, 1, 2, 3, 4].map((i) => (
                    <span key={i} className="h-2 flex-1 rounded-full" style={{ background: i <= strength.score ? strength.color : '#2b2b31' }} />
                  ))}
                </div>
                {strength.suggestions.length > 0 && (
                  <ul className="mt-4 space-y-1.5">
                    {strength.suggestions.map((s, i) => (
                      <li key={i} className="flex items-start gap-2 text-xs text-[#9b9ba4]">
                        <FileWarning className="mt-0.5 h-3 w-3 shrink-0 text-[#eab308]" />
                        {s}
                      </li>
                    ))}
                  </ul>
                )}
              </div>
            )}
            {!toCheck && (
              <p className="mt-4 text-xs text-[#9b9ba4]">
                La evaluación es local y matemática: longitud y variedad de caracteres. Nada se envía a ningún servidor.
              </p>
            )}
          </div>
        )}

        {tab === 'hash' && (
          <div className="space-y-4">
            <div className="rounded-2xl border border-[#2b2b31] bg-[#17171a] p-5">
              <p className="mb-3 flex items-center gap-2 text-xs font-semibold uppercase tracking-wide text-[#9b9ba4]">
                <FileText className="h-3.5 w-3.5" /> Hash de texto
              </p>
              <textarea
                value={hashText}
                onChange={(e) => setHashText(e.target.value)}
                rows={3}
                placeholder="Pega aquí el texto…"
                className="w-full resize-y rounded-xl border border-[#2b2b31] bg-[#0f0f10] px-3 py-2.5 text-sm outline-none focus:border-[#ef4444]"
              />
              <div className="mt-3 flex items-center gap-2">
                <button className={btnAccent} onClick={runHashes} disabled={!hashText || hashBusy}>
                  <Hash className="h-3.5 w-3.5" /> Calcular hashes
                </button>
                {hashBusy && <span className="text-xs text-[#9b9ba4]">Calculando…</span>}
              </div>
              {Object.keys(hashes).length > 0 && (
                <div className="mt-4 space-y-2">
                  {Object.entries(hashes).map(([algo, hex]) => (
                    <div key={algo} className="flex items-center gap-2 rounded-lg border border-[#2b2b31] bg-[#0f0f10] px-3 py-2">
                      <span className="w-16 shrink-0 text-[11px] font-bold text-[#f87171]">{algo}</span>
                      <code className="min-w-0 flex-1 truncate font-mono text-[11px] text-[#ececf1]" title={hex}>{hex}</code>
                      <CopyBtn value={hex} label={`Copiar ${algo}`} />
                    </div>
                  ))}
                </div>
              )}
            </div>

            <div className="rounded-2xl border border-[#2b2b31] bg-[#17171a] p-5">
              <p className="mb-3 flex items-center gap-2 text-xs font-semibold uppercase tracking-wide text-[#9b9ba4]">
                <Upload className="h-3.5 w-3.5" /> Hash de archivo
              </p>
              <input ref={fileRef} type="file" hidden onChange={(e) => onFile(e.target.files?.[0] ?? null)} />
              <button className={btn} onClick={() => fileRef.current?.click()}>
                <Upload className="h-3.5 w-3.5" /> Elegir archivo
              </button>
              {fileInfo && (
                <div className="mt-4">
                  <p className="text-xs text-[#9b9ba4]">
                    {fileInfo.name} · {fmtBytes(fileInfo.size)}
                    <button className="ml-2 text-[#f87171] hover:underline" onClick={() => { setFileInfo(null); setFileHashes({}) }}>
                      quitar
                    </button>
                  </p>
                  <div className="mt-2 space-y-2">
                    {Object.entries(fileHashes).map(([algo, hex]) => (
                      <div key={algo} className="flex items-center gap-2 rounded-lg border border-[#2b2b31] bg-[#0f0f10] px-3 py-2">
                        <span className="w-16 shrink-0 text-[11px] font-bold text-[#f87171]">{algo}</span>
                        <code className="min-w-0 flex-1 truncate font-mono text-[11px] text-[#ececf1]" title={hex}>{hex}</code>
                        <CopyBtn value={hex} label={`Copiar ${algo}`} />
                      </div>
                    ))}
                    {!Object.keys(fileHashes).length && hashBusy && <p className="text-xs text-[#9b9ba4]">Leyendo y calculando…</p>}
                  </div>
                </div>
              )}
              <p className="mt-3 text-[11px] text-[#9b9ba4]">
                El archivo se lee en trozos desde tu disco: nunca se sube a internet.
              </p>
            </div>
          </div>
        )}
      </main>

      <Footer />
    </div>
  )
}
