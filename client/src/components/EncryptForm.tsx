'use client';

import { useState, useRef, useCallback } from 'react';
import { generateEncryptionKey, exportKey, encryptData } from '@/lib/crypto';
import { createSecret } from '@/lib/api';

export default function EncryptForm() {
  const [content, setContent] = useState('');
  const [maxViews, setMaxViews] = useState(1);
  const [expiresIn, setExpiresIn] = useState(3600);
  const [isEncrypting, setIsEncrypting] = useState(false);
  const [result, setResult] = useState<{ url: string; key: string } | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [uploadedFileName, setUploadedFileName] = useState<string | null>(null);
  const [copySuccess, setCopySuccess] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleFileRead = useCallback((file: File) => {
    if (file.size > 512000) {
      setError('SIZE_LIMIT_EXCEEDED');
      return;
    }
    const reader = new FileReader();
    reader.onload = (e) => {
      const text = e.target?.result as string;
      if (text) {
        setContent(text);
        setUploadedFileName(file.name);
        setError(null);
      }
    };
    reader.readAsText(file);
  }, []);

  const handleEncrypt = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!content.trim()) return;

    setIsEncrypting(true);
    setError(null);

    try {
      const key = await generateEncryptionKey();
      const keyBase64 = await exportKey(key);
      const { encryptedData, iv } = await encryptData(content, key);

      const { accessToken } = await createSecret({
        encryptedData,
        iv,
        isPasswordProtected: false,
        maxViews: maxViews,
        expiresIn: expiresIn,
      });

      setResult({ url: `${window.location.origin}/secret/${accessToken}#${keyBase64}`, key: keyBase64 });
      setContent('');
      setUploadedFileName(null);
    } catch (err: any) {
      setError(err.message || 'ENCR_ERROR');
    } finally {
      setIsEncrypting(false);
    }
  };

  if (result) {
    return (
      <div className="w-full flex flex-col justify-center space-y-10 animate-in fade-in slide-in-from-bottom-4 duration-500">
        <div className="space-y-4">
          <div className="h-1 w-12 bg-white" />
          <h2 className="text-5xl font-black tracking-tighter">PROTOCOL <br /> ESTABLISHED.</h2>
          <p className="text-zinc-600 text-[9px] font-black uppercase tracking-[0.4em]">VAULT_ID: [LOCAL_ENCRYPTION_SYNC]</p>
        </div>

        <div className="space-y-8">
          <div className="space-y-3">
            <label className="text-[8px] font-black text-zinc-500 uppercase tracking-[0.4em]">DECRYPTION_URI</label>
            <div className="flex flex-col gap-4">
              <input
                readOnly
                value={result.url}
                className="w-full bg-[#0a0a0b] border border-zinc-900 p-6 text-[10px] font-mono text-zinc-400 outline-none selection:bg-zinc-800"
              />
              <button
                onClick={() => {
                  navigator.clipboard.writeText(result.url);
                  setCopySuccess(true);
                  setTimeout(() => setCopySuccess(false), 2000);
                }}
                className="w-full btn-action h-14"
              >
                {copySuccess ? 'BUFFER_COPIED' : 'COPY_VAULT_URI'}
              </button>
            </div>
          </div>

          <button onClick={() => setResult(null)} className="w-full btn-ghost h-14 group">
            <span className="group-hover:tracking-[0.5em] transition-all duration-300">INIT_NEW_PROTOCOL</span>
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="w-full h-full max-h-[75vh] flex flex-col animate-in fade-in duration-700 overflow-hidden">
      <form onSubmit={handleEncrypt} className="flex-1 flex flex-col space-y-6 overflow-hidden">
        {/* Stylish File Upload */}
        <div
          onClick={() => fileInputRef.current?.click()}
          className="shrink-0 cursor-pointer bg-[#050506] p-8 border border-zinc-900 transition-all hover:border-zinc-700 group relative"
        >
          <div className="absolute top-0 right-0 p-2 opacity-0 group-hover:opacity-100 transition-opacity">
            <div className="w-1 h-1 bg-zinc-600" />
          </div>
          <input ref={fileInputRef} type="file" onChange={(e) => { if (e.target.files?.[0]) handleFileRead(e.target.files[0]); }} className="hidden" />
          <div className="text-center space-y-2">
            <p className="text-[10px] font-black uppercase tracking-[0.5em] text-zinc-500 group-hover:text-zinc-300 transition-colors">
              {uploadedFileName ? uploadedFileName : 'LOAD_BUFFER'}
            </p>
            {!uploadedFileName && <p className="text-[8px] text-zinc-800 font-bold uppercase tracking-[0.2em]">FILE_SYSTEM_INGESTION</p>}
          </div>
        </div>

        {/* Technical Textarea */}
        <div className="flex-1 flex flex-col space-y-3 overflow-hidden">
          <div className="flex justify-between items-center px-1">
            <label className="text-[8px] font-black text-zinc-700 uppercase tracking-[0.4em]">DATA_BUFFER</label>
            <div className="text-[8px] font-black text-zinc-900 uppercase tracking-widest">{content.length} BYTES</div>
          </div>
          <textarea
            required
            value={content}
            onChange={(e) => setContent(e.target.value)}
            placeholder="PLAINTEXT_BUFFER_INGEST..."
            className="flex-1 w-full bg-[#050506] border border-zinc-900 p-8 font-mono text-[10px] text-zinc-400 outline-none resize-none no-scrollbar placeholder:text-zinc-900 focus:border-zinc-700 transition-colors"
          />
        </div>

        {/* Pro Settings: Segmented Controls */}
        <div className="shrink-0 grid grid-cols-1 md:grid-cols-2 gap-px bg-white/5 border border-white/5">
          <div className="bg-black p-6 space-y-4">
            <label className="block text-[8px] font-black text-white/20 uppercase tracking-[0.5em]">UNIT_CAP_PROTOCOL</label>
            <div className="flex gap-2">
              {[1, 5, 10].map((v) => (
                <button
                  key={v}
                  type="button"
                  onClick={() => setMaxViews(v)}
                  className={`flex-1 py-3 text-[9px] font-black uppercase tracking-widest transition-all ${maxViews === v ? 'bg-white text-black' : 'bg-white/5 text-white/30 hover:bg-white/10'}`}
                >
                  {v.toString().padStart(2, '0')}
                </button>
              ))}
            </div>
          </div>
          <div className="bg-black p-6 space-y-4">
            <label className="block text-[8px] font-black text-white/20 uppercase tracking-[0.5em]">TTL_INTERVAL_SEC</label>
            <div className="flex gap-2">
              {[
                { label: '01H', val: 3600 },
                { label: '24H', val: 86400 },
                { label: '07D', val: 604800 }
              ].map((t) => (
                <button
                  key={t.val}
                  type="button"
                  onClick={() => setExpiresIn(t.val)}
                  className={`flex-1 py-3 text-[9px] font-black uppercase tracking-widest transition-all ${expiresIn === t.val ? 'bg-white text-black' : 'bg-white/5 text-white/30 hover:bg-white/10'}`}
                >
                  {t.label}
                </button>
              ))}
            </div>
          </div>
        </div>

        {error && <div className="shrink-0 py-3 bg-red-950/20 text-red-500 text-[8px] font-black uppercase tracking-widest text-center border border-red-950/30">ERROR: {error}</div>}

        <button
          type="submit"
          disabled={isEncrypting || !content.trim()}
          className="shrink-0 w-full btn-action h-14 disabled:opacity-10"
        >
          {isEncrypting ? 'INITIALIZING_SECURE_VAULT...' : 'INITIATE_LOCK_PROTOCOL'}
        </button>
      </form>
    </div>
  );
}
