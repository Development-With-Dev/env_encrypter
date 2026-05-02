'use client';

import { useState, useEffect } from 'react';
import { importKey, decryptData } from '@/lib/crypto';
import { getSecret, deleteSecret, SecretMetadata } from '@/lib/api';

interface SecretViewerProps {
  id: string;
  initialMetadata: SecretMetadata;
}

export default function SecretViewer({ id, initialMetadata }: SecretViewerProps) {
  const [key, setKey] = useState('');
  const [plaintext, setPlaintext] = useState<string | null>(null);
  const [isDecrypting, setIsDecrypting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [isBurned, setIsBurned] = useState(false);
  const [copySuccess, setCopySuccess] = useState(false);

  useEffect(() => {
    const fragment = window.location.hash.substring(1);
    if (fragment) { setKey(fragment); }
  }, []);

  const handleReveal = async () => {
    if (!key) return;
    setIsDecrypting(true);
    setError(null);
    try {
      const { encryptedData, iv } = await getSecret(id);
      const cryptoKey = await importKey(key);
      const decrypted = await decryptData(encryptedData, iv, cryptoKey);
      setPlaintext(decrypted);
    } catch (err: any) {
      setError(err.message || 'DECRYPTION_FAULT');
    } finally {
      setIsDecrypting(false);
    }
  };

  const handleBurn = async () => {
    try {
      setIsDecrypting(true);
      await deleteSecret(id);
      setIsBurned(true);
    } catch (err: any) {
      setError(`PURGE_FAULT: ${err.message || 'SERVER_REJECTED_REQUEST'}`);
    } finally {
      setIsDecrypting(false);
    }
  };

  if (isBurned) {
    return (
      <div className="h-full w-full flex flex-col items-center justify-center space-y-8 animate-in fade-in duration-700 bg-black">
        <div className="space-y-2 text-center">
          <h2 className="text-6xl md:text-8xl font-black tracking-tighter uppercase text-white leading-none">PURGED.</h2>
          <p className="text-white/20 font-black text-[9px] uppercase tracking-[0.6em]">VOLATILE_MEMORY_SCRUBBED</p>
        </div>
        <a href="/" className="btn-action h-12 px-10">RETURN_TO_BASE</a>
      </div>
    );
  }

  if (plaintext) {
    return (
      <div className="h-full w-full flex flex-col bg-black animate-in fade-in duration-700">
        <div className="w-full border-b border-white/10 px-8 py-3 flex justify-between items-center shrink-0">
          <div className="flex items-center gap-4">
            <div className="status-static" />
            <div className="text-[9px] font-black uppercase tracking-[0.6em] text-white/40">DECRYPTED_SESSION_ACTIVE</div>
          </div>
          <div className="text-[8px] font-black uppercase tracking-[0.4em] text-white/10">v1.0.0</div>
        </div>
        <div className="flex-1 w-full flex flex-col p-6 md:p-10 xl:p-12 overflow-hidden relative">
          <div className="absolute inset-0 bg-grid opacity-10 pointer-events-none" />
          <div className="flex-1 flex flex-col space-y-4 z-10 overflow-hidden corner-accent corner-accent-tl corner-accent-tr corner-accent-bl corner-accent-br p-2">
            <div className="shrink-0 flex justify-between items-center px-3">
              <label className="text-[8px] font-black text-white/30 uppercase tracking-[0.6em]">BUFFER_PLAINTEXT_DATA</label>
              <button onClick={() => { navigator.clipboard.writeText(plaintext); setCopySuccess(true); setTimeout(() => setCopySuccess(false), 2000); }} className="text-[8px] font-black uppercase tracking-[0.4em] text-white/40 hover:text-white transition-colors border-b border-white/10 pb-0.5">
                {copySuccess ? 'BUFFER_COPIED' : 'COPY_VAULT_DATA'}
              </button>
            </div>
            <textarea readOnly value={plaintext} cols={100} rows={20} className="flex-1 w-full bg-black/40 border border-white/5 p-8 font-mono text-[10px] text-white/70 outline-none resize-none no-scrollbar leading-relaxed" />
            <div className="shrink-0 p-5 bg-white/[0.01] border border-white/5">
              <p className="text-[8px] text-white/20 uppercase tracking-widest leading-relaxed">SESSION_VOLATILE_MEMORY. PURGE_RECOMMENDED_UPON_FINALIZE.</p>
            </div>
          </div>
        </div>
        <div className="shrink-0 grid grid-cols-2 gap-px bg-white/5 border-t border-white/5">
          <button onClick={handleBurn} className="bg-black h-16 text-[9px] font-black uppercase tracking-[0.5em] text-white/20 hover:text-white transition-all">EXECUTE_PURGE</button>
          <a href="/" className="bg-white h-16 flex items-center justify-center text-[9px] font-black uppercase tracking-[0.5em] text-black hover:bg-white/90 transition-all">FINALIZE_SESSION</a>
        </div>
      </div>
    );
  }

  return (
    <div className="h-full w-full flex flex-col bg-black bg-grid animate-in fade-in duration-700 relative overflow-hidden">
      <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[80vw] h-[80vw] bg-white/[0.01] rounded-full blur-[120px] pointer-events-none" />
      <div className="w-full border-b border-white/10 px-6 py-4 flex justify-between items-center shrink-0 z-10 bg-black/50 backdrop-blur-md">
        <div className="flex items-center gap-3">
          <div className="status-static" />
          <div className="text-[9px] font-black uppercase tracking-[0.5em] text-white/40">VAULT_AUTH</div>
        </div>
        <div className="text-[8px] font-mono text-white/20 tracking-widest">{id.substring(0, 16)}</div>
      </div>
      <div className="flex-1 flex flex-col items-center justify-center p-6 z-10 overflow-hidden">
        <div className="w-full max-w-2xl h-[80vh] flex flex-col items-center justify-center space-y-8 md:space-y-12">
          <div className="w-full flex justify-between opacity-50 px-2 shrink-0">
            <div className="space-y-1">
              <p className="text-[7px] font-black uppercase tracking-[0.6em] text-white/30">TIME_LIFE</p>
              <p className="text-2xl font-black text-white tracking-tighter">
                {Math.round((new Date(initialMetadata.expiresAt).getTime() - Date.now()) / 60000)}M
              </p>
            </div>
            <div className="space-y-1 text-right">
              <p className="text-[7px] font-black uppercase tracking-[0.6em] text-white/30">QUOTA</p>
              <p className="text-2xl font-black text-white tracking-tighter">
                {(initialMetadata.viewsRemaining ?? 0).toString().padStart(2, '0')}U
              </p>
            </div>
          </div>
          <div className="w-full space-y-8 corner-accent corner-accent-tl corner-accent-tr corner-accent-bl corner-accent-br p-8 md:p-12 bg-white/[0.01] border border-white/5">
            <div className="space-y-4">
              <label className="block text-[8px] font-black text-white/30 uppercase tracking-[0.6em]">DECRYPTION_PROTOCOL_KEY</label>
              <input type="password" placeholder="INPUT_KEY..." value={key} onChange={(e) => setKey(e.target.value)} className="w-full bg-black border border-white/5 p-6 text-sm font-mono text-white/70 outline-none focus:border-white/20 transition-all placeholder:text-white/5 text-center tracking-[0.5em]" />
            </div>
            {error && (
              <div className="py-2 text-white/40 text-[8px] font-black uppercase tracking-widest text-center border border-white/5">FAULT: {error}</div>
            )}
            <button onClick={handleReveal} disabled={!key || isDecrypting} className="w-full btn-action h-14 disabled:opacity-10">
              {isDecrypting ? 'SYNCING...' : 'INITIATE_DECRYPTION'}
            </button>
          </div>
          <div className="flex items-center gap-8 opacity-5">
            <div className="h-px w-16 bg-white" />
            <span className="text-[7px] font-black uppercase tracking-[0.8em]">STABLE_LINK</span>
            <div className="h-px w-16 bg-white" />
          </div>
        </div>
      </div>
      <div className="w-full border-t border-white/5 px-6 py-4 flex justify-between items-center shrink-0 z-10 bg-black/50">
        <p className="text-[8px] font-black uppercase tracking-[0.6em] text-white/5">VAULT_CORE_ENGINE</p>
        <p className="text-[8px] font-black uppercase tracking-[0.6em] text-white/5">v1.0.0</p>
      </div>
    </div>
  );
}
