import EncryptForm from "@/components/EncryptForm";

export default function Home() {
  return (
    <div className="h-full w-full flex flex-col overflow-hidden bg-black bg-grid">
      <header className="w-full border-b border-white/10 px-8 py-5 flex justify-between items-center shrink-0 z-10 bg-black">
        <div className="flex items-center gap-4">
          <div className="status-static" />
          <div className="text-[10px] font-black uppercase tracking-[0.6em] text-white/40">
            ENCRYPTION_ACCESS
          </div>
        </div>
        <a
          href="https://github.com/Development-With-Dev/env_encrypter"
          target="_blank"
          rel="noopener noreferrer"
          className="flex items-center gap-2 text-[10px] font-black uppercase tracking-[0.4em] text-white/40 hover:text-white transition-colors group"
        >
          <svg viewBox="0 0 24 24" className="w-4 h-4 fill-current opacity-60 group-hover:opacity-100 transition-opacity" xmlns="http://www.w3.org/2000/svg">
            <path d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z" />
          </svg>
          GITHUB
        </a>
      </header>

      <div className="flex-1 w-full flex flex-col lg:flex-row items-stretch overflow-hidden">
        <div className="w-full lg:w-1/2 p-8 md:p-12 xl:p-20 flex flex-col justify-center space-y-10 border-b lg:border-b-0 lg:border-r border-zinc-900 bg-black/40 backdrop-blur-[2px]">
          <div className="space-y-6">
            <div className="h-px w-12 bg-white/10" />
            <h1 className="text-[12vw] lg:text-[7vw] font-black tracking-tighter leading-[0.8] text-white">
              SECURE <br />
              BUFFERS.
            </h1>
            <p className="text-zinc-500 text-[10px] md:text-[11px] font-bold uppercase tracking-[0.3em] leading-relaxed max-w-xs">
              DISTRIBUTED ZERO-KNOWLEDGE <br />
              CONFIGURATION SHARING LAYER.
            </p>
          </div>

          <div className="hidden xl:flex flex-col gap-6">
            <div className="space-y-2 group">
              <div className="h-px w-6 bg-zinc-800 group-hover:w-12 transition-all duration-500" />
              <p className="text-[8px] font-black uppercase tracking-[0.4em] text-zinc-600 group-hover:text-zinc-400 transition-colors">END_TO_END_ENCRYPTION</p>
            </div>
            <div className="space-y-2 group">
              <div className="h-px w-6 bg-zinc-800 group-hover:w-12 transition-all duration-500" />
              <p className="text-[8px] font-black uppercase tracking-[0.4em] text-zinc-600 group-hover:text-zinc-400 transition-colors">MEMORY_ONLY_VOLATILE</p>
            </div>
          </div>
        </div>

        <div className="flex-1 p-4 md:p-8 flex items-center justify-center bg-[#050506]/80 backdrop-blur-sm overflow-hidden">
          <div className="w-full max-w-xl h-full flex flex-col justify-center">
            <EncryptForm />
          </div>
        </div>
      </div>

      <footer className="w-full border-t border-zinc-900 px-6 py-6 flex justify-between items-center shrink-0 bg-black/80 backdrop-blur-sm z-10">
        <div className="flex items-center gap-10">
          <p className="text-[9px] font-black uppercase tracking-[0.5em] text-zinc-800">VAULT_CORE_SYSTEM</p>
          <p className="text-[8px] font-black uppercase tracking-[0.2em] text-zinc-900 hidden md:block">0x0F29A8...B912</p>
        </div>
        <div className="flex gap-10">
          <div className="flex items-center gap-2">
            <div className="w-1 h-1 bg-zinc-800" />
            <p className="text-[8px] font-black uppercase tracking-[0.15em] text-zinc-700">LATENCY: 14MS</p>
          </div>
          <div className="flex items-center gap-2">
            <div className="w-1 h-1 bg-zinc-800" />
            <p className="text-[8px] font-black uppercase tracking-[0.15em] text-zinc-700">BUFFER_MODE: VOLATILE</p>
          </div>
        </div>
      </footer>
    </div>
  );
}
