import SecretViewer from "@/components/SecretViewer";
import { getSecretMetadata } from "@/lib/api";

interface PageProps {
  params: Promise<{ id: string }>;
}

export default async function SecretPage({ params }: PageProps) {
  const { id } = await params;
  
  let metadata = null;
  let error = null;

  try {
    metadata = await getSecretMetadata(id);
  } catch (err: any) {
    error = err.message || 'Secret not found or has expired.';
  }

  return (
    <div className="flex-1 flex flex-col items-center justify-center p-4 py-12 relative overflow-hidden">
      {/* Background decoration */}
      <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-full max-w-4xl h-96 bg-blue-500/5 blur-[120px] rounded-full -z-10" />
      
      <div className="max-w-2xl w-full">
        {error ? (
          <div className="glass p-12 rounded-3xl text-center space-y-6">
            <div className="w-20 h-20 bg-red-500/10 text-red-500 rounded-full flex items-center justify-center mx-auto">
              <svg viewBox="0 0 24 24" className="w-10 h-10" fill="none" stroke="currentColor" strokeWidth="2">
                <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>
              </svg>
            </div>
            <div className="space-y-2">
              <h1 className="text-3xl font-bold">Secret Unavailable</h1>
              <p className="text-zinc-400">
                {error.includes('burned') 
                  ? 'This secret has been viewed and automatically deleted.' 
                  : 'This link may have expired or never existed.'}
              </p>
            </div>
            <a 
              href="/"
              className="inline-block bg-zinc-800 hover:bg-zinc-700 text-white px-8 py-3 rounded-xl transition-colors font-medium"
            >
              Create New Secret
            </a>
          </div>
        ) : (
          <SecretViewer id={id} initialMetadata={metadata!} />
        )}
      </div>
    </div>
  );
}
