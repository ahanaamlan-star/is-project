import { Link } from 'react-router-dom';
import { FolderPlus, UploadCloud } from 'lucide-react';
import { useStore } from '../store/useStore';
import { EmptyState, Btn } from './ui';

export function NeedsRun({ children }: { children: React.ReactNode }) {
  const { activeCaseId, run, progress } = useStore();
  if (!activeCaseId) return <EmptyState icon={<FolderPlus className="w-6 h-6" />} title="No investigation case yet" body="Create a case with the “New Case” button, or open the ingestion page to load a demo capture." action={<Link to="/app/ingest"><Btn>Go to ingestion</Btn></Link>} />;
  if (!run) return <EmptyState icon={<UploadCloud className="w-6 h-6" />} title={progress ? 'Analysis in progress…' : 'No analysed capture in this case'} body={progress ? `${progress.stage} — ${Math.round(progress.pct * 100)}%` : 'Upload a PCAP/PCAPNG file (or pick a demo capture) and run the forensic analysis to populate this view.'} action={!progress && <Link to="/app/ingest"><Btn><UploadCloud className="w-3.5 h-3.5" />Ingest a capture</Btn></Link>} />;
  return <>{children}</>;
}
