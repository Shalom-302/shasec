import './legacy.css';
import OperatorConsole from './console';
import AdminOnly from '@/components/AdminOnly';

export const metadata = { title: 'Console opérateur · Kortex Security' };

// Admin tooling (active exploitation, repeater). The API enforces admin-only
// on those routes; this gate just keeps the page out of customers' way.
export default function OperatorPage() {
  return (
    <AdminOnly>
      <div className="legacy min-h-screen">
        <OperatorConsole />
      </div>
    </AdminOnly>
  );
}
