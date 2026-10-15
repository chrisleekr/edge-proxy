import { QueryCache, QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { Problem } from './api';
import { App } from './App';
import './index.css';

// Retries hide real errors from people fixing config; one is enough for
// a flaky network.
const qc: QueryClient = new QueryClient({
  defaultOptions: { queries: { retry: 1, refetchOnWindowFocus: false } },
  queryCache: new QueryCache({
    // A 401 means the session ended: refetching 'me' shows the sign-in
    // form. 'me' itself is skipped, since App already handles its 401.
    onError: (e, q) => {
      if (e instanceof Problem && e.status === 401 && q.queryKey[0] !== 'me') void qc.invalidateQueries({ queryKey: ['me'] });
    },
  }),
});

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <QueryClientProvider client={qc}>
      <App />
    </QueryClientProvider>
  </StrictMode>,
);
