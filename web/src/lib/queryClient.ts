import { QueryClient } from '@tanstack/react-query'

/** Shared cache client: exported so that application stores (long-running searches that
 *  survive navigation) can invalidate the data on completion. */
export const queryClient = new QueryClient({
  defaultOptions: {
    queries: { retry: 1, refetchOnWindowFocus: false, staleTime: 10_000 },
  },
})
