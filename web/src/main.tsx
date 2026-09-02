import { QueryClientProvider } from '@tanstack/react-query'
import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { createBrowserRouter, RouterProvider } from 'react-router-dom'

import { AppShell } from '@/components/AppShell'
import { ConfigurationScreen } from '@/screens/Configuration'
import { CtiScreen } from '@/screens/Cti'
import { DashboardScreen } from '@/screens/Dashboard'
import { HistoryScreen } from '@/screens/History'
import { HuntLiveScreen } from '@/screens/HuntLive'
import { IocValidationScreen } from '@/screens/IocValidation'
import { PlaybookScreen } from '@/screens/Playbook'
import { NewHuntScreen } from '@/screens/NewHunt'
import { ReportScreen } from '@/screens/Report'

import { queryClient } from '@/lib/queryClient'

import './index.css'

const router = createBrowserRouter([
  {
    path: '/',
    element: <AppShell />,
    children: [
      { index: true, element: <NewHuntScreen /> },
      { path: 'dashboard', element: <DashboardScreen /> },
      { path: 'cti', element: <CtiScreen /> },
      { path: 'history', element: <HistoryScreen /> },
      { path: 'configuration', element: <ConfigurationScreen /> },
      { path: 'hunts/:huntId/indicators', element: <IocValidationScreen /> },
      { path: 'hunts/:huntId/playbook', element: <PlaybookScreen /> },
      { path: 'hunts/:huntId/feed', element: <HuntLiveScreen /> },
      { path: 'hunts/:huntId/report', element: <ReportScreen /> },
    ],
  },
])

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <QueryClientProvider client={queryClient}>
      <RouterProvider router={router} />
    </QueryClientProvider>
  </StrictMode>,
)
