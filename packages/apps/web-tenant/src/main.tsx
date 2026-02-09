import React from 'react'
import ReactDOM from 'react-dom/client'
import App from './App'
import './index.css'
import { initSentry } from './lib/sentry'
import { appLogger } from './lib/logger'

initSentry()
appLogger.info('web-tenant bootstrap complete')

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
)
