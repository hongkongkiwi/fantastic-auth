/**
 * Hosted UI Configuration Hook
 * 
 * Provides configuration, theming, and loading state for hosted pages.
 */

import { useState, useEffect, useCallback, createContext, useContext } from 'react'
import { getHostedConfig } from './api'
import type { HostedUIConfig, HostedPageSearchParams } from './types'

interface HostedConfigContextType {
  config: HostedUIConfig | null
  isLoading: boolean
  error: string | null
  tenantId: string | null
  redirectUrl: string | null
  organizationId: string | null
  refetch: () => Promise<void>
}

const HostedConfigContext = createContext<HostedConfigContextType | undefined>(undefined)

interface HostedConfigProviderProps {
  children: React.ReactNode
  searchParams: URLSearchParams
}

export function HostedConfigProvider({ children, searchParams }: HostedConfigProviderProps) {
  const [config, setConfig] = useState<HostedUIConfig | null>(null)
  const [isLoading, setIsLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  const tenantId = searchParams.get('tenant_id')
  const redirectUrl = searchParams.get('redirect_url')
  const organizationId = searchParams.get('organization_id')

  const fetchConfig = useCallback(async () => {
    if (!tenantId) {
      setError('Missing tenant_id parameter')
      setIsLoading(false)
      return
    }

    try {
      setIsLoading(true)
      setError(null)
      const data = await getHostedConfig({ data: { tenantId } })
      setConfig(data)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load configuration')
    } finally {
      setIsLoading(false)
    }
  }, [tenantId])

  useEffect(() => {
    void fetchConfig()
  }, [fetchConfig])

  // Apply theming when config loads
  useEffect(() => {
    if (!config) return

    // Apply primary color
    if (config.primaryColor) {
      document.documentElement.style.setProperty('--primary-color', config.primaryColor)
      
      // Create a style element for primary color variants
      const styleId = 'hosted-primary-color'
      let styleEl = document.getElementById(styleId) as HTMLStyleElement | null
      
      if (!styleEl) {
        styleEl = document.createElement('style')
        styleEl.id = styleId
        document.head.appendChild(styleEl)
      }
      
      styleEl.textContent = `
        :host, :root {
          --color-primary: ${config.primaryColor};
        }
        .hosted-primary-bg { background-color: ${config.primaryColor} !important; }
        .hosted-primary-text { color: ${config.primaryColor} !important; }
        .hosted-primary-border { border-color: ${config.primaryColor} !important; }
      `
    }

    // Apply background color
    if (config.backgroundColor) {
      document.body.style.backgroundColor = config.backgroundColor
    }

    // Apply custom CSS
    if (config.customCss) {
      const cssId = 'hosted-custom-css'
      let cssEl = document.getElementById(cssId) as HTMLStyleElement | null
      
      if (!cssEl) {
        cssEl = document.createElement('style')
        cssEl.id = cssId
        document.head.appendChild(cssEl)
      }
      
      cssEl.textContent = config.customCss
    }

    // Update favicon
    if (config.faviconUrl) {
      const faviconLink = document.querySelector('link[rel="icon"]') as HTMLLinkElement | null
      if (faviconLink) {
        faviconLink.href = config.faviconUrl
      }
    }

    // Cleanup on unmount
    return () => {
      document.documentElement.style.removeProperty('--primary-color')
      document.body.style.backgroundColor = ''
    }
  }, [config])

  const value: HostedConfigContextType = {
    config,
    isLoading,
    error,
    tenantId,
    redirectUrl,
    organizationId,
    refetch: fetchConfig,
  }

  return (
    <HostedConfigContext.Provider value={value}>
      {children}
    </HostedConfigContext.Provider>
  )
}

export function useHostedConfig() {
  const context = useContext(HostedConfigContext)
  if (context === undefined) {
    throw new Error('useHostedConfig must be used within a HostedConfigProvider')
  }
  return context
}

/**
 * Hook to get search params from URL in a safe way
 */
export function useHostedSearchParams(): HostedPageSearchParams {
  if (typeof window === 'undefined') {
    return { tenant_id: '' }
  }
  
  const params = new URLSearchParams(window.location.search)
  
  return {
    tenant_id: params.get('tenant_id') || '',
    redirect_url: params.get('redirect_url') || undefined,
    oauth_callback: params.get('oauth_callback') || undefined,
    organization_id: params.get('organization_id') || undefined,
    error: params.get('error') || undefined,
    message: params.get('message') || undefined,
  }
}
