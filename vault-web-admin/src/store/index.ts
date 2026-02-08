import { create } from 'zustand'
import { persist } from 'zustand/middleware'
import { User, Theme } from '@/types'

interface AuthState {
  user: User | null
  token: string | null
  isAuthenticated: boolean
  setAuth: (user: User, token: string) => void
  clearAuth: () => void
  setUser: (user: User) => void
}

export const useAuthStore = create<AuthState>()(
  persist(
    (set) => ({
      user: null,
      token: null,
      isAuthenticated: false,
      setAuth: (user, token) => {
        localStorage.setItem('vault_admin_token', token)
        set({ user, token, isAuthenticated: true })
      },
      clearAuth: () => {
        localStorage.removeItem('vault_admin_token')
        set({ user: null, token: null, isAuthenticated: false })
      },
      setUser: (user) => set({ user }),
    }),
    {
      name: 'vault-auth',
      partialize: (state) => ({ user: state.user, isAuthenticated: state.isAuthenticated }),
    }
  )
)

interface UIState {
  theme: Theme
  sidebarCollapsed: boolean
  setTheme: (theme: Theme) => void
  toggleSidebar: () => void
  setSidebarCollapsed: (collapsed: boolean) => void
}

export const useUIStore = create<UIState>()(
  persist(
    (set) => ({
      theme: 'system',
      sidebarCollapsed: false,
      setTheme: (theme) => {
        set({ theme })
        applyTheme(theme)
      },
      toggleSidebar: () => set((state) => ({ sidebarCollapsed: !state.sidebarCollapsed })),
      setSidebarCollapsed: (collapsed) => set({ sidebarCollapsed: collapsed }),
    }),
    {
      name: 'vault-ui',
    }
  )
)

function applyTheme(theme: Theme) {
  const root = window.document.documentElement
  root.classList.remove('light', 'dark')

  if (theme === 'system') {
    const systemTheme = window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light'
    root.classList.add(systemTheme)
  } else {
    root.classList.add(theme)
  }
}

// Initialize theme
if (typeof window !== 'undefined') {
  const stored = localStorage.getItem('vault-ui')
  if (stored) {
    const { theme } = JSON.parse(stored)
    applyTheme(theme)
  }

  // Listen for system theme changes
  window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', (e) => {
    const uiStore = useUIStore.getState()
    if (uiStore.theme === 'system') {
      applyTheme('system')
    }
  })
}

interface NotificationItem {
  id: string
  type: 'info' | 'success' | 'warning' | 'error'
  title: string
  message?: string
  duration?: number
  read?: boolean
}

interface NotificationState {
  notifications: NotificationItem[]
  addNotification: (notification: Omit<NotificationItem, 'id'>) => void
  removeNotification: (id: string) => void
  clearNotifications: () => void
}

export const useNotificationStore = create<NotificationState>((set) => ({
  notifications: [],
  addNotification: (notification) => {
    const id = Math.random().toString(36).substring(7)
    set((state) => ({
      notifications: [...state.notifications, { ...notification, id }],
    }))
    
    if (notification.duration !== 0) {
      setTimeout(() => {
        set((state) => ({
          notifications: state.notifications.filter((n) => n.id !== id),
        }))
      }, notification.duration || 5000)
    }
  },
  removeNotification: (id) =>
    set((state) => ({
      notifications: state.notifications.filter((n) => n.id !== id),
    })),
  clearNotifications: () => set({ notifications: [] }),
}))

interface FilterState {
  userFilters: {
    status: string
    role: string
    search: string
  }
  setUserFilters: (filters: Partial<FilterState['userFilters']>) => void
  resetUserFilters: () => void
}

export const useFilterStore = create<FilterState>((set) => ({
  userFilters: {
    status: 'all',
    role: 'all',
    search: '',
  },
  setUserFilters: (filters) =>
    set((state) => ({
      userFilters: { ...state.userFilters, ...filters },
    })),
  resetUserFilters: () =>
    set({
      userFilters: {
        status: 'all',
        role: 'all',
        search: '',
      },
    }),
}))
