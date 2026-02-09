import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useNavigate } from 'react-router-dom'
import { api } from '@/services/api'
import { useAuthStore, useNotificationStore } from '@/store'
import type { User } from '@/types'

export function useAuth() {
  const navigate = useNavigate()
  const queryClient = useQueryClient()
  const { setAuth, clearAuth, user, isAuthenticated } = useAuthStore()
  const { addNotification } = useNotificationStore()

  const loginMutation = useMutation({
    mutationFn: async ({ email, password, mfaCode }: { email: string; password: string; mfaCode?: string }) => {
      const result = await api.login(email, password, mfaCode)
      return result
    },
    onSuccess: (data) => {
      setAuth(data.user, data.token)
      addNotification({
        type: 'success',
        title: 'Welcome back!',
        message: `Logged in as ${data.user.email}`,
      })
      navigate('/')
    },
    onError: (error: Error) => {
      addNotification({
        type: 'error',
        title: 'Login failed',
        message: error.message,
      })
    },
  })

  const logoutMutation = useMutation({
    mutationFn: async () => {
      await api.logout()
    },
    onSuccess: () => {
      clearAuth()
      queryClient.clear()
      addNotification({
        type: 'info',
        title: 'Logged out',
        message: 'You have been successfully logged out.',
      })
      navigate('/login')
    },
    onError: () => {
      // Still clear local state even if API call fails
      clearAuth()
      queryClient.clear()
      navigate('/login')
    },
  })

  const { data: currentUser, isLoading: isLoadingUser } = useQuery({
    queryKey: ['currentUser'],
    queryFn: () => api.getCurrentUser(),
    enabled: isAuthenticated && !user,
    retry: false,
  })

  return {
    user: user || currentUser,
    isAuthenticated,
    isLoading: loginMutation.isPending || logoutMutation.isPending || isLoadingUser,
    login: loginMutation.mutate,
    logout: logoutMutation.mutate,
    loginError: loginMutation.error,
  }
}

export function useRequireAuth() {
  const navigate = useNavigate()
  const { isAuthenticated } = useAuthStore()

  return useQuery({
    queryKey: ['auth-check'],
    queryFn: async () => {
      if (!isAuthenticated) {
        navigate('/login')
        throw new Error('Not authenticated')
      }
      return true
    },
    enabled: !isAuthenticated,
    retry: false,
  })
}

export function useUpdateProfile() {
  const queryClient = useQueryClient()
  const { setUser, user } = useAuthStore()
  const { addNotification } = useNotificationStore()

  return useMutation({
    mutationFn: async (data: Partial<User>) => {
      const response = await api.updateUser(user!.id, data)
      return response
    },
    onSuccess: (data) => {
      setUser(data)
      queryClient.invalidateQueries({ queryKey: ['currentUser'] })
      addNotification({
        type: 'success',
        title: 'Profile updated',
        message: 'Your profile has been updated successfully.',
      })
    },
    onError: (error: Error) => {
      addNotification({
        type: 'error',
        title: 'Update failed',
        message: error.message,
      })
    },
  })
}
