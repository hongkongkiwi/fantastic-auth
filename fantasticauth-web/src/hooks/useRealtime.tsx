import * as React from 'react'
import { toast } from '../components/ui/Toaster'

interface RealtimeMessage {
  type: 'tenant.created' | 'tenant.updated' | 'tenant.deleted' | 'user.login' | 'system.alert' | 'ping'
  data: Record<string, unknown>
  timestamp: string
}

type MessageHandler = (message: RealtimeMessage) => void

interface RealtimeContextType {
  isConnected: boolean
  lastMessage: RealtimeMessage | null
  subscribe: (handler: MessageHandler) => () => void
  sendMessage: (message: Omit<RealtimeMessage, 'timestamp'>) => void
}

const RealtimeContext = React.createContext<RealtimeContextType | undefined>(undefined)

// EventSource-based real-time updates (SSE)
export function RealtimeProvider({ children }: { children: React.ReactNode }) {
  const [isConnected, setIsConnected] = React.useState(false)
  const [lastMessage, setLastMessage] = React.useState<RealtimeMessage | null>(null)
  const eventSourceRef = React.useRef<EventSource | null>(null)
  const handlersRef = React.useRef<Set<MessageHandler>>(new Set())

  // Subscribe to messages
  const subscribe = React.useCallback((handler: MessageHandler) => {
    handlersRef.current.add(handler)
    return () => {
      handlersRef.current.delete(handler)
    }
  }, [])

  // Send message (for WebSocket mode)
  const sendMessage = React.useCallback((message: Omit<RealtimeMessage, 'timestamp'>) => {
    const fullMessage: RealtimeMessage = {
      ...message,
      timestamp: new Date().toISOString(),
    }
    
    // In a real implementation, this would send via WebSocket
    // For demo, we just broadcast to local handlers
    handlersRef.current.forEach((handler) => handler(fullMessage))
  }, [])

  // Connect to SSE endpoint
  React.useEffect(() => {
    // For demo purposes, we'll simulate a connection
    // In production, replace with: new EventSource('/api/events')
    
    const connect = () => {
      setIsConnected(true)
      
      // Simulate incoming messages
      const interval = setInterval(() => {
        const messages: RealtimeMessage['type'][] = [
          'tenant.created',
          'user.login',
          'ping',
        ]
        const randomType = messages[Math.floor(Math.random() * messages.length)]
        
        if (randomType !== 'ping') {
          const message: RealtimeMessage = {
            type: randomType,
            data: {},
            timestamp: new Date().toISOString(),
          }
          
          setLastMessage(message)
          handlersRef.current.forEach((handler) => handler(message))
          
          // Show toast for important events
          if (randomType === 'tenant.created') {
            toast.info(
              'New tenant created',
              'A new tenant has been added to the platform'
            )
          }
        }
      }, 30000) // Every 30 seconds
      
      return () => clearInterval(interval)
    }
    
    const cleanup = connect()
    
    return () => {
      cleanup?.()
      eventSourceRef.current?.close()
    }
  }, [])

  return (
    <RealtimeContext.Provider value={{ isConnected, lastMessage, subscribe, sendMessage }}>
      {children}
    </RealtimeContext.Provider>
  )
}

export function useRealtime() {
  const context = React.useContext(RealtimeContext)
  if (context === undefined) {
    throw new Error('useRealtime must be used within a RealtimeProvider')
  }
  return context
}

// Hook for listening to specific event types
export function useRealtimeEvent<T extends RealtimeMessage['type']>(
  eventType: T,
  handler: (data: RealtimeMessage['data']) => void
) {
  const { subscribe } = useRealtime()
  
  React.useEffect(() => {
    const unsubscribe = subscribe((message) => {
      if (message.type === eventType) {
        handler(message.data)
      }
    })
    
    return unsubscribe
  }, [eventType, handler, subscribe])
}

// Connection status indicator component
export function ConnectionStatus() {
  const { isConnected } = useRealtime()
  
  return (
    <div className="flex items-center gap-2 text-sm">
      <div
        className={`h-2 w-2 rounded-full ${
          isConnected ? 'bg-green-500 animate-pulse' : 'bg-red-500'
        }`}
      />
      <span className={isConnected ? 'text-green-600' : 'text-red-600'}>
        {isConnected ? 'Live' : 'Disconnected'}
      </span>
    </div>
  )
}
