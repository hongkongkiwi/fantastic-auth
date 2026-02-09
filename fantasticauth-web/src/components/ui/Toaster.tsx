import { Toaster as Sonner } from 'sonner'

type ToasterProps = React.ComponentProps<typeof Sonner>

const Toaster = ({ ...props }: ToasterProps) => {
  return (
    <Sonner
      theme="system"
      className="toaster group"
      toastOptions={{
        classNames: {
          toast:
            'group toast group-[.toaster]:bg-background group-[.toaster]:text-foreground group-[.toaster]:border-border group-[.toaster]:shadow-elevated',
          description: 'group-[.toast]:text-muted-foreground',
          actionButton:
            'group-[.toast]:bg-primary group-[.toast]:text-primary-foreground',
          cancelButton:
            'group-[.toast]:bg-muted group-[.toast]:text-muted-foreground',
          success: 'group-[.toaster]:border-success group-[.toaster]:text-success',
          error: 'group-[.toaster]:border-destructive group-[.toaster]:text-destructive',
          warning: 'group-[.toaster]:border-warning group-[.toaster]:text-warning',
          info: 'group-[.toaster]:border-info group-[.toaster]:text-info',
        },
      }}
      {...props}
    />
  )
}

export { Toaster }

// Helper functions for toast notifications
export const toast = {
  success: (message: string, description?: string) => {
    import('sonner').then(({ toast }) => {
      toast.success(message, { description })
    })
  },
  error: (message: string, description?: string) => {
    import('sonner').then(({ toast }) => {
      toast.error(message, { description })
    })
  },
  warning: (message: string, description?: string) => {
    import('sonner').then(({ toast }) => {
      toast.warning(message, { description })
    })
  },
  info: (message: string, description?: string) => {
    import('sonner').then(({ toast }) => {
      toast.info(message, { description })
    })
  },
  loading: (message: string) => {
    import('sonner').then(({ toast }) => {
      toast.loading(message)
    })
  },
  promise: <T,>(
    promise: Promise<T>,
    messages: {
      loading: string
      success: string | ((data: T) => string)
      error: string | ((error: unknown) => string)
    }
  ) => {
    import('sonner').then(({ toast }) => {
      toast.promise(promise, {
        loading: messages.loading,
        success: messages.success,
        error: messages.error,
      })
    })
  },
}
