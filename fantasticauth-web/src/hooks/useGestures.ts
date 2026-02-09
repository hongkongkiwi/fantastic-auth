import * as React from 'react'

interface GestureConfig {
  onSwipeLeft?: () => void
  onSwipeRight?: () => void
  onSwipeUp?: () => void
  onSwipeDown?: () => void
  onTap?: () => void
  onLongPress?: () => void
  threshold?: number
  preventDefault?: boolean
}

interface SwipeState {
  startX: number
  startY: number
  startTime: number
}

export function useGestures(
  ref: React.RefObject<HTMLElement>,
  config: GestureConfig
) {
  const {
    onSwipeLeft,
    onSwipeRight,
    onSwipeUp,
    onSwipeDown,
    onTap,
    onLongPress,
    threshold = 50,
    preventDefault = true,
  } = config

  const swipeState = React.useRef<SwipeState | null>(null)
  const longPressTimer = React.useRef<number | null>(null)
  const LONG_PRESS_DURATION = 500

  React.useEffect(() => {
    const element = ref.current
    if (!element) return

    const handleTouchStart = (e: TouchEvent) => {
      const touch = e.touches[0]
      swipeState.current = {
        startX: touch.clientX,
        startY: touch.clientY,
        startTime: Date.now(),
      }

      // Start long press timer
      if (onLongPress) {
        longPressTimer.current = window.setTimeout(() => {
          onLongPress()
          swipeState.current = null
        }, LONG_PRESS_DURATION)
      }

      if (preventDefault) {
        // Don't prevent default on touch start - it blocks scrolling
      }
    }

    const handleTouchMove = (e: TouchEvent) => {
      if (!swipeState.current) return

      // Cancel long press on move
      if (longPressTimer.current) {
        clearTimeout(longPressTimer.current)
        longPressTimer.current = null
      }

      // Optionally prevent default for horizontal swipes
      if (preventDefault && onSwipeLeft && onSwipeRight) {
        const touch = e.touches[0]
        const diffX = Math.abs(touch.clientX - swipeState.current.startX)
        const diffY = Math.abs(touch.clientY - swipeState.current.startY)

        // If horizontal movement is greater than vertical, prevent scroll
        if (diffX > diffY) {
          e.preventDefault()
        }
      }
    }

    const handleTouchEnd = (e: TouchEvent) => {
      // Cancel long press timer
      if (longPressTimer.current) {
        clearTimeout(longPressTimer.current)
        longPressTimer.current = null
      }

      if (!swipeState.current) return

      const touch = e.changedTouches[0]
      const diffX = touch.clientX - swipeState.current.startX
      const diffY = touch.clientY - swipeState.current.startY
      const duration = Date.now() - swipeState.current.startTime

      // Determine if it was a tap (short duration, small movement)
      const isTap = duration < 200 && Math.abs(diffX) < 10 && Math.abs(diffY) < 10

      if (isTap && onTap) {
        onTap()
        swipeState.current = null
        return
      }

      // Determine swipe direction
      const absX = Math.abs(diffX)
      const absY = Math.abs(diffY)

      if (absX > absY && absX > threshold) {
        // Horizontal swipe
        if (diffX > 0 && onSwipeRight) {
          onSwipeRight()
        } else if (diffX < 0 && onSwipeLeft) {
          onSwipeLeft()
        }
      } else if (absY > absX && absY > threshold) {
        // Vertical swipe
        if (diffY > 0 && onSwipeDown) {
          onSwipeDown()
        } else if (diffY < 0 && onSwipeUp) {
          onSwipeUp()
        }
      }

      swipeState.current = null
    }

    const handleTouchCancel = () => {
      if (longPressTimer.current) {
        clearTimeout(longPressTimer.current)
        longPressTimer.current = null
      }
      swipeState.current = null
    }

    element.addEventListener('touchstart', handleTouchStart, { passive: true })
    element.addEventListener('touchmove', handleTouchMove, { passive: false })
    element.addEventListener('touchend', handleTouchEnd)
    element.addEventListener('touchcancel', handleTouchCancel)

    return () => {
      element.removeEventListener('touchstart', handleTouchStart)
      element.removeEventListener('touchmove', handleTouchMove)
      element.removeEventListener('touchend', handleTouchEnd)
      element.removeEventListener('touchcancel', handleTouchCancel)

      if (longPressTimer.current) {
        clearTimeout(longPressTimer.current)
      }
    }
  }, [ref, onSwipeLeft, onSwipeRight, onSwipeUp, onSwipeDown, onTap, onLongPress, threshold, preventDefault])
}

// Hook for pull-to-refresh
export function usePullToRefresh(
  ref: React.RefObject<HTMLElement>,
  onRefresh: () => Promise<void>
) {
  const [isPulling, setIsPulling] = React.useState(false)
  const [pullDistance, setPullDistance] = React.useState(0)
  const startY = React.useRef(0)
  const REFRESH_THRESHOLD = 100

  React.useEffect(() => {
    const element = ref.current
    if (!element) return

    const handleTouchStart = (e: TouchEvent) => {
      // Only trigger if at top of element
      if (element.scrollTop === 0) {
        startY.current = e.touches[0].clientY
      }
    }

    const handleTouchMove = (e: TouchEvent) => {
      if (startY.current === 0) return
      
      const touch = e.touches[0]
      const diff = touch.clientY - startY.current

      if (diff > 0 && element.scrollTop === 0) {
        setIsPulling(true)
        setPullDistance(Math.min(diff * 0.5, REFRESH_THRESHOLD + 50))
        
        if (diff > REFRESH_THRESHOLD) {
          e.preventDefault()
        }
      }
    }

    const handleTouchEnd = async () => {
      if (pullDistance >= REFRESH_THRESHOLD) {
        await onRefresh()
      }
      
      setIsPulling(false)
      setPullDistance(0)
      startY.current = 0
    }

    element.addEventListener('touchstart', handleTouchStart, { passive: true })
    element.addEventListener('touchmove', handleTouchMove, { passive: false })
    element.addEventListener('touchend', handleTouchEnd)

    return () => {
      element.removeEventListener('touchstart', handleTouchStart)
      element.removeEventListener('touchmove', handleTouchMove)
      element.removeEventListener('touchend', handleTouchEnd)
    }
  }, [ref, onRefresh, pullDistance])

  return { isPulling, pullDistance, threshold: REFRESH_THRESHOLD }
}

// Hook for swipeable list items (like iOS mail)
export function useSwipeableItem(
  ref: React.RefObject<HTMLElement>,
  config: {
    onSwipeLeft?: () => void
    onSwipeRight?: () => void
    leftActions?: React.ReactNode
    rightActions?: React.ReactNode
  }
) {
  const [translateX, setTranslateX] = React.useState(0)
  const startX = React.useRef(0)
  const isDragging = React.useRef(false)
  const ACTION_WIDTH = 80

  React.useEffect(() => {
    const element = ref.current
    if (!element) return

    const handleTouchStart = (e: TouchEvent) => {
      startX.current = e.touches[0].clientX - translateX
      isDragging.current = true
    }

    const handleTouchMove = (e: TouchEvent) => {
      if (!isDragging.current) return

      const touch = e.touches[0]
      const diff = touch.clientX - startX.current

      // Limit swipe distance
      const maxSwipe = config.rightActions ? ACTION_WIDTH : 0
      const minSwipe = config.leftActions ? -ACTION_WIDTH : 0
      
      setTranslateX(Math.max(minSwipe, Math.min(maxSwipe, diff)))
    }

    const handleTouchEnd = () => {
      isDragging.current = false

      // Snap to action or close
      if (translateX > ACTION_WIDTH / 2 && config.rightActions) {
        setTranslateX(ACTION_WIDTH)
      } else if (translateX < -ACTION_WIDTH / 2 && config.leftActions) {
        setTranslateX(-ACTION_WIDTH)
      } else {
        setTranslateX(0)
      }

      // Trigger actions
      if (translateX > ACTION_WIDTH && config.onSwipeRight) {
        config.onSwipeRight()
      } else if (translateX < -ACTION_WIDTH && config.onSwipeLeft) {
        config.onSwipeLeft()
      }
    }

    element.addEventListener('touchstart', handleTouchStart, { passive: true })
    element.addEventListener('touchmove', handleTouchMove, { passive: true })
    element.addEventListener('touchend', handleTouchEnd)

    return () => {
      element.removeEventListener('touchstart', handleTouchStart)
      element.removeEventListener('touchmove', handleTouchMove)
      element.removeEventListener('touchend', handleTouchEnd)
    }
  }, [ref, translateX, config])

  return { translateX, isOpen: Math.abs(translateX) > ACTION_WIDTH / 2 }
}
