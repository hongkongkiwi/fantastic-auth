import { Button } from '../ui/Button'
import { Chrome, Github, Apple, Slack, Gamepad2, BadgeCheck } from 'lucide-react'

interface SocialLoginButtonsProps {
  onGoogleClick?: () => void
  onGitHubClick?: () => void
  onMicrosoftClick?: () => void
  onAppleClick?: () => void
  onSlackClick?: () => void
  onDiscordClick?: () => void
  isLoading?: boolean
}

export function SocialLoginButtons({
  onGoogleClick,
  onGitHubClick,
  onMicrosoftClick,
  onAppleClick,
  onSlackClick,
  onDiscordClick,
  isLoading,
}: SocialLoginButtonsProps) {
  const hasProviders = Boolean(
    onGoogleClick || onGitHubClick || onMicrosoftClick || onAppleClick || onSlackClick || onDiscordClick,
  )

  if (!hasProviders) {
    return null
  }

  return (
    <div className="space-y-3">
      <div className="relative">
        <div className="absolute inset-0 flex items-center">
          <span className="w-full border-t" />
        </div>
        <div className="relative flex justify-center text-xs uppercase">
          <span className="bg-background px-2 text-muted-foreground">
            Or continue with
          </span>
        </div>
      </div>

      <div className="grid grid-cols-2 gap-3">
        {onGoogleClick && (
          <Button
            variant="outline"
            onClick={onGoogleClick}
            disabled={isLoading}
            className="gap-2"
          >
            <Chrome className="h-4 w-4 text-red-500" />
            Google
          </Button>
        )}
        
        {onGitHubClick && (
          <Button
            variant="outline"
            onClick={onGitHubClick}
            disabled={isLoading}
            className="gap-2"
          >
            <Github className="h-4 w-4" />
            GitHub
          </Button>
        )}
        
        {onAppleClick && (
          <Button
            variant="outline"
            onClick={onAppleClick}
            disabled={isLoading}
            className="gap-2"
          >
            <Apple className="h-4 w-4" />
            Apple
          </Button>
        )}

        {onMicrosoftClick && (
          <Button
            variant="outline"
            onClick={onMicrosoftClick}
            disabled={isLoading}
            className="gap-2"
          >
            <BadgeCheck className="h-4 w-4 text-blue-600" />
            Microsoft
          </Button>
        )}
        
        {onSlackClick && (
          <Button
            variant="outline"
            onClick={onSlackClick}
            disabled={isLoading}
            className="gap-2"
          >
            <Slack className="h-4 w-4 text-purple-500" />
            Slack
          </Button>
        )}
        
        {onDiscordClick && (
          <Button
            variant="outline"
            onClick={onDiscordClick}
            disabled={isLoading}
            className="gap-2"
          >
            <Gamepad2 className="h-4 w-4 text-indigo-500" />
            Discord
          </Button>
        )}
      </div>
    </div>
  )
}
