type PendingMfaLogin = {
  email: string
  password: string
  mfaToken?: string
  redirectPath?: string
}

let pendingLogin: PendingMfaLogin | null = null

export const setPendingMfaLogin = (value: PendingMfaLogin) => {
  pendingLogin = value
}

export const getPendingMfaLogin = () => pendingLogin

export const clearPendingMfaLogin = () => {
  pendingLogin = null
}

