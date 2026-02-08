<script lang="ts">
  /**
   * Example page showing SDK usage
   */
  import { 
    useAuth, 
    SignIn, 
    SignUp, 
    UserButton,
    SignedIn,
    SignedOut,
    Protect 
  } from '$lib/index.js';
  
  const { isSignedIn, user, signOut } = useAuth();
  
  let showSignUp = $state(false);
</script>

<div class="container">
  <h1>Vault Svelte SDK Demo</h1>
  
  <SignedIn>
    <div class="dashboard">
      <div class="header">
        <h2>Welcome, {user?.profile?.name || user?.email}</h2>
        <UserButton showName={true} />
      </div>
      
      <Protect role="admin">
        <div class="admin-panel">
          <h3>Admin Panel</h3>
          <p>This is only visible to admins.</p>
        </div>
        
        {#snippet fallback()}
          <p>You need admin access to see the admin panel.</p>
        {/snippet}
      </Protect>
      
      <button onclick={signOut} class="btn-secondary">
        Sign Out
      </button>
    </div>
  </SignedIn>
  
  <SignedOut>
    {#if showSignUp}
      <SignUp 
        oauthProviders={['google', 'github']}
        requireName={true}
        onSignUp={() => console.log('Signed up!')}
      />
      <p class="toggle">
        Already have an account?
        <button onclick={() => showSignUp = false} class="link">
          Sign in
        </button>
      </p>
    {:else}
      <SignIn
        oauthProviders={['google', 'github']}
        showMagicLink={true}
        showForgotPassword={true}
        onSignIn={() => console.log('Signed in!')}
      />
      <p class="toggle">
        Don't have an account?
        <button onclick={() => showSignUp = true} class="link">
          Sign up
        </button>
      </p>
    {/if}
  </SignedOut>
</div>

<style>
  .container {
    max-width: 600px;
    margin: 2rem auto;
    padding: 0 1rem;
  }
  
  h1 {
    text-align: center;
    margin-bottom: 2rem;
  }
  
  .dashboard {
    display: flex;
    flex-direction: column;
    gap: 1.5rem;
  }
  
  .header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 1rem;
    background: #f9fafb;
    border-radius: 0.5rem;
  }
  
  .header h2 {
    margin: 0;
    font-size: 1.25rem;
  }
  
  .admin-panel {
    padding: 1rem;
    background: #eff6ff;
    border: 1px solid #3b82f6;
    border-radius: 0.5rem;
  }
  
  .admin-panel h3 {
    margin: 0 0 0.5rem;
    color: #1e40af;
  }
  
  .admin-panel p {
    margin: 0;
    color: #3b82f6;
  }
  
  .btn-secondary {
    padding: 0.5rem 1rem;
    background: white;
    border: 1px solid #d1d5db;
    border-radius: 0.375rem;
    color: #374151;
    cursor: pointer;
  }
  
  .btn-secondary:hover {
    background: #f9fafb;
  }
  
  .toggle {
    text-align: center;
    margin-top: 1rem;
    color: #6b7280;
  }
  
  .link {
    background: none;
    border: none;
    color: #3b82f6;
    cursor: pointer;
    text-decoration: underline;
  }
  
  .link:hover {
    color: #2563eb;
  }
</style>
