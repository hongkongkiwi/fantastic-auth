package com.vault.ui

import android.app.AlertDialog
import android.content.Intent
import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.Button
import android.widget.ImageView
import android.widget.ProgressBar
import android.widget.TextView
import android.widget.Toast
import androidx.fragment.app.Fragment
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.repeatOnLifecycle
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.bumptech.glide.Glide
import com.vault.R
import com.vault.VaultAuth
import com.vault.models.*
import kotlinx.coroutines.launch

/**
 * Pre-built profile fragment for displaying and managing user profile
 * 
 * Usage:
 * ```kotlin
 * // In your activity
 * supportFragmentManager.beginTransaction()
 *     .replace(R.id.container, VaultProfileFragment.newInstance())
 *     .commit()
 * ```
 * 
 * Or in XML:
 * ```xml
 * <fragment
 *     android:name="com.vault.ui.VaultProfileFragment"
 *     android:id="@+id/profile_fragment"
 *     android:layout_width="match_parent"
 *     android:layout_height="match_parent" />
 * ```
 */
open class VaultProfileFragment : Fragment() {

    private lateinit var avatarImage: ImageView
    private lateinit var nameText: TextView
    private lateinit var emailText: TextView
    private lateinit var emailVerifiedBadge: View
    private lateinit var mfaStatusText: TextView
    private lateinit var editProfileButton: Button
    private lateinit var changePasswordButton: Button
    private lateinit var mfaButton: Button
    private lateinit var logoutButton: Button
    private lateinit var progressBar: ProgressBar
    private lateinit var organizationsRecyclerView: RecyclerView
    private lateinit var sessionsButton: Button

    private var organizationsAdapter: OrganizationsAdapter? = null

    companion object {
        /**
         * Create a new instance of VaultProfileFragment
         */
        @JvmStatic
        fun newInstance(): VaultProfileFragment {
            return VaultProfileFragment()
        }
    }

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View? {
        return inflater.inflate(R.layout.fragment_vault_profile, container, false)
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)

        initViews(view)
        setupListeners()
        setupOrganizationsList()
        observeAuthState()
        loadUserData()
    }

    private fun initViews(view: View) {
        avatarImage = view.findViewById(R.id.avatar_image)
        nameText = view.findViewById(R.id.name_text)
        emailText = view.findViewById(R.id.email_text)
        emailVerifiedBadge = view.findViewById(R.id.email_verified_badge)
        mfaStatusText = view.findViewById(R.id.mfa_status_text)
        editProfileButton = view.findViewById(R.id.edit_profile_button)
        changePasswordButton = view.findViewById(R.id.change_password_button)
        mfaButton = view.findViewById(R.id.mfa_button)
        logoutButton = view.findViewById(R.id.logout_button)
        progressBar = view.findViewById(R.id.progress_bar)
        organizationsRecyclerView = view.findViewById(R.id.organizations_recycler_view)
        sessionsButton = view.findViewById(R.id.sessions_button)
    }

    private fun setupListeners() {
        editProfileButton.setOnClickListener {
            showEditProfileDialog()
        }

        changePasswordButton.setOnClickListener {
            showChangePasswordDialog()
        }

        mfaButton.setOnClickListener {
            if (VaultAuth.getInstance().currentUser?.mfaEnabled == true) {
                showDisableMfaDialog()
            } else {
                showEnableMfaDialog()
            }
        }

        logoutButton.setOnClickListener {
            showLogoutConfirmation()
        }

        sessionsButton.setOnClickListener {
            showSessionsDialog()
        }
    }

    private fun setupOrganizationsList() {
        organizationsAdapter = OrganizationsAdapter { organization ->
            switchOrganization(organization)
        }
        organizationsRecyclerView.layoutManager = LinearLayoutManager(requireContext())
        organizationsRecyclerView.adapter = organizationsAdapter
    }

    private fun observeAuthState() {
        viewLifecycleOwner.lifecycleScope.launch {
            viewLifecycleOwner.repeatOnLifecycle(Lifecycle.State.STARTED) {
                VaultAuth.getInstance().authState?.collect { state ->
                    when (state) {
                        is AuthState.Authenticated -> {
                            updateUI(state.user)
                        }
                        is AuthState.Unauthenticated -> {
                            // User logged out, fragment should be closed or updated
                            onUserLoggedOut()
                        }
                        else -> { /* Handle other states */ }
                    }
                }
            }
        }
    }

    private fun loadUserData() {
        val user = VaultAuth.getInstance().currentUser ?: return
        updateUI(user)
        loadOrganizations()
    }

    private fun updateUI(user: User) {
        nameText.text = user.getFullName()
        emailText.text = user.email
        emailVerifiedBadge.visibility = if (user.emailVerified) View.VISIBLE else View.GONE
        
        // Update MFA status
        mfaStatusText.text = if (user.mfaEnabled) {
            "MFA Enabled (${user.mfaMethods.joinToString(", ")})"
        } else {
            "MFA Disabled"
        }
        mfaButton.text = if (user.mfaEnabled) "Disable MFA" else "Enable MFA"

        // Load avatar
        user.profile.picture?.let { url ->
            Glide.with(this)
                .load(url)
                .placeholder(R.drawable.ic_person)
                .circleCrop()
                .into(avatarImage)
        } ?: run {
            avatarImage.setImageResource(R.drawable.ic_person)
        }
    }

    private fun loadOrganizations() {
        viewLifecycleOwner.lifecycleScope.launch {
            setLoading(true)
            try {
                val organizations = VaultAuth.getInstance().getOrganizations()
                organizationsAdapter?.submitList(organizations)
            } catch (e: VaultAuthException) {
                // Silently fail - organizations are optional
            } finally {
                setLoading(false)
            }
        }
    }

    private fun switchOrganization(organization: Organization) {
        viewLifecycleOwner.lifecycleScope.launch {
            setLoading(true)
            try {
                VaultAuth.getInstance().switchOrganization(organization.id)
                Toast.makeText(requireContext(), "Switched to ${organization.name}", Toast.LENGTH_SHORT).show()
            } catch (e: VaultAuthException) {
                Toast.makeText(requireContext(), "Failed to switch organization", Toast.LENGTH_SHORT).show()
            } finally {
                setLoading(false)
            }
        }
    }

    /**
     * Show edit profile dialog
     * Override to customize
     */
    protected open fun showEditProfileDialog() {
        val user = VaultAuth.getInstance().currentUser ?: return
        
        // This is a simplified version - in production, use a proper dialog fragment
        AlertDialog.Builder(requireContext())
            .setTitle("Edit Profile")
            .setMessage("Edit profile functionality to be implemented")
            .setPositiveButton("OK", null)
            .show()
    }

    /**
     * Show change password dialog
     * Override to customize
     */
    protected open fun showChangePasswordDialog() {
        // This is a simplified version - in production, use a proper dialog fragment
        AlertDialog.Builder(requireContext())
            .setTitle("Change Password")
            .setMessage("Change password functionality to be implemented")
            .setPositiveButton("OK", null)
            .show()
    }

    /**
     * Show enable MFA dialog
     * Override to customize
     */
    protected open fun showEnableMfaDialog() {
        AlertDialog.Builder(requireContext())
            .setTitle("Enable MFA")
            .setMessage("Enable multi-factor authentication for enhanced security?")
            .setPositiveButton("Enable") { _, _ ->
                enableMfa()
            }
            .setNegativeButton("Cancel", null)
            .show()
    }

    /**
     * Show disable MFA dialog
     * Override to customize
     */
    protected open fun showDisableMfaDialog() {
        AlertDialog.Builder(requireContext())
            .setTitle("Disable MFA")
            .setMessage("Are you sure you want to disable multi-factor authentication?")
            .setPositiveButton("Disable") { _, _ ->
                disableMfa()
            }
            .setNegativeButton("Cancel", null)
            .show()
    }

    private fun enableMfa() {
        viewLifecycleOwner.lifecycleScope.launch {
            setLoading(true)
            try {
                val setup = VaultAuth.getInstance().enableMfa(MfaMethod.TOTP)
                // Show QR code dialog
                showMfaSetupDialog(setup)
            } catch (e: VaultAuthException) {
                Toast.makeText(requireContext(), e.message, Toast.LENGTH_LONG).show()
            } finally {
                setLoading(false)
            }
        }
    }

    private fun disableMfa() {
        viewLifecycleOwner.lifecycleScope.launch {
            setLoading(true)
            try {
                // Disable all MFA methods
                VaultAuth.getInstance().currentUser?.mfaMethods?.forEach { method ->
                    VaultAuth.getInstance().disableMfa(method)
                }
                Toast.makeText(requireContext(), "MFA disabled", Toast.LENGTH_SHORT).show()
                loadUserData()
            } catch (e: VaultAuthException) {
                Toast.makeText(requireContext(), e.message, Toast.LENGTH_LONG).show()
            } finally {
                setLoading(false)
            }
        }
    }

    /**
     * Show MFA setup dialog with QR code
     * Override to customize
     */
    protected open fun showMfaSetupDialog(setup: MfaSetup) {
        AlertDialog.Builder(requireContext())
            .setTitle("MFA Setup")
            .setMessage("Secret: ${setup.secret}\n\nBackup codes:\n${setup.backupCodes.joinToString("\n")}")
            .setPositiveButton("OK") { _, _ ->
                loadUserData()
            }
            .show()
    }

    /**
     * Show logout confirmation dialog
     * Override to customize
     */
    protected open fun showLogoutConfirmation() {
        AlertDialog.Builder(requireContext())
            .setTitle("Logout")
            .setMessage("Are you sure you want to logout?")
            .setPositiveButton("Logout") { _, _ ->
                performLogout()
            }
            .setNegativeButton("Cancel", null)
            .show()
    }

    private fun performLogout() {
        viewLifecycleOwner.lifecycleScope.launch {
            setLoading(true)
            try {
                VaultAuth.getInstance().logout()
            } catch (e: VaultAuthException) {
                Toast.makeText(requireContext(), e.message, Toast.LENGTH_LONG).show()
            } finally {
                setLoading(false)
            }
        }
    }

    /**
     * Show sessions dialog
     * Override to customize
     */
    protected open fun showSessionsDialog() {
        viewLifecycleOwner.lifecycleScope.launch {
            setLoading(true)
            try {
                val sessions = VaultAuth.getInstance().getSessions()
                showSessionsListDialog(sessions)
            } catch (e: VaultAuthException) {
                Toast.makeText(requireContext(), "Failed to load sessions", Toast.LENGTH_SHORT).show()
            } finally {
                setLoading(false)
            }
        }
    }

    /**
     * Show sessions list dialog
     * Override to customize
     */
    protected open fun showSessionsListDialog(sessions: List<SessionInfo>) {
        val sessionDescriptions = sessions.map { session ->
            val currentMarker = if (session.isCurrent) " (Current)" else ""
            "${session.getDisplayLocation()} - ${session.userAgent ?: "Unknown device"}$currentMarker"
        }.toTypedArray()

        AlertDialog.Builder(requireContext())
            .setTitle("Active Sessions")
            .setItems(sessionDescriptions) { _, _ -> }
            .setPositiveButton("Revoke All Others") { _, _ ->
                revokeAllOtherSessions()
            }
            .setNegativeButton("Close", null)
            .show()
    }

    private fun revokeAllOtherSessions() {
        viewLifecycleOwner.lifecycleScope.launch {
            setLoading(true)
            try {
                VaultAuth.getInstance().revokeAllOtherSessions()
                Toast.makeText(requireContext(), "All other sessions revoked", Toast.LENGTH_SHORT).show()
            } catch (e: VaultAuthException) {
                Toast.makeText(requireContext(), "Failed to revoke sessions", Toast.LENGTH_SHORT).show()
            } finally {
                setLoading(false)
            }
        }
    }

    /**
     * Called when user is logged out
     * Override to customize behavior
     */
    protected open fun onUserLoggedOut() {
        // Default: close the fragment's activity
        activity?.finish()
    }

    private fun setLoading(loading: Boolean) {
        progressBar.visibility = if (loading) View.VISIBLE else View.GONE
    }
}

/**
 * RecyclerView adapter for organizations
 */
private class OrganizationsAdapter(
    private val onOrganizationClick: (Organization) -> Unit
) : RecyclerView.Adapter<OrganizationsAdapter.ViewHolder>() {

    private var organizations: List<Organization> = emptyList()

    fun submitList(newList: List<Organization>) {
        organizations = newList
        notifyDataSetChanged()
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ViewHolder {
        val view = LayoutInflater.from(parent.context)
            .inflate(R.layout.item_organization, parent, false)
        return ViewHolder(view)
    }

    override fun onBindViewHolder(holder: ViewHolder, position: Int) {
        holder.bind(organizations[position])
    }

    override fun getItemCount(): Int = organizations.size

    inner class ViewHolder(itemView: View) : RecyclerView.ViewHolder(itemView) {
        private val nameText: TextView = itemView.findViewById(R.id.org_name_text)
        private val roleText: TextView = itemView.findViewById(R.id.org_role_text)

        fun bind(organization: Organization) {
            nameText.text = organization.name
            roleText.text = organization.role.name.lowercase().replaceFirstChar { it.uppercase() }
            itemView.setOnClickListener { onOrganizationClick(organization) }
        }
    }
}
