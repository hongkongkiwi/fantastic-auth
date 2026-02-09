package com.vault.ui

import android.content.Context
import android.content.Intent
import android.os.Bundle
import android.view.View
import android.widget.ProgressBar
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.core.widget.addTextChangedListener
import androidx.lifecycle.lifecycleScope
import com.google.android.material.button.MaterialButton
import com.google.android.material.textfield.TextInputEditText
import com.google.android.material.textfield.TextInputLayout
import com.vault.R
import com.vault.VaultAuth
import com.vault.models.User
import com.vault.models.VaultAuthException
import kotlinx.coroutines.launch

/**
 * Pre-built login activity for Vault authentication
 * 
 * Usage:
 * ```kotlin
 * val intent = VaultLoginActivity.createIntent(context)
 * startActivityForResult(intent, REQUEST_LOGIN)
 * ```
 * 
 * Or with result API:
 * ```kotlin
 * val launcher = registerForActivityResult(
 *     ActivityResultContracts.StartActivityForResult()
 * ) { result ->
 *     if (result.resultCode == RESULT_OK) {
 *         val user = result.data?.getParcelableExtra<User>(VaultLoginActivity.EXTRA_USER)
 *         // Handle successful login
 *     }
 * }
 * launcher.launch(VaultLoginActivity.createIntent(context))
 * ```
 */
open class VaultLoginActivity : AppCompatActivity() {

    private lateinit var emailInput: TextInputEditText
    private lateinit var emailLayout: TextInputLayout
    private lateinit var passwordInput: TextInputEditText
    private lateinit var passwordLayout: TextInputLayout
    private lateinit var loginButton: MaterialButton
    private lateinit var signupButton: MaterialButton
    private lateinit var progressBar: ProgressBar
    private lateinit var biometricButton: MaterialButton

    companion object {
        const val EXTRA_USER = "user"
        const val EXTRA_ERROR = "error"
        const val EXTRA_THEME = "theme"

        /**
         * Create an intent to launch the login activity
         * 
         * @param context The context
         * @param theme Optional theme resource ID
         * @return The intent
         */
        @JvmStatic
        @JvmOverloads
        fun createIntent(context: Context, theme: Int = 0): Intent {
            return Intent(context, VaultLoginActivity::class.java).apply {
                if (theme != 0) {
                    putExtra(EXTRA_THEME, theme)
                }
            }
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        // Apply custom theme if provided
        val themeResId = intent.getIntExtra(EXTRA_THEME, 0)
        if (themeResId != 0) {
            setTheme(themeResId)
        }
        
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_vault_login)

        initViews()
        setupListeners()
        checkBiometricAvailability()
    }

    private fun initViews() {
        emailInput = findViewById(R.id.email_input)
        emailLayout = findViewById(R.id.email_layout)
        passwordInput = findViewById(R.id.password_input)
        passwordLayout = findViewById(R.id.password_layout)
        loginButton = findViewById(R.id.login_button)
        signupButton = findViewById(R.id.signup_button)
        progressBar = findViewById(R.id.progress_bar)
        biometricButton = findViewById(R.id.biometric_button)
    }

    private fun setupListeners() {
        // Validate email on text change
        emailInput.addTextChangedListener {
            emailLayout.error = null
        }

        // Validate password on text change
        passwordInput.addTextChangedListener {
            passwordLayout.error = null
        }

        // Login button click
        loginButton.setOnClickListener {
            if (validateInputs()) {
                performLogin()
            }
        }

        // Signup button click
        signupButton.setOnClickListener {
            openSignup()
        }

        // Biometric button click
        biometricButton.setOnClickListener {
            performBiometricLogin()
        }
    }

    private fun checkBiometricAvailability() {
        val vaultAuth = VaultAuth.getInstance()
        if (vaultAuth.isConfigured() && 
            vaultAuth.isBiometricLoginEnabled() && 
            vaultAuth.isBiometricAvailable(this)) {
            biometricButton.visibility = View.VISIBLE
        } else {
            biometricButton.visibility = View.GONE
        }
    }

    private fun validateInputs(): Boolean {
        var valid = true

        val email = emailInput.text?.toString()?.trim() ?: ""
        if (email.isEmpty()) {
            emailLayout.error = "Email is required"
            valid = false
        } else if (!android.util.Patterns.EMAIL_ADDRESS.matcher(email).matches()) {
            emailLayout.error = "Invalid email format"
            valid = false
        }

        val password = passwordInput.text?.toString() ?: ""
        if (password.isEmpty()) {
            passwordLayout.error = "Password is required"
            valid = false
        } else if (password.length < 8) {
            passwordLayout.error = "Password must be at least 8 characters"
            valid = false
        }

        return valid
    }

    private fun performLogin() {
        val email = emailInput.text?.toString()?.trim() ?: return
        val password = passwordInput.text?.toString() ?: return

        setLoading(true)

        lifecycleScope.launch {
            try {
                val user = VaultAuth.getInstance().login(email, password)
                onLoginSuccess(user)
            } catch (e: VaultAuthException) {
                onLoginError(e)
            } finally {
                setLoading(false)
            }
        }
    }

    private fun performBiometricLogin() {
        if (this is androidx.fragment.app.FragmentActivity) {
            setLoading(true)

            lifecycleScope.launch {
                try {
                    val user = VaultAuth.getInstance().loginWithBiometric(this@VaultLoginActivity)
                    onLoginSuccess(user)
                } catch (e: VaultAuthException) {
                    onLoginError(e)
                } finally {
                    setLoading(false)
                }
            }
        } else {
            Toast.makeText(this, "Biometric login requires FragmentActivity", Toast.LENGTH_SHORT).show()
        }
    }

    /**
     * Called when login is successful
     * Override this method to customize the success behavior
     */
    protected open fun onLoginSuccess(user: User) {
        val resultIntent = Intent().apply {
            putExtra(EXTRA_USER, VaultUserParcelable(user))
        }
        setResult(RESULT_OK, resultIntent)
        finish()
    }

    /**
     * Called when login fails
     * Override this method to customize the error handling
     */
    protected open fun onLoginError(error: VaultAuthException) {
        val errorMessage = when (error) {
            is VaultAuthException.InvalidCredentials -> "Invalid email or password"
            is VaultAuthException.UserNotFound -> "User not found"
            is VaultAuthException.AccountLocked -> "Account is locked. Please contact support."
            is VaultAuthException.AccountNotVerified -> "Please verify your email before logging in"
            is VaultAuthException.NetworkError -> "Network error. Please check your connection."
            is VaultAuthException.BiometricNotAvailable -> "Biometric authentication is not available"
            is VaultAuthException.BiometricCancelled -> null // Don't show error for cancellation
            else -> error.message
        }

        errorMessage?.let {
            Toast.makeText(this, it, Toast.LENGTH_LONG).show()
        }

        // Also return error via intent for programmatic handling
        val resultIntent = Intent().apply {
            putExtra(EXTRA_ERROR, error.message)
        }
        setResult(RESULT_CANCELED, resultIntent)
    }

    /**
     * Open signup activity
     * Override this method to customize the signup flow
     */
    protected open fun openSignup() {
        val intent = VaultSignupActivity.createIntent(this)
        startActivity(intent)
    }

    private fun setLoading(loading: Boolean) {
        progressBar.visibility = if (loading) View.VISIBLE else View.GONE
        loginButton.isEnabled = !loading
        signupButton.isEnabled = !loading
        biometricButton.isEnabled = !loading
        emailInput.isEnabled = !loading
        passwordInput.isEnabled = !loading
    }
}

/**
 * Parcelable wrapper for User
 * Since User is a data class, we create a wrapper for Parcelable support
 */
data class VaultUserParcelable(
    val id: String,
    val email: String,
    val name: String?
) : android.os.Parcelable {
    constructor(user: User) : this(
        id = user.id,
        email = user.email,
        name = user.getFullName()
    )

    constructor(parcel: android.os.Parcel) : this(
        id = parcel.readString() ?: "",
        email = parcel.readString() ?: "",
        name = parcel.readString()
    )

    override fun writeToParcel(parcel: android.os.Parcel, flags: Int) {
        parcel.writeString(id)
        parcel.writeString(email)
        parcel.writeString(name)
    }

    override fun describeContents(): Int = 0

    companion object CREATOR : android.os.Parcelable.Creator<VaultUserParcelable> {
        override fun createFromParcel(parcel: android.os.Parcel): VaultUserParcelable {
            return VaultUserParcelable(parcel)
        }

        override fun newArray(size: Int): Array<VaultUserParcelable?> {
            return arrayOfNulls(size)
        }
    }
}

/**
 * Vault theme configuration
 */
sealed class VaultTheme(val resourceId: Int) {
    object DEFAULT : VaultTheme(0)
    object LIGHT : VaultTheme(0) // Use default light theme
    object DARK : VaultTheme(0) // Use default dark theme
    class Custom(resId: Int) : VaultTheme(resId)
}
