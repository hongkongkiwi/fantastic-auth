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
 * Pre-built signup activity for Vault authentication
 * 
 * Usage:
 * ```kotlin
 * val intent = VaultSignupActivity.createIntent(context)
 * startActivityForResult(intent, REQUEST_SIGNUP)
 * ```
 */
open class VaultSignupActivity : AppCompatActivity() {

    private lateinit var nameInput: TextInputEditText
    private lateinit var nameLayout: TextInputLayout
    private lateinit var emailInput: TextInputEditText
    private lateinit var emailLayout: TextInputLayout
    private lateinit var passwordInput: TextInputEditText
    private lateinit var passwordLayout: TextInputLayout
    private lateinit var confirmPasswordInput: TextInputEditText
    private lateinit var confirmPasswordLayout: TextInputLayout
    private lateinit var signupButton: MaterialButton
    private lateinit var loginButton: MaterialButton
    private lateinit var progressBar: ProgressBar

    companion object {
        const val EXTRA_USER = "user"
        const val EXTRA_ERROR = "error"
        const val EXTRA_REQUIRE_NAME = "require_name"

        /**
         * Create an intent to launch the signup activity
         * 
         * @param context The context
         * @param requireName Whether to require the name field
         * @return The intent
         */
        @JvmStatic
        @JvmOverloads
        fun createIntent(context: Context, requireName: Boolean = false): Intent {
            return Intent(context, VaultSignupActivity::class.java).apply {
                putExtra(EXTRA_REQUIRE_NAME, requireName)
            }
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_vault_signup)

        initViews()
        setupListeners()
        
        val requireName = intent.getBooleanExtra(EXTRA_REQUIRE_NAME, false)
        if (!requireName) {
            nameLayout.visibility = View.GONE
        }
    }

    private fun initViews() {
        nameInput = findViewById(R.id.name_input)
        nameLayout = findViewById(R.id.name_layout)
        emailInput = findViewById(R.id.email_input)
        emailLayout = findViewById(R.id.email_layout)
        passwordInput = findViewById(R.id.password_input)
        passwordLayout = findViewById(R.id.password_layout)
        confirmPasswordInput = findViewById(R.id.confirm_password_input)
        confirmPasswordLayout = findViewById(R.id.confirm_password_layout)
        signupButton = findViewById(R.id.signup_button)
        loginButton = findViewById(R.id.login_button)
        progressBar = findViewById(R.id.progress_bar)
    }

    private fun setupListeners() {
        // Clear errors on text change
        nameInput.addTextChangedListener { nameLayout.error = null }
        emailInput.addTextChangedListener { emailLayout.error = null }
        passwordInput.addTextChangedListener { passwordLayout.error = null }
        confirmPasswordInput.addTextChangedListener { confirmPasswordLayout.error = null }

        // Signup button click
        signupButton.setOnClickListener {
            if (validateInputs()) {
                performSignup()
            }
        }

        // Login button click
        loginButton.setOnClickListener {
            openLogin()
        }
    }

    private fun validateInputs(): Boolean {
        var valid = true

        // Validate name if visible
        if (nameLayout.visibility == View.VISIBLE) {
            val name = nameInput.text?.toString()?.trim() ?: ""
            if (name.isEmpty()) {
                nameLayout.error = "Name is required"
                valid = false
            }
        }

        // Validate email
        val email = emailInput.text?.toString()?.trim() ?: ""
        if (email.isEmpty()) {
            emailLayout.error = "Email is required"
            valid = false
        } else if (!android.util.Patterns.EMAIL_ADDRESS.matcher(email).matches()) {
            emailLayout.error = "Invalid email format"
            valid = false
        }

        // Validate password
        val password = passwordInput.text?.toString() ?: ""
        if (password.isEmpty()) {
            passwordLayout.error = "Password is required"
            valid = false
        } else if (password.length < 8) {
            passwordLayout.error = "Password must be at least 8 characters"
            valid = false
        } else if (!isPasswordStrong(password)) {
            passwordLayout.error = "Password must contain uppercase, lowercase, and a number"
            valid = false
        }

        // Validate confirm password
        val confirmPassword = confirmPasswordInput.text?.toString() ?: ""
        if (confirmPassword.isEmpty()) {
            confirmPasswordLayout.error = "Please confirm your password"
            valid = false
        } else if (confirmPassword != password) {
            confirmPasswordLayout.error = "Passwords do not match"
            valid = false
        }

        return valid
    }

    private fun isPasswordStrong(password: String): Boolean {
        val hasUppercase = password.any { it.isUpperCase() }
        val hasLowercase = password.any { it.isLowerCase() }
        val hasDigit = password.any { it.isDigit() }
        return hasUppercase && hasLowercase && hasDigit
    }

    private fun performSignup() {
        val name = nameInput.text?.toString()?.trim()
        val email = emailInput.text?.toString()?.trim() ?: return
        val password = passwordInput.text?.toString() ?: return

        setLoading(true)

        lifecycleScope.launch {
            try {
                val user = VaultAuth.getInstance().signup(email, password, name)
                onSignupSuccess(user)
            } catch (e: VaultAuthException) {
                onSignupError(e)
            } finally {
                setLoading(false)
            }
        }
    }

    /**
     * Called when signup is successful
     * Override this method to customize the success behavior
     */
    protected open fun onSignupSuccess(user: User) {
        val resultIntent = Intent().apply {
            putExtra(EXTRA_USER, VaultUserParcelable(user))
        }
        setResult(RESULT_OK, resultIntent)
        finish()
    }

    /**
     * Called when signup fails
     * Override this method to customize the error handling
     */
    protected open fun onSignupError(error: VaultAuthException) {
        val errorMessage = when (error) {
            is VaultAuthException.InvalidConfiguration -> "SDK not configured"
            is VaultAuthException.NetworkError -> "Network error. Please check your connection."
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
     * Open login activity
     * Override this method to customize the login flow
     */
    protected open fun openLogin() {
        finish() // By default, just finish to go back to login
    }

    private fun setLoading(loading: Boolean) {
        progressBar.visibility = if (loading) View.VISIBLE else View.GONE
        signupButton.isEnabled = !loading
        loginButton.isEnabled = !loading
        nameInput.isEnabled = !loading
        emailInput.isEnabled = !loading
        passwordInput.isEnabled = !loading
        confirmPasswordInput.isEnabled = !loading
    }
}
