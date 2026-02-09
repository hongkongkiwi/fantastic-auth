import UIKit
import Combine

// MARK: - VaultLoginViewController

public class VaultLoginViewController: UIViewController {
    
    // MARK: - Properties
    
    public var onLoginSuccess: ((User) -> Void)?
    public var onLoginError: ((Error) -> Void)?
    public var onSignupTap: (() -> Void)?
    public var onForgotPasswordTap: (() -> Void)?
    
    private let theme: VaultTheme
    private var cancellables = Set<AnyCancellable>()
    
    // MARK: - UI Components
    
    private lazy var scrollView: UIScrollView = {
        let scrollView = UIScrollView()
        scrollView.translatesAutoresizingMaskIntoConstraints = false
        scrollView.keyboardDismissMode = .interactive
        return scrollView
    }()
    
    private lazy var contentView: UIView = {
        let view = UIView()
        view.translatesAutoresizingMaskIntoConstraints = false
        return view
    }()
    
    private lazy var logoImageView: UIImageView = {
        let imageView = UIImageView()
        imageView.translatesAutoresizingMaskIntoConstraints = false
        imageView.contentMode = .scaleAspectFit
        imageView.tintColor = theme.primaryColor
        imageView.image = UIImage(systemName: "lock.shield.fill")
        return imageView
    }()
    
    private lazy var titleLabel = VaultLabel(theme: theme, text: "Welcome Back", style: .title)
    private lazy var subtitleLabel = VaultLabel(theme: theme, text: "Sign in to your account", style: .subtitle)
    
    private lazy var emailTextField: VaultTextField = {
        let textField = VaultTextField(theme: theme, placeholder: "Email")
        textField.translatesAutoresizingMaskIntoConstraints = false
        textField.keyboardType = .emailAddress
        textField.textContentType = .username
        textField.autocapitalizationType = .none
        textField.returnKeyType = .next
        textField.delegate = self
        return textField
    }()
    
    private lazy var passwordTextField: VaultTextField = {
        let textField = VaultTextField(theme: theme, placeholder: "Password")
        textField.translatesAutoresizingMaskIntoConstraints = false
        textField.isSecureTextEntry = true
        textField.textContentType = .password
        textField.returnKeyType = .done
        textField.delegate = self
        return textField
    }()
    
    private lazy var showPasswordButton: UIButton = {
        let button = UIButton(type: .custom)
        button.translatesAutoresizingMaskIntoConstraints = false
        button.setImage(UIImage(systemName: "eye.slash"), for: .normal)
        button.tintColor = theme.secondaryTextColor
        button.addTarget(self, action: #selector(togglePasswordVisibility), for: .touchUpInside)
        return button
    }()
    
    private lazy var biometricButton: VaultButton = {
        let type = BiometricAuth.shared.biometricType
        let button = VaultButton(theme: theme, title: "Sign in with \(type.displayName)", style: .secondary)
        button.translatesAutoresizingMaskIntoConstraints = false
        button.isHidden = !BiometricAuth.shared.canUseBiometricLogin
        button.addTarget(self, action: #selector(biometricLoginTapped), for: .touchUpInside)
        return button
    }()
    
    private lazy var loginButton: VaultButton = {
        let button = VaultButton(theme: theme, title: "Sign In", style: .primary)
        button.translatesAutoresizingMaskIntoConstraints = false
        button.addTarget(self, action: #selector(loginTapped), for: .touchUpInside)
        return button
    }()
    
    private lazy var forgotPasswordButton: VaultButton = {
        let button = VaultButton(theme: theme, title: "Forgot Password?", style: .text)
        button.translatesAutoresizingMaskIntoConstraints = false
        button.addTarget(self, action: #selector(forgotPasswordTapped), for: .touchUpInside)
        return button
    }()
    
    private lazy var signupStackView: UIStackView = {
        let label = UILabel()
        label.text = "Don't have an account?"
        label.font = theme.captionFont
        label.textColor = theme.secondaryTextColor
        
        let button = UIButton(type: .system)
        button.setTitle("Sign Up", for: .normal)
        button.titleLabel?.font = theme.captionFont
        button.setTitleColor(theme.primaryColor, for: .normal)
        button.addTarget(self, action: #selector(signupTapped), for: .touchUpInside)
        
        let stackView = UIStackView(arrangedSubviews: [label, button])
        stackView.translatesAutoresizingMaskIntoConstraints = false
        stackView.axis = .horizontal
        stackView.spacing = 4
        stackView.alignment = .center
        return stackView
    }()
    
    private lazy var errorLabel: VaultLabel = {
        let label = VaultLabel(theme: theme, style: .error)
        label.translatesAutoresizingMaskIntoConstraints = false
        label.isHidden = true
        return label
    }()
    
    private let loadingView = LoadingView()
    
    // MARK: - Initialization
    
    public init(theme: VaultTheme = .default) {
        self.theme = theme
        super.init(nibName: nil, bundle: nil)
    }
    
    required init?(coder: NSCoder) {
        self.theme = .default
        super.init(coder: coder)
    }
    
    // MARK: - Lifecycle
    
    public override func viewDidLoad() {
        super.viewDidLoad()
        setupUI()
        setupKeyboardHandling()
        
        // Update biometric button visibility when biometric state changes
        NotificationCenter.default.publisher(for: .biometricLoginEnabled)
            .merge(with: NotificationCenter.default.publisher(for: .biometricLoginDisabled))
            .receive(on: DispatchQueue.main)
            .sink { [weak self] _ in
                self?.updateBiometricButton()
            }
            .store(in: &cancellables)
    }
    
    public override func viewWillAppear(_ animated: Bool) {
        super.viewWillAppear(animated)
        updateBiometricButton()
    }
    
    // MARK: - Setup
    
    private func setupUI() {
        view.backgroundColor = theme.backgroundColor
        
        view.addSubview(scrollView)
        scrollView.addSubview(contentView)
        
        // Password visibility button
        passwordTextField.rightView = showPasswordButton
        passwordTextField.rightViewMode = .always
        
        // Add subviews to content
        [logoImageView, titleLabel, subtitleLabel, emailTextField, passwordTextField,
         errorLabel, loginButton, biometricButton, forgotPasswordButton, signupStackView]
            .forEach { contentView.addSubview($0) }
        
        NSLayoutConstraint.activate([
            scrollView.topAnchor.constraint(equalTo: view.topAnchor),
            scrollView.leadingAnchor.constraint(equalTo: view.leadingAnchor),
            scrollView.trailingAnchor.constraint(equalTo: view.trailingAnchor),
            scrollView.bottomAnchor.constraint(equalTo: view.bottomAnchor),
            
            contentView.topAnchor.constraint(equalTo: scrollView.topAnchor),
            contentView.leadingAnchor.constraint(equalTo: scrollView.leadingAnchor),
            contentView.trailingAnchor.constraint(equalTo: scrollView.trailingAnchor),
            contentView.bottomAnchor.constraint(equalTo: scrollView.bottomAnchor),
            contentView.widthAnchor.constraint(equalTo: scrollView.widthAnchor),
            
            logoImageView.topAnchor.constraint(equalTo: contentView.topAnchor, constant: 60),
            logoImageView.centerXAnchor.constraint(equalTo: contentView.centerXAnchor),
            logoImageView.widthAnchor.constraint(equalToConstant: 80),
            logoImageView.heightAnchor.constraint(equalToConstant: 80),
            
            titleLabel.topAnchor.constraint(equalTo: logoImageView.bottomAnchor, constant: 24),
            titleLabel.leadingAnchor.constraint(equalTo: contentView.leadingAnchor, constant: theme.padding),
            titleLabel.trailingAnchor.constraint(equalTo: contentView.trailingAnchor, constant: -theme.padding),
            
            subtitleLabel.topAnchor.constraint(equalTo: titleLabel.bottomAnchor, constant: 8),
            subtitleLabel.leadingAnchor.constraint(equalTo: contentView.leadingAnchor, constant: theme.padding),
            subtitleLabel.trailingAnchor.constraint(equalTo: contentView.trailingAnchor, constant: -theme.padding),
            
            emailTextField.topAnchor.constraint(equalTo: subtitleLabel.bottomAnchor, constant: 40),
            emailTextField.leadingAnchor.constraint(equalTo: contentView.leadingAnchor, constant: theme.padding),
            emailTextField.trailingAnchor.constraint(equalTo: contentView.trailingAnchor, constant: -theme.padding),
            emailTextField.heightAnchor.constraint(equalToConstant: 50),
            
            passwordTextField.topAnchor.constraint(equalTo: emailTextField.bottomAnchor, constant: 16),
            passwordTextField.leadingAnchor.constraint(equalTo: contentView.leadingAnchor, constant: theme.padding),
            passwordTextField.trailingAnchor.constraint(equalTo: contentView.trailingAnchor, constant: -theme.padding),
            passwordTextField.heightAnchor.constraint(equalToConstant: 50),
            
            showPasswordButton.widthAnchor.constraint(equalToConstant: 44),
            showPasswordButton.heightAnchor.constraint(equalToConstant: 44),
            
            errorLabel.topAnchor.constraint(equalTo: passwordTextField.bottomAnchor, constant: 12),
            errorLabel.leadingAnchor.constraint(equalTo: contentView.leadingAnchor, constant: theme.padding),
            errorLabel.trailingAnchor.constraint(equalTo: contentView.trailingAnchor, constant: -theme.padding),
            
            loginButton.topAnchor.constraint(equalTo: errorLabel.bottomAnchor, constant: 24),
            loginButton.leadingAnchor.constraint(equalTo: contentView.leadingAnchor, constant: theme.padding),
            loginButton.trailingAnchor.constraint(equalTo: contentView.trailingAnchor, constant: -theme.padding),
            loginButton.heightAnchor.constraint(equalToConstant: 50),
            
            biometricButton.topAnchor.constraint(equalTo: loginButton.bottomAnchor, constant: 12),
            biometricButton.leadingAnchor.constraint(equalTo: contentView.leadingAnchor, constant: theme.padding),
            biometricButton.trailingAnchor.constraint(equalTo: contentView.trailingAnchor, constant: -theme.padding),
            
            forgotPasswordButton.topAnchor.constraint(equalTo: biometricButton.bottomAnchor, constant: 8),
            forgotPasswordButton.centerXAnchor.constraint(equalTo: contentView.centerXAnchor),
            
            signupStackView.topAnchor.constraint(equalTo: forgotPasswordButton.bottomAnchor, constant: 24),
            signupStackView.centerXAnchor.constraint(equalTo: contentView.centerXAnchor),
            signupStackView.bottomAnchor.constraint(equalTo: contentView.bottomAnchor, constant: -40)
        ])
    }
    
    private func setupKeyboardHandling() {
        NotificationCenter.default.addObserver(
            self,
            selector: #selector(keyboardWillShow),
            name: UIResponder.keyboardWillShowNotification,
            object: nil
        )
        NotificationCenter.default.addObserver(
            self,
            selector: #selector(keyboardWillHide),
            name: UIResponder.keyboardWillHideNotification,
            object: nil
        )
        
        let tapGesture = UITapGestureRecognizer(target: self, action: #selector(dismissKeyboard))
        view.addGestureRecognizer(tapGesture)
    }
    
    // MARK: - Actions
    
    @objc private func loginTapped() {
        guard validateInputs() else { return }
        
        let email = emailTextField.text?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        let password = passwordTextField.text ?? ""
        
        showLoading()
        
        Task {
            do {
                let user = try await VaultAuth.shared.login(email: email, password: password)
                hideLoading()
                onLoginSuccess?(user)
            } catch VaultAuthError.mfaRequired {
                hideLoading()
                showMFAEntry()
            } catch {
                hideLoading()
                showError(error.localizedDescription)
                onLoginError?(error)
            }
        }
    }
    
    @objc private func biometricLoginTapped() {
        showLoading()
        
        Task {
            do {
                let user = try await VaultAuth.shared.loginWithBiometric()
                hideLoading()
                onLoginSuccess?(user)
            } catch {
                hideLoading()
                showError(error.localizedDescription)
                onLoginError?(error)
            }
        }
    }
    
    @objc private func togglePasswordVisibility() {
        passwordTextField.isSecureTextEntry.toggle()
        let imageName = passwordTextField.isSecureTextEntry ? "eye.slash" : "eye"
        showPasswordButton.setImage(UIImage(systemName: imageName), for: .normal)
    }
    
    @objc private func forgotPasswordTapped() {
        onForgotPasswordTap?()
    }
    
    @objc private func signupTapped() {
        onSignupTap?()
    }
    
    @objc private func dismissKeyboard() {
        view.endEditing(true)
    }
    
    @objc private func keyboardWillShow(notification: Notification) {
        guard let keyboardFrame = notification.userInfo?[UIResponder.keyboardFrameEndUserInfoKey] as? CGRect else {
            return
        }
        scrollView.contentInset.bottom = keyboardFrame.height
    }
    
    @objc private func keyboardWillHide(notification: Notification) {
        scrollView.contentInset.bottom = 0
    }
    
    // MARK: - Private Methods
    
    private func validateInputs() -> Bool {
        let email = emailTextField.text?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        let password = passwordTextField.text ?? ""
        
        if email.isEmpty {
            showError("Please enter your email")
            return false
        }
        
        if !isValidEmail(email) {
            showError("Please enter a valid email")
            return false
        }
        
        if password.isEmpty {
            showError("Please enter your password")
            return false
        }
        
        hideError()
        return true
    }
    
    private func isValidEmail(_ email: String) -> Bool {
        let emailRegex = "[A-Z0-9a-z._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}"
        return NSPredicate(format: "SELF MATCHES %@", emailRegex).evaluate(with: email)
    }
    
    private func showError(_ message: String) {
        errorLabel.text = message
        errorLabel.isHidden = false
    }
    
    private func hideError() {
        errorLabel.isHidden = true
    }
    
    private func showLoading() {
        loginButton.isEnabled = false
        biometricButton.isEnabled = false
        loadingView.show(in: view)
    }
    
    private func hideLoading() {
        loginButton.isEnabled = true
        biometricButton.isEnabled = true
        loadingView.hide()
    }
    
    private func updateBiometricButton() {
        let type = BiometricAuth.shared.biometricType
        biometricButton.setTitle("Sign in with \(type.displayName)", for: .normal)
        biometricButton.isHidden = !BiometricAuth.shared.canUseBiometricLogin
    }
    
    private func showMFAEntry() {
        // Present MFA entry view or call delegate
        let alert = UIAlertController(
            title: "Two-Factor Authentication",
            message: "Please enter the verification code from your authenticator app",
            preferredStyle: .alert
        )
        
        alert.addTextField { textField in
            textField.placeholder = "Code"
            textField.keyboardType = .numberPad
        }
        
        alert.addAction(UIAlertAction(title: "Cancel", style: .cancel))
        alert.addAction(UIAlertAction(title: "Verify", style: .default) { [weak self] _ in
            guard let code = alert.textFields?.first?.text else { return }
            
            Task {
                do {
                    let user = try await VaultAuth.shared.verifyMFA(code: code)
                    await MainActor.run {
                        self?.onLoginSuccess?(user)
                    }
                } catch {
                    await MainActor.run {
                        self?.showError(error.localizedDescription)
                        self?.onLoginError?(error)
                    }
                }
            }
        })
        
        present(alert, animated: true)
    }
}

// MARK: - UITextFieldDelegate

extension VaultLoginViewController: UITextFieldDelegate {
    public func textFieldShouldReturn(_ textField: UITextField) -> Bool {
        if textField == emailTextField {
            passwordTextField.becomeFirstResponder()
        } else if textField == passwordTextField {
            dismissKeyboard()
            loginTapped()
        }
        return true
    }
}
