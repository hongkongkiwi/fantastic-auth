import UIKit
import Combine

// MARK: - VaultSignupViewController

public class VaultSignupViewController: UIViewController {
    
    // MARK: - Properties
    
    public var onSignupSuccess: ((User) -> Void)?
    public var onSignupError: ((Error) -> Void)?
    public var onLoginTap: (() -> Void)?
    
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
        imageView.image = UIImage(systemName: "person.badge.plus")
        return imageView
    }()
    
    private lazy var titleLabel = VaultLabel(theme: theme, text: "Create Account", style: .title)
    private lazy var subtitleLabel = VaultLabel(theme: theme, text: "Sign up to get started", style: .subtitle)
    
    private lazy var nameTextField: VaultTextField = {
        let textField = VaultTextField(theme: theme, placeholder: "Full Name (Optional)")
        textField.translatesAutoresizingMaskIntoConstraints = false
        textField.textContentType = .name
        textField.autocapitalizationType = .words
        textField.returnKeyType = .next
        textField.delegate = self
        return textField
    }()
    
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
        textField.textContentType = .newPassword
        textField.returnKeyType = .next
        textField.delegate = self
        return textField
    }()
    
    private lazy var confirmPasswordTextField: VaultTextField = {
        let textField = VaultTextField(theme: theme, placeholder: "Confirm Password")
        textField.translatesAutoresizingMaskIntoConstraints = false
        textField.isSecureTextEntry = true
        textField.textContentType = .newPassword
        textField.returnKeyType = .done
        textField.delegate = self
        return textField
    }()
    
    private lazy var passwordStrengthView: PasswordStrengthView = {
        let view = PasswordStrengthView(theme: theme)
        view.translatesAutoresizingMaskIntoConstraints = false
        return view
    }()
    
    private lazy var showPasswordButton: UIButton = {
        let button = UIButton(type: .custom)
        button.translatesAutoresizingMaskIntoConstraints = false
        button.setImage(UIImage(systemName: "eye.slash"), for: .normal)
        button.tintColor = theme.secondaryTextColor
        button.addTarget(self, action: #selector(togglePasswordVisibility), for: .touchUpInside)
        return button
    }()
    
    private lazy var termsLabel: UILabel = {
        let label = UILabel()
        label.translatesAutoresizingMaskIntoConstraints = false
        label.font = theme.captionFont
        label.textColor = theme.secondaryTextColor
        label.numberOfLines = 0
        label.textAlignment = .center
        label.text = "By signing up, you agree to our Terms of Service and Privacy Policy"
        return label
    }()
    
    private lazy var signupButton: VaultButton = {
        let button = VaultButton(theme: theme, title: "Create Account", style: .primary)
        button.translatesAutoresizingMaskIntoConstraints = false
        button.addTarget(self, action: #selector(signupTapped), for: .touchUpInside)
        return button
    }()
    
    private lazy var loginStackView: UIStackView = {
        let label = UILabel()
        label.text = "Already have an account?"
        label.font = theme.captionFont
        label.textColor = theme.secondaryTextColor
        
        let button = UIButton(type: .system)
        button.setTitle("Sign In", for: .normal)
        button.titleLabel?.font = theme.captionFont
        button.setTitleColor(theme.primaryColor, for: .normal)
        button.addTarget(self, action: #selector(loginTapped), for: .touchUpInside)
        
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
        setupPasswordStrengthMonitoring()
    }
    
    // MARK: - Setup
    
    private func setupUI() {
        view.backgroundColor = theme.backgroundColor
        
        view.addSubview(scrollView)
        scrollView.addSubview(contentView)
        
        // Password visibility button
        passwordTextField.rightView = showPasswordButton
        passwordTextField.rightViewMode = .always
        
        // Add subviews
        [logoImageView, titleLabel, subtitleLabel, nameTextField, emailTextField,
         passwordTextField, passwordStrengthView, confirmPasswordTextField,
         errorLabel, termsLabel, signupButton, loginStackView]
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
            
            logoImageView.topAnchor.constraint(equalTo: contentView.topAnchor, constant: 40),
            logoImageView.centerXAnchor.constraint(equalTo: contentView.centerXAnchor),
            logoImageView.widthAnchor.constraint(equalToConstant: 60),
            logoImageView.heightAnchor.constraint(equalToConstant: 60),
            
            titleLabel.topAnchor.constraint(equalTo: logoImageView.bottomAnchor, constant: 24),
            titleLabel.leadingAnchor.constraint(equalTo: contentView.leadingAnchor, constant: theme.padding),
            titleLabel.trailingAnchor.constraint(equalTo: contentView.trailingAnchor, constant: -theme.padding),
            
            subtitleLabel.topAnchor.constraint(equalTo: titleLabel.bottomAnchor, constant: 8),
            subtitleLabel.leadingAnchor.constraint(equalTo: contentView.leadingAnchor, constant: theme.padding),
            subtitleLabel.trailingAnchor.constraint(equalTo: contentView.trailingAnchor, constant: -theme.padding),
            
            nameTextField.topAnchor.constraint(equalTo: subtitleLabel.bottomAnchor, constant: 32),
            nameTextField.leadingAnchor.constraint(equalTo: contentView.leadingAnchor, constant: theme.padding),
            nameTextField.trailingAnchor.constraint(equalTo: contentView.trailingAnchor, constant: -theme.padding),
            nameTextField.heightAnchor.constraint(equalToConstant: 50),
            
            emailTextField.topAnchor.constraint(equalTo: nameTextField.bottomAnchor, constant: 16),
            emailTextField.leadingAnchor.constraint(equalTo: contentView.leadingAnchor, constant: theme.padding),
            emailTextField.trailingAnchor.constraint(equalTo: contentView.trailingAnchor, constant: -theme.padding),
            emailTextField.heightAnchor.constraint(equalToConstant: 50),
            
            passwordTextField.topAnchor.constraint(equalTo: emailTextField.bottomAnchor, constant: 16),
            passwordTextField.leadingAnchor.constraint(equalTo: contentView.leadingAnchor, constant: theme.padding),
            passwordTextField.trailingAnchor.constraint(equalTo: contentView.trailingAnchor, constant: -theme.padding),
            passwordTextField.heightAnchor.constraint(equalToConstant: 50),
            
            showPasswordButton.widthAnchor.constraint(equalToConstant: 44),
            showPasswordButton.heightAnchor.constraint(equalToConstant: 44),
            
            passwordStrengthView.topAnchor.constraint(equalTo: passwordTextField.bottomAnchor, constant: 8),
            passwordStrengthView.leadingAnchor.constraint(equalTo: contentView.leadingAnchor, constant: theme.padding),
            passwordStrengthView.trailingAnchor.constraint(equalTo: contentView.trailingAnchor, constant: -theme.padding),
            passwordStrengthView.heightAnchor.constraint(equalToConstant: 4),
            
            confirmPasswordTextField.topAnchor.constraint(equalTo: passwordStrengthView.bottomAnchor, constant: 16),
            confirmPasswordTextField.leadingAnchor.constraint(equalTo: contentView.leadingAnchor, constant: theme.padding),
            confirmPasswordTextField.trailingAnchor.constraint(equalTo: contentView.trailingAnchor, constant: -theme.padding),
            confirmPasswordTextField.heightAnchor.constraint(equalToConstant: 50),
            
            errorLabel.topAnchor.constraint(equalTo: confirmPasswordTextField.bottomAnchor, constant: 12),
            errorLabel.leadingAnchor.constraint(equalTo: contentView.leadingAnchor, constant: theme.padding),
            errorLabel.trailingAnchor.constraint(equalTo: contentView.trailingAnchor, constant: -theme.padding),
            
            termsLabel.topAnchor.constraint(equalTo: errorLabel.bottomAnchor, constant: 16),
            termsLabel.leadingAnchor.constraint(equalTo: contentView.leadingAnchor, constant: theme.padding),
            termsLabel.trailingAnchor.constraint(equalTo: contentView.trailingAnchor, constant: -theme.padding),
            
            signupButton.topAnchor.constraint(equalTo: termsLabel.bottomAnchor, constant: 24),
            signupButton.leadingAnchor.constraint(equalTo: contentView.leadingAnchor, constant: theme.padding),
            signupButton.trailingAnchor.constraint(equalTo: contentView.trailingAnchor, constant: -theme.padding),
            signupButton.heightAnchor.constraint(equalToConstant: 50),
            
            loginStackView.topAnchor.constraint(equalTo: signupButton.bottomAnchor, constant: 24),
            loginStackView.centerXAnchor.constraint(equalTo: contentView.centerXAnchor),
            loginStackView.bottomAnchor.constraint(equalTo: contentView.bottomAnchor, constant: -40)
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
    
    private func setupPasswordStrengthMonitoring() {
        passwordTextField.addTarget(self, action: #selector(passwordChanged), for: .editingChanged)
    }
    
    // MARK: - Actions
    
    @objc private func signupTapped() {
        guard validateInputs() else { return }
        
        let name = nameTextField.text?.trimmingCharacters(in: .whitespacesAndNewlines)
        let email = emailTextField.text?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        let password = passwordTextField.text ?? ""
        
        showLoading()
        
        Task {
            do {
                let user = try await VaultAuth.shared.signup(email: email, password: password, name: name)
                hideLoading()
                onSignupSuccess?(user)
            } catch {
                hideLoading()
                showError(error.localizedDescription)
                onSignupError?(error)
            }
        }
    }
    
    @objc private func loginTapped() {
        onLoginTap?()
    }
    
    @objc private func togglePasswordVisibility() {
        passwordTextField.isSecureTextEntry.toggle()
        confirmPasswordTextField.isSecureTextEntry = passwordTextField.isSecureTextEntry
        let imageName = passwordTextField.isSecureTextEntry ? "eye.slash" : "eye"
        showPasswordButton.setImage(UIImage(systemName: imageName), for: .normal)
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
    
    @objc private func passwordChanged() {
        let strength = calculatePasswordStrength(passwordTextField.text ?? "")
        passwordStrengthView.setStrength(strength)
    }
    
    // MARK: - Private Methods
    
    private func validateInputs() -> Bool {
        let email = emailTextField.text?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        let password = passwordTextField.text ?? ""
        let confirmPassword = confirmPasswordTextField.text ?? ""
        
        if email.isEmpty {
            showError("Please enter your email")
            return false
        }
        
        if !isValidEmail(email) {
            showError("Please enter a valid email")
            return false
        }
        
        if password.count < 8 {
            showError("Password must be at least 8 characters")
            return false
        }
        
        if password != confirmPassword {
            showError("Passwords do not match")
            return false
        }
        
        hideError()
        return true
    }
    
    private func isValidEmail(_ email: String) -> Bool {
        let emailRegex = "[A-Z0-9a-z._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}"
        return NSPredicate(format: "SELF MATCHES %@", emailRegex).evaluate(with: email)
    }
    
    private func calculatePasswordStrength(_ password: String) -> PasswordStrength {
        var score = 0
        
        if password.count >= 8 { score += 1 }
        if password.count >= 12 { score += 1 }
        if password.rangeOfCharacter(from: .uppercaseLetters) != nil { score += 1 }
        if password.rangeOfCharacter(from: .lowercaseLetters) != nil { score += 1 }
        if password.rangeOfCharacter(from: .decimalDigits) != nil { score += 1 }
        if password.rangeOfCharacter(from: CharacterSet(charactersIn: "!@#$%^&*()_+-=[]{}|;:,.<>?")) != nil { score += 1 }
        
        switch score {
        case 0...2: return .weak
        case 3...4: return .fair
        case 5...6: return .good
        default: return .strong
        }
    }
    
    private func showError(_ message: String) {
        errorLabel.text = message
        errorLabel.isHidden = false
    }
    
    private func hideError() {
        errorLabel.isHidden = true
    }
    
    private func showLoading() {
        signupButton.isEnabled = false
        loadingView.show(in: view)
    }
    
    private func hideLoading() {
        signupButton.isEnabled = true
        loadingView.hide()
    }
}

// MARK: - UITextFieldDelegate

extension VaultSignupViewController: UITextFieldDelegate {
    public func textFieldShouldReturn(_ textField: UITextField) -> Bool {
        switch textField {
        case nameTextField:
            emailTextField.becomeFirstResponder()
        case emailTextField:
            passwordTextField.becomeFirstResponder()
        case passwordTextField:
            confirmPasswordTextField.becomeFirstResponder()
        case confirmPasswordTextField:
            dismissKeyboard()
            signupTapped()
        default:
            break
        }
        return true
    }
}

// MARK: - Password Strength

enum PasswordStrength {
    case weak
    case fair
    case good
    case strong
}

// MARK: - PasswordStrengthView

class PasswordStrengthView: UIView {
    private let theme: VaultTheme
    private let progressView = UIProgressView(progressViewStyle: .bar)
    
    init(theme: VaultTheme) {
        self.theme = theme
        super.init(frame: .zero)
        setup()
    }
    
    required init?(coder: NSCoder) {
        self.theme = .default
        super.init(coder: coder)
        setup()
    }
    
    private func setup() {
        progressView.translatesAutoresizingMaskIntoConstraints = false
        progressView.trackTintColor = theme.surfaceColor
        progressView.progress = 0
        
        addSubview(progressView)
        
        NSLayoutConstraint.activate([
            progressView.topAnchor.constraint(equalTo: topAnchor),
            progressView.leadingAnchor.constraint(equalTo: leadingAnchor),
            progressView.trailingAnchor.constraint(equalTo: trailingAnchor),
            progressView.bottomAnchor.constraint(equalTo: bottomAnchor)
        ])
    }
    
    func setStrength(_ strength: PasswordStrength) {
        switch strength {
        case .weak:
            progressView.progress = 0.25
            progressView.progressTintColor = theme.errorColor
        case .fair:
            progressView.progress = 0.5
            progressView.progressTintColor = .systemOrange
        case .good:
            progressView.progress = 0.75
            progressView.progressTintColor = .systemYellow
        case .strong:
            progressView.progress = 1.0
            progressView.progressTintColor = theme.successColor
        }
    }
}
