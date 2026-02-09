import SwiftUI

// MARK: - VaultLoginView (SwiftUI)

@available(iOS 14.0, *)
public struct VaultLoginView: View {
    @StateObject private var viewModel = LoginViewModel()
    
    public var onSuccess: (User) -> Void
    public var onError: ((Error) -> Void)?
    public var onSignup: (() -> Void)?
    public var onForgotPassword: (() -> Void)?
    
    private let primaryColor: Color
    private let backgroundColor: Color
    
    public init(
        primaryColor: Color = .blue,
        backgroundColor: Color = Color(.systemBackground),
        onSuccess: @escaping (User) -> Void,
        onError: ((Error) -> Void)? = nil,
        onSignup: (() -> Void)? = nil,
        onForgotPassword: (() -> Void)? = nil
    ) {
        self.primaryColor = primaryColor
        self.backgroundColor = backgroundColor
        self.onSuccess = onSuccess
        self.onError = onError
        self.onSignup = onSignup
        self.onForgotPassword = onForgotPassword
    }
    
    public var body: some View {
        ScrollView {
            VStack(spacing: 20) {
                // Logo
                Image(systemName: "lock.shield.fill")
                    .resizable()
                    .scaledToFit()
                    .frame(width: 80, height: 80)
                    .foregroundColor(primaryColor)
                    .padding(.top, 40)
                
                // Title
                Text("Welcome Back")
                    .font(.largeTitle.bold())
                    .foregroundColor(.primary)
                
                Text("Sign in to your account")
                    .font(.body)
                    .foregroundColor(.secondary)
                
                // Error Message
                if let error = viewModel.errorMessage {
                    Text(error)
                        .font(.caption)
                        .foregroundColor(.red)
                        .multilineTextAlignment(.center)
                }
                
                // Form Fields
                VStack(spacing: 16) {
                    TextField("Email", text: $viewModel.email)
                        .textContentType(.username)
                        .keyboardType(.emailAddress)
                        .autocapitalization(.none)
                        .textFieldStyle(RoundedTextFieldStyle())
                    
                    SecureField("Password", text: $viewModel.password)
                        .textContentType(.password)
                        .textFieldStyle(RoundedTextFieldStyle())
                }
                .padding(.top, 20)
                
                // Biometric Login Button
                if viewModel.canUseBiometricLogin {
                    Button(action: { viewModel.loginWithBiometric() }) {
                        HStack {
                            Image(systemName: biometricIcon)
                            Text("Sign in with \(viewModel.biometricType)")
                        }
                        .frame(maxWidth: .infinity)
                        .padding()
                        .background(Color(.secondarySystemBackground))
                        .foregroundColor(primaryColor)
                        .cornerRadius(12)
                    }
                }
                
                // Login Button
                Button(action: { viewModel.login() }) {
                    if viewModel.isLoading {
                        ProgressView()
                            .progressViewStyle(CircularProgressViewStyle(tint: .white))
                    } else {
                        Text("Sign In")
                            .fontWeight(.semibold)
                    }
                }
                .frame(maxWidth: .infinity)
                .padding()
                .background(primaryColor)
                .foregroundColor(.white)
                .cornerRadius(12)
                .disabled(viewModel.isLoading || !viewModel.isValid)
                .opacity(viewModel.isLoading || !viewModel.isValid ? 0.6 : 1)
                
                // Forgot Password
                Button("Forgot Password?") {
                    onForgotPassword?()
                }
                .font(.footnote)
                .foregroundColor(primaryColor)
                
                Spacer()
                
                // Sign Up Link
                HStack {
                    Text("Don't have an account?")
                        .font(.footnote)
                        .foregroundColor(.secondary)
                    
                    Button("Sign Up") {
                        onSignup?()
                    }
                    .font(.footnote)
                    .foregroundColor(primaryColor)
                }
                .padding(.bottom, 20)
            }
            .padding(.horizontal, 24)
        }
        .background(backgroundColor.ignoresSafeArea())
        .onChange(of: viewModel.user) { user in
            if let user = user {
                onSuccess(user)
            }
        }
        .onChange(of: viewModel.error) { error in
            if let error = error {
                onError?(error)
            }
        }
        .sheet(isPresented: $viewModel.showMFA) {
            MFASheetView(viewModel: viewModel)
        }
    }
    
    private var biometricIcon: String {
        switch BiometricAuth.shared.biometricType {
        case .faceID:
            return "faceid"
        case .touchID:
            return "touchid"
        default:
            return "lock"
        }
    }
}

// MARK: - LoginViewModel

@available(iOS 14.0, *)
class LoginViewModel: ObservableObject {
    @Published var email = ""
    @Published var password = ""
    @Published var isLoading = false
    @Published var errorMessage: String?
    @Published var user: User?
    @Published var error: Error?
    @Published var showMFA = false
    @Published var mfaCode = ""
    
    var isValid: Bool {
        !email.isEmpty && !password.isEmpty && isValidEmail(email)
    }
    
    var canUseBiometricLogin: Bool {
        BiometricAuth.shared.canUseBiometricLogin
    }
    
    var biometricType: String {
        BiometricAuth.shared.biometricType.displayName
    }
    
    func login() {
        guard isValid else { return }
        
        isLoading = true
        errorMessage = nil
        
        Task {
            do {
                let user = try await VaultAuth.shared.login(email: email, password: password)
                await MainActor.run {
                    self.user = user
                    self.isLoading = false
                }
            } catch VaultAuthError.mfaRequired {
                await MainActor.run {
                    self.showMFA = true
                    self.isLoading = false
                }
            } catch {
                await MainActor.run {
                    self.error = error
                    self.errorMessage = error.localizedDescription
                    self.isLoading = false
                }
            }
        }
    }
    
    func loginWithBiometric() {
        isLoading = true
        errorMessage = nil
        
        Task {
            do {
                let user = try await VaultAuth.shared.loginWithBiometric()
                await MainActor.run {
                    self.user = user
                    self.isLoading = false
                }
            } catch {
                await MainActor.run {
                    self.error = error
                    self.errorMessage = error.localizedDescription
                    self.isLoading = false
                }
            }
        }
    }
    
    func verifyMFA() {
        guard !mfaCode.isEmpty else { return }
        
        isLoading = true
        
        Task {
            do {
                let user = try await VaultAuth.shared.verifyMFA(code: mfaCode)
                await MainActor.run {
                    self.user = user
                    self.showMFA = false
                    self.isLoading = false
                }
            } catch {
                await MainActor.run {
                    self.errorMessage = error.localizedDescription
                    self.isLoading = false
                }
            }
        }
    }
    
    private func isValidEmail(_ email: String) -> Bool {
        let emailRegex = "[A-Z0-9a-z._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}"
        return NSPredicate(format: "SELF MATCHES %@", emailRegex).evaluate(with: email)
    }
}

// MARK: - MFASheetView

@available(iOS 14.0, *)
struct MFASheetView: View {
    @ObservedObject var viewModel: LoginViewModel
    
    var body: some View {
        NavigationView {
            VStack(spacing: 24) {
                Image(systemName: "lock.shield")
                    .font(.system(size: 60))
                    .foregroundColor(.blue)
                
                Text("Two-Factor Authentication")
                    .font(.title2.bold())
                
                Text("Enter the verification code from your authenticator app")
                    .font(.body)
                    .foregroundColor(.secondary)
                    .multilineTextAlignment(.center)
                
                TextField("Code", text: $viewModel.mfaCode)
                    .keyboardType(.numberPad)
                    .textFieldStyle(RoundedTextFieldStyle())
                    .frame(maxWidth: 200)
                
                if let error = viewModel.errorMessage {
                    Text(error)
                        .font(.caption)
                        .foregroundColor(.red)
                }
                
                Button(action: { viewModel.verifyMFA() }) {
                    if viewModel.isLoading {
                        ProgressView()
                    } else {
                        Text("Verify")
                            .fontWeight(.semibold)
                    }
                }
                .frame(maxWidth: .infinity)
                .padding()
                .background(Color.blue)
                .foregroundColor(.white)
                .cornerRadius(12)
                .disabled(viewModel.isLoading || viewModel.mfaCode.isEmpty)
                .padding(.horizontal, 40)
                
                Spacer()
            }
            .padding()
            .navigationBarItems(trailing: Button("Cancel") {
                viewModel.showMFA = false
            })
        }
    }
}

// MARK: - RoundedTextFieldStyle

@available(iOS 14.0, *)
struct RoundedTextFieldStyle: TextFieldStyle {
    func _body(configuration: TextField<Self._Label>) -> some View {
        configuration
            .padding()
            .background(Color(.secondarySystemBackground))
            .cornerRadius(8)
    }
}

// MARK: - VaultSignupView

@available(iOS 14.0, *)
public struct VaultSignupView: View {
    @StateObject private var viewModel = SignupViewModel()
    
    public var onSuccess: (User) -> Void
    public var onError: ((Error) -> Void)?
    public var onLogin: (() -> Void)?
    
    private let primaryColor: Color
    
    public init(
        primaryColor: Color = .blue,
        onSuccess: @escaping (User) -> Void,
        onError: ((Error) -> Void)? = nil,
        onLogin: (() -> Void)? = nil
    ) {
        self.primaryColor = primaryColor
        self.onSuccess = onSuccess
        self.onError = onError
        self.onLogin = onLogin
    }
    
    public var body: some View {
        ScrollView {
            VStack(spacing: 20) {
                Image(systemName: "person.badge.plus")
                    .resizable()
                    .scaledToFit()
                    .frame(width: 60, height: 60)
                    .foregroundColor(primaryColor)
                    .padding(.top, 40)
                
                Text("Create Account")
                    .font(.largeTitle.bold())
                
                Text("Sign up to get started")
                    .font(.body)
                    .foregroundColor(.secondary)
                
                if let error = viewModel.errorMessage {
                    Text(error)
                        .font(.caption)
                        .foregroundColor(.red)
                        .multilineTextAlignment(.center)
                }
                
                VStack(spacing: 16) {
                    TextField("Full Name (Optional)", text: $viewModel.name)
                        .textContentType(.name)
                        .textFieldStyle(RoundedTextFieldStyle())
                    
                    TextField("Email", text: $viewModel.email)
                        .textContentType(.username)
                        .keyboardType(.emailAddress)
                        .autocapitalization(.none)
                        .textFieldStyle(RoundedTextFieldStyle())
                    
                    SecureField("Password", text: $viewModel.password)
                        .textContentType(.newPassword)
                        .textFieldStyle(RoundedTextFieldStyle())
                    
                    SecureField("Confirm Password", text: $viewModel.confirmPassword)
                        .textContentType(.newPassword)
                        .textFieldStyle(RoundedTextFieldStyle())
                }
                .padding(.top, 20)
                
                // Password strength indicator
                GeometryReader { geometry in
                    ZStack(alignment: .leading) {
                        RoundedRectangle(cornerRadius: 2)
                            .fill(Color(.systemGray5))
                            .frame(height: 4)
                        
                        RoundedRectangle(cornerRadius: 2)
                            .fill(viewModel.passwordStrengthColor)
                            .frame(width: geometry.size.width * viewModel.passwordStrengthProgress, height: 4)
                    }
                }
                .frame(height: 4)
                
                Button(action: { viewModel.signup() }) {
                    if viewModel.isLoading {
                        ProgressView()
                            .progressViewStyle(CircularProgressViewStyle(tint: .white))
                    } else {
                        Text("Create Account")
                            .fontWeight(.semibold)
                    }
                }
                .frame(maxWidth: .infinity)
                .padding()
                .background(primaryColor)
                .foregroundColor(.white)
                .cornerRadius(12)
                .disabled(viewModel.isLoading || !viewModel.isValid)
                .opacity(viewModel.isLoading || !viewModel.isValid ? 0.6 : 1)
                
                Spacer()
                
                HStack {
                    Text("Already have an account?")
                        .font(.footnote)
                        .foregroundColor(.secondary)
                    
                    Button("Sign In") {
                        onLogin?()
                    }
                    .font(.footnote)
                    .foregroundColor(primaryColor)
                }
                .padding(.bottom, 20)
            }
            .padding(.horizontal, 24)
        }
        .onChange(of: viewModel.user) { user in
            if let user = user {
                onSuccess(user)
            }
        }
        .onChange(of: viewModel.error) { error in
            if let error = error {
                onError?(error)
            }
        }
    }
}

// MARK: - SignupViewModel

@available(iOS 14.0, *)
class SignupViewModel: ObservableObject {
    @Published var name = ""
    @Published var email = ""
    @Published var password = ""
    @Published var confirmPassword = ""
    @Published var isLoading = false
    @Published var errorMessage: String?
    @Published var user: User?
    @Published var error: Error?
    
    var isValid: Bool {
        !email.isEmpty && isValidEmail(email) &&
        password.count >= 8 &&
        password == confirmPassword
    }
    
    var passwordStrengthProgress: CGFloat {
        switch calculatePasswordStrength() {
        case .weak: return 0.25
        case .fair: return 0.5
        case .good: return 0.75
        case .strong: return 1.0
        }
    }
    
    var passwordStrengthColor: Color {
        switch calculatePasswordStrength() {
        case .weak: return .red
        case .fair: return .orange
        case .good: return .yellow
        case .strong: return .green
        }
    }
    
    func signup() {
        guard isValid else {
            if password != confirmPassword {
                errorMessage = "Passwords do not match"
            } else if password.count < 8 {
                errorMessage = "Password must be at least 8 characters"
            }
            return
        }
        
        isLoading = true
        errorMessage = nil
        
        Task {
            do {
                let userName = name.isEmpty ? nil : name
                let user = try await VaultAuth.shared.signup(
                    email: email,
                    password: password,
                    name: userName
                )
                await MainActor.run {
                    self.user = user
                    self.isLoading = false
                }
            } catch {
                await MainActor.run {
                    self.error = error
                    self.errorMessage = error.localizedDescription
                    self.isLoading = false
                }
            }
        }
    }
    
    private func isValidEmail(_ email: String) -> Bool {
        let emailRegex = "[A-Z0-9a-z._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}"
        return NSPredicate(format: "SELF MATCHES %@", emailRegex).evaluate(with: email)
    }
    
    private func calculatePasswordStrength() -> PasswordStrength {
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
}
