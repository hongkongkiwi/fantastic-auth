import SwiftUI
import Vault

struct ContentView: View {
    @StateObject private var sessionObserver = SessionObserver()
    
    var body: some View {
        Group {
            if sessionObserver.isAuthenticated {
                HomeView()
            } else {
                SignInView()
            }
        }
        .environmentObject(sessionObserver)
    }
}

// MARK: - Sign In View

struct SignInView: View {
    @State private var email = ""
    @State private var password = ""
    @State private var isLoading = false
    @State private var errorMessage: String?
    @State private var showingSignUp = false
    
    var body: some View {
        NavigationView {
            VStack(spacing: 20) {
                Image(systemName: "lock.shield")
                    .font(.system(size: 80))
                    .foregroundColor(.accentColor)
                    .padding(.bottom, 20)
                
                Text("Welcome to Vault")
                    .font(.largeTitle)
                    .fontWeight(.bold)
                
                VStack(spacing: 16) {
                    TextField("Email", text: $email)
                        .textContentType(.emailAddress)
                        .keyboardType(.emailAddress)
                        .autocapitalization(.none)
                        .disableAutocorrection(true)
                        .textFieldStyle(RoundedBorderTextFieldStyle())
                    
                    SecureField("Password", text: $password)
                        .textContentType(.password)
                        .textFieldStyle(RoundedBorderTextFieldStyle())
                }
                .padding(.horizontal)
                
                if let error = errorMessage {
                    Text(error)
                        .foregroundColor(.red)
                        .font(.caption)
                }
                
                Button(action: signIn) {
                    if isLoading {
                        ProgressView()
                            .progressViewStyle(CircularProgressViewStyle(tint: .white))
                    } else {
                        Text("Sign In")
                            .fontWeight(.semibold)
                    }
                }
                .frame(maxWidth: .infinity)
                .padding()
                .background(Color.accentColor)
                .foregroundColor(.white)
                .cornerRadius(10)
                .disabled(email.isEmpty || password.isEmpty || isLoading)
                .padding(.horizontal)
                
                // Biometric Sign In
                BiometricButton()
                
                // OAuth Buttons
                VStack(spacing: 12) {
                    OAuthButton(provider: .apple)
                    OAuthButton(provider: .google)
                }
                .padding(.top)
                
                Spacer()
                
                Button("Create Account") {
                    showingSignUp = true
                }
                .sheet(isPresented: $showingSignUp) {
                    SignUpView()
                }
            }
            .padding()
        }
    }
    
    private func signIn() {
        Task {
            isLoading = true
            errorMessage = nil
            
            do {
                _ = try await Vault.shared.auth.signIn(
                    email: email,
                    password: password
                )
            } catch VaultError.unauthorized {
                errorMessage = "Invalid email or password"
            } catch VaultError.networkError {
                errorMessage = "Network error. Please try again."
            } catch {
                errorMessage = error.localizedDescription
            }
            
            isLoading = false
        }
    }
}

// MARK: - Biometric Button

struct BiometricButton: View {
    let biometric = Vault.shared.biometric
    @State private var isLoading = false
    
    var body: some View {
        if biometric.isAvailable && biometric.isKeyRegistered {
            Button(action: signIn) {
                HStack {
                    Image(systemName: biometric.biometricType.iconName)
                    Text("Sign in with \(biometric.biometricType.displayName)")
                }
                .frame(maxWidth: .infinity)
                .padding()
                .background(Color.secondary.opacity(0.1))
                .foregroundColor(.primary)
                .cornerRadius(10)
            }
            .disabled(isLoading)
            .padding(.horizontal)
        }
    }
    
    private func signIn() {
        Task {
            isLoading = true
            do {
                _ = try await Vault.shared.auth.signInWithBiometric()
            } catch {
                // Handle error
            }
            isLoading = false
        }
    }
}

// MARK: - OAuth Button

struct OAuthButton: View {
    let provider: OAuthProvider
    @State private var isLoading = false
    
    var body: some View {
        Button(action: signIn) {
            HStack {
                Image(systemName: provider.iconName)
                Text("Continue with \(provider.displayName)")
            }
            .frame(maxWidth: .infinity)
            .padding()
            .background(Color.secondary.opacity(0.1))
            .foregroundColor(.primary)
            .cornerRadius(10)
        }
        .disabled(isLoading)
        .padding(.horizontal)
    }
    
    private func signIn() {
        Task {
            isLoading = true
            do {
                _ = try await Vault.shared.oauth.signIn(with: provider)
            } catch {
                // Handle error
            }
            isLoading = false
        }
    }
}

// MARK: - Sign Up View

struct SignUpView: View {
    @Environment(\.presentationMode) var presentationMode
    @State private var email = ""
    @State private var password = ""
    @State private var confirmPassword = ""
    @State private var firstName = ""
    @State private var lastName = ""
    @State private var isLoading = false
    @State private var errorMessage: String?
    
    private var isValid: Bool {
        !email.isEmpty &&
        !password.isEmpty &&
        password == confirmPassword &&
        password.count >= 8
    }
    
    var body: some View {
        NavigationView {
            Form {
                Section("Personal Info") {
                    TextField("First Name", text: $firstName)
                    TextField("Last Name", text: $lastName)
                }
                
                Section("Account") {
                    TextField("Email", text: $email)
                        .textContentType(.emailAddress)
                        .keyboardType(.emailAddress)
                        .autocapitalization(.none)
                    
                    SecureField("Password", text: $password)
                    SecureField("Confirm Password", text: $confirmPassword)
                    
                    if password != confirmPassword && !confirmPassword.isEmpty {
                        Text("Passwords do not match")
                            .font(.caption)
                            .foregroundColor(.red)
                    }
                }
                
                if let error = errorMessage {
                    Section {
                        Text(error)
                            .foregroundColor(.red)
                    }
                }
                
                Section {
                    Button(action: signUp) {
                        if isLoading {
                            ProgressView()
                        } else {
                            Text("Create Account")
                        }
                    }
                    .disabled(!isValid || isLoading)
                }
            }
            .navigationTitle("Create Account")
            .navigationBarItems(trailing: Button("Cancel") {
                presentationMode.wrappedValue.dismiss()
            })
        }
    }
    
    private func signUp() {
        Task {
            isLoading = true
            errorMessage = nil
            
            do {
                _ = try await Vault.shared.auth.signUp(
                    email: email,
                    password: password,
                    firstName: firstName.isEmpty ? nil : firstName,
                    lastName: lastName.isEmpty ? nil : lastName
                )
                presentationMode.wrappedValue.dismiss()
            } catch VaultError.conflict(let message) {
                errorMessage = message
            } catch VaultError.validationFailed(let errors) {
                errorMessage = errors.values.flatMap { $0 }.joined(separator: ", ")
            } catch {
                errorMessage = error.localizedDescription
            }
            
            isLoading = false
        }
    }
}

// MARK: - Home View

struct HomeView: View {
    @EnvironmentObject var sessionObserver: SessionObserver
    @StateObject private var profile = VaultProfile()
    @State private var showingSettings = false
    
    var body: some View {
        NavigationView {
            List {
                // User Profile Section
                Section {
                    HStack {
                        ProfileImage(user: profile.currentUser)
                            .frame(width: 60, height: 60)
                        
                        VStack(alignment: .leading) {
                            Text(profile.currentUser?.fullName ?? "User")
                                .font(.headline)
                            Text(profile.currentUser?.email ?? "")
                                .font(.subheadline)
                                .foregroundColor(.secondary)
                        }
                    }
                    .padding(.vertical, 8)
                }
                
                // Organizations Section
                Section("Organizations") {
                    OrganizationsList()
                }
                
                // Actions
                Section {
                    Button(action: { showingSettings = true }) {
                        Label("Settings", systemImage: "gear")
                    }
                    
                    Button(action: signOut) {
                        Label("Sign Out", systemImage: "arrow.right.square")
                            .foregroundColor(.red)
                    }
                }
            }
            .navigationTitle("Vault")
            .task {
                await profile.refresh()
            }
            .sheet(isPresented: $showingSettings) {
                SettingsView()
            }
        }
    }
    
    private func signOut() {
        Task {
            await Vault.shared.session.signOut()
        }
    }
}

// MARK: - Profile Image

struct ProfileImage: View {
    let user: VaultUser?
    
    var body: some View {
        ZStack {
            Circle()
                .fill(Color.accentColor.opacity(0.2))
            
            Text(user?.initials ?? "U")
                .font(.system(size: 24, weight: .medium))
                .foregroundColor(.accentColor)
        }
    }
}

// MARK: - Organizations List

struct OrganizationsList: View {
    @State private var organizations: [VaultOrganizationMembership] = []
    @State private var isLoading = false
    
    var body: some View {
        Group {
            if organizations.isEmpty {
                Text("No organizations")
                    .foregroundColor(.secondary)
            } else {
                ForEach(organizations) { org in
                    HStack {
                        VStack(alignment: .leading) {
                            Text(org.name)
                                .font(.headline)
                            Text(org.role.displayName)
                                .font(.caption)
                                .foregroundColor(.secondary)
                        }
                        
                        Spacer()
                        
                        if org.isActive {
                            Image(systemName: "checkmark.circle.fill")
                                .foregroundColor(.accentColor)
                        }
                    }
                    .contentShape(Rectangle())
                    .onTapGesture {
                        selectOrganization(org)
                    }
                }
            }
        }
        .task {
            await loadOrganizations()
        }
    }
    
    private func loadOrganizations() async {
        isLoading = true
        do {
            organizations = try await Vault.shared.organizations.list()
        } catch {
            // Handle error
        }
        isLoading = false
    }
    
    private func selectOrganization(_ org: VaultOrganizationMembership) {
        Task {
            try? await Vault.shared.organizations.setActive(org.id)
            await loadOrganizations()
        }
    }
}

// MARK: - Settings View

struct SettingsView: View {
    @Environment(\.presentationMode) var presentationMode
    @State private var useBiometric = false
    let biometric = Vault.shared.biometric
    
    var body: some View {
        NavigationView {
            Form {
                Section("Security") {
                    if biometric.isAvailable {
                        Toggle("Use \(biometric.biometricType.displayName)", isOn: $useBiometric)
                            .onChange(of: useBiometric) { newValue in
                                Task {
                                    if newValue {
                                        try? await Vault.shared.auth.registerBiometric()
                                    } else {
                                        try? await Vault.shared.auth.unregisterBiometric()
                                    }
                                }
                            }
                    }
                }
                
                Section("Account") {
                    Button("Change Password") {
                        // Show change password
                    }
                    
                    Button("Manage Linked Accounts") {
                        // Show linked accounts
                    }
                }
            }
            .navigationTitle("Settings")
            .navigationBarItems(trailing: Button("Done") {
                presentationMode.wrappedValue.dismiss()
            })
            .task {
                useBiometric = biometric.isKeyRegistered
            }
        }
    }
}

// MARK: - Preview

struct ContentView_Previews: PreviewProvider {
    static var previews: some View {
        ContentView()
    }
}
