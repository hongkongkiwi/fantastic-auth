import Foundation
import Combine

/// A helper class for managing the current user's profile.
///
/// This provides reactive updates and convenient access to the current user.
@MainActor
public final class VaultProfile: ObservableObject {
    
    // MARK: - Properties
    
    /// The current user, if authenticated.
    @Published public private(set) var currentUser: VaultUser?
    
    /// Whether the profile is currently loading.
    @Published public private(set) var isLoading = false
    
    /// Any error that occurred while loading or updating.
    @Published public private(set) var error: VaultError?
    
    private let userService: VaultUserService
    private var cancellables = Set<AnyCancellable>()
    
    // MARK: - Initialization
    
    init() {
        self.userService = VaultUserService(apiClient: Vault.shared.apiClient)
        
        // Listen for session changes
        Vault.shared.session.statePublisher
            .sink { [weak self] state in
                switch state {
                case .authenticated(let user):
                    self?.currentUser = user
                case .unauthenticated:
                    self?.currentUser = nil
                case .refreshing:
                    break
                }
            }
            .store(in: &cancellables)
    }
    
    // MARK: - Public Methods
    
    /// Refreshes the current user's profile.
    ///
    /// This fetches the latest user data from the server.
    public func refresh() async {
        guard !isLoading else { return }
        
        isLoading = true
        error = nil
        
        do {
            let user = try await userService.getCurrentUser()
            self.currentUser = user
            
            // Update the session's user
            await Vault.shared.session.updateUser(user)
        } catch let vaultError as VaultError {
            self.error = vaultError
        } catch {
            self.error = .networkError(error)
        }
        
        isLoading = false
    }
    
    /// Updates the user's profile.
    ///
    /// - Parameters:
    ///   - firstName: Optional new first name
    ///   - lastName: Optional new last name
    ///   - phoneNumber: Optional phone number
    public func update(
        firstName: String? = nil,
        lastName: String? = nil,
        phoneNumber: String? = nil
    ) async {
        guard !isLoading else { return }
        
        isLoading = true
        error = nil
        
        do {
            let user = try await userService.updateProfile(
                firstName: firstName,
                lastName: lastName,
                phoneNumber: phoneNumber
            )
            self.currentUser = user
            await Vault.shared.session.updateUser(user)
        } catch let vaultError as VaultError {
            self.error = vaultError
        } catch {
            self.error = .networkError(error)
        }
        
        isLoading = false
    }
    
    /// Uploads a new profile image.
    ///
    /// - Parameter imageData: The image data
    public func uploadImage(_ imageData: Data) async {
        guard !isLoading else { return }
        
        isLoading = true
        error = nil
        
        do {
            let user = try await userService.uploadProfileImage(imageData)
            self.currentUser = user
            await Vault.shared.session.updateUser(user)
        } catch let vaultError as VaultError {
            self.error = vaultError
        } catch {
            self.error = .networkError(error)
        }
        
        isLoading = false
    }
    
    /// Deletes the user's profile image.
    public func deleteImage() async {
        guard !isLoading else { return }
        
        isLoading = true
        error = nil
        
        do {
            let user = try await userService.deleteProfileImage()
            self.currentUser = user
            await Vault.shared.session.updateUser(user)
        } catch let vaultError as VaultError {
            self.error = vaultError
        } catch {
            self.error = .networkError(error)
        }
        
        isLoading = false
    }
}

// MARK: - SwiftUI Extensions

import SwiftUI

public extension View {
    /// Observes the current user's profile and updates when it changes.
    func vaultProfile() -> some View {
        self.modifier(VaultProfileModifier())
    }
}

private struct VaultProfileModifier: ViewModifier {
    @StateObject private var profile = VaultProfile()
    
    func body(content: Content) -> some View {
        content
            .environmentObject(profile)
    }
}

// MARK: - Profile View Model

/// A view model for profile management screens.
@MainActor
public class ProfileViewModel: ObservableObject {
    
    // MARK: - Properties
    
    @Published public var firstName: String = ""
    @Published public var lastName: String = ""
    @Published public var phoneNumber: String = ""
    @Published public var isLoading = false
    @Published public var errorMessage: String?
    @Published public var isSuccess = false
    
    private let profile: VaultProfile
    
    // MARK: - Initialization
    
    public init(profile: VaultProfile = VaultProfile()) {
        self.profile = profile
        
        // Initialize fields from current user
        if let user = profile.currentUser {
            self.firstName = user.firstName ?? ""
            self.lastName = user.lastName ?? ""
        }
    }
    
    // MARK: - Methods
    
    /// Saves the profile changes.
    public func save() async {
        isLoading = true
        errorMessage = nil
        isSuccess = false
        
        await profile.update(
            firstName: firstName.isEmpty ? nil : firstName,
            lastName: lastName.isEmpty ? nil : lastName,
            phoneNumber: phoneNumber.isEmpty ? nil : phoneNumber
        )
        
        if let error = profile.error {
            errorMessage = error.localizedDescription
        } else {
            isSuccess = true
        }
        
        isLoading = false
    }
    
    /// Refreshes the profile data.
    public func refresh() async {
        isLoading = true
        await profile.refresh()
        
        if let user = profile.currentUser {
            self.firstName = user.firstName ?? ""
            self.lastName = user.lastName ?? ""
        }
        
        isLoading = false
    }
    
    /// Validates the form.
    public var isValid: Bool {
        // Add validation logic here
        true
    }
}
