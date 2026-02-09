import SwiftUI
import Vault

@main
struct VaultExampleApp: App {
    
    init() {
        // Configure Vault SDK
        Vault.configure(
            apiUrl: "https://api.vault.dev",
            tenantId: "your-tenant-id",
            debugMode: true
        )
    }
    
    var body: some Scene {
        WindowGroup {
            ContentView()
                .observeVaultSession()
        }
    }
}
