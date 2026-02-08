Pod::Spec.new do |spec|
  spec.name         = "VaultAuth"
  spec.version      = "1.0.0"
  spec.summary      = "Native iOS SDK for Vault authentication"
  spec.description  = <<-DESC
    VaultAuth provides a complete authentication solution for iOS applications,
    including secure token storage, biometric authentication, MFA support,
    push notifications, and pre-built UI components.
  DESC
  
  spec.homepage     = "https://github.com/vault/ios-sdk"
  spec.license      = { :type => "MIT", :file => "LICENSE" }
  spec.author       = { "Vault" => "support@vault.example.com" }
  
  spec.platform     = :ios, "13.0"
  spec.swift_version = "5.7"
  
  spec.source       = { 
    :git => "https://github.com/vault/ios-sdk.git", 
    :tag => "#{spec.version}" 
  }
  
  spec.source_files = "Sources/VaultAuth/**/*.swift"
  spec.frameworks   = "Foundation", "UIKit", "LocalAuthentication", "Security"
  
  spec.requires_arc = true
end
