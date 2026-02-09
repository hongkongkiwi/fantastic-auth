#
# To learn more about a Podspec see http://guides.cocoapods.org/syntax/podspec.html.
# Run `pod lib lint vault_sdk.podspec` to validate before publishing.
#
Pod::Spec.new do |s|
  s.name             = 'vault_sdk'
  s.version          = '0.1.0'
  s.summary          = 'Vault SDK for Flutter'
  s.description      = <<-DESC
A comprehensive Flutter SDK for Vault - a secure, quantum-resistant user authentication and management system.
                       DESC
  s.homepage         = 'https://github.com/yourorg/vault'
  s.license          = { :file => '../LICENSE' }
  s.author           = { 'Vault Team' => 'support@vault.dev' }
  s.source           = { :path => '.' }
  s.source_files = 'Classes/**/*'
  s.dependency 'Flutter'
  s.dependency 'LocalAuthentication'
  s.platform = :ios, '12.0'

  # Flutter.framework does not contain a i386 slice.
  s.pod_target_xcconfig = { 'DEFINES_MODULE' => 'YES', 'EXCLUDED_ARCHS[sdk=iphonesimulator*]' => 'i386' }
  s.swift_version = '5.0'
end
