import 'package:flutter_test/flutter_test.dart';
import 'package:vault_sdk/vault.dart';

void main() {
  group('Vault', () {
    tearDown(() async {
      // Clean up after each test
      try {
        await Vault.reset();
      } catch (_) {}
    });

    test('should throw when accessing instance before initialization', () {
      expect(
        () => Vault.instance,
        throwsA(isA<VaultConfigurationException>()),
      );
    });

    test('should initialize correctly', () {
      Vault.initialize(
        apiUrl: 'https://api.vault.dev',
        tenantId: 'test-tenant',
      );

      expect(Vault.isInitialized, true);
      expect(Vault.instance.apiUrl, 'https://api.vault.dev');
      expect(Vault.instance.tenantId, 'test-tenant');
    });

    test('should throw when initialized twice', () {
      Vault.initialize(apiUrl: 'https://api.vault.dev');

      expect(
        () => Vault.initialize(apiUrl: 'https://api.vault.dev'),
        throwsA(isA<VaultConfigurationException>()),
      );
    });

    test('should validate API URL', () {
      expect(
        () => Vault.initialize(apiUrl: ''),
        throwsA(isA<VaultConfigurationException>()),
      );

      expect(
        () => Vault.initialize(apiUrl: 'invalid-url'),
        throwsA(isA<VaultConfigurationException>()),
      );
    });
  });

  group('VaultUser', () {
    test('should create from JSON', () {
      final json = {
        'id': 'usr_123',
        'email': 'test@example.com',
        'emailVerified': true,
        'name': 'Test User',
        'mfaEnabled': false,
      };

      final user = VaultUser.fromJson(json);

      expect(user.id, 'usr_123');
      expect(user.email, 'test@example.com');
      expect(user.emailVerified, true);
      expect(user.name, 'Test User');
      expect(user.mfaEnabled, false);
    });

    test('should convert to JSON', () {
      const user = VaultUser(
        id: 'usr_123',
        email: 'test@example.com',
        emailVerified: true,
      );

      final json = user.toJson();

      expect(json['id'], 'usr_123');
      expect(json['email'], 'test@example.com');
      expect(json['emailVerified'], true);
    });

    test('should calculate display name correctly', () {
      const userWithName = VaultUser(
        id: 'usr_123',
        email: 'test@example.com',
        emailVerified: true,
        name: 'Test User',
      );

      expect(userWithName.displayName, 'Test User');

      const userWithoutName = VaultUser(
        id: 'usr_123',
        email: 'test@example.com',
        emailVerified: true,
      );

      expect(userWithoutName.displayName, 'test@example.com');
    });

    test('should calculate initials correctly', () {
      const user = VaultUser(
        id: 'usr_123',
        email: 'test@example.com',
        emailVerified: true,
        name: 'John Doe',
      );

      expect(user.initials, 'JD');
    });
  });

  group('Organization', () {
    test('should create from JSON', () {
      final json = {
        'id': 'org_123',
        'name': 'Test Org',
        'slug': 'test-org',
        'memberCount': 5,
        'ssoRequired': false,
        'createdAt': '2024-01-01T00:00:00Z',
        'updatedAt': '2024-01-01T00:00:00Z',
      };

      final org = Organization.fromJson(json);

      expect(org.id, 'org_123');
      expect(org.name, 'Test Org');
      expect(org.slug, 'test-org');
      expect(org.memberCount, 5);
    });
  });

  group('OAuthProvider', () {
    test('should return correct names', () {
      expect(OAuthProvider.google.name, 'google');
      expect(OAuthProvider.apple.name, 'apple');
      expect(OAuthProvider.github.name, 'github');
    });

    test('should return correct display names', () {
      expect(OAuthProvider.google.displayName, 'Google');
      expect(OAuthProvider.apple.displayName, 'Apple');
      expect(OAuthProvider.github.displayName, 'GitHub');
    });
  });

  group('OrganizationRole', () {
    test('should parse from string correctly', () {
      expect(OrganizationRole.fromString('owner'), OrganizationRole.owner);
      expect(OrganizationRole.fromString('admin'), OrganizationRole.admin);
      expect(OrganizationRole.fromString('member'), OrganizationRole.member);
      expect(OrganizationRole.fromString('guest'), OrganizationRole.guest);
    });

    test('should handle unknown role', () {
      expect(OrganizationRole.fromString('unknown'), OrganizationRole.member);
    });

    test('should check permissions correctly', () {
      expect(OrganizationRole.owner.canManageMembers, true);
      expect(OrganizationRole.admin.canManageMembers, true);
      expect(OrganizationRole.member.canManageMembers, false);

      expect(OrganizationRole.owner.canDeleteOrganization, true);
      expect(OrganizationRole.admin.canDeleteOrganization, false);
    });
  });

  group('Exceptions', () {
    test('VaultException should format correctly', () {
      final exception = VaultException(
        'Test error',
        code: 'TEST_CODE',
        statusCode: 400,
      );

      expect(exception.toString(), contains('Test error'));
      expect(exception.toString(), contains('TEST_CODE'));
      expect(exception.toString(), contains('400'));
    });

    test('VaultAuthException should be a VaultException', () {
      final exception = VaultAuthException('Auth failed');

      expect(exception, isA<VaultException>());
    });

    test('VaultRateLimitException should calculate seconds until reset', () {
      final now = DateTime.now().millisecondsSinceEpoch ~/ 1000;
      final exception = VaultRateLimitException(
        'Rate limited',
        resetTimestamp: now + 60,
      );

      expect(exception.secondsUntilReset, lessThanOrEqualTo(60));
    });
  });
}
