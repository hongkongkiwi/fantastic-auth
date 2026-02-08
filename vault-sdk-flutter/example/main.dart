import 'package:flutter/material.dart';
import 'package:vault_sdk/vault.dart';

void main() {
  // Initialize Vault SDK
  Vault.initialize(
    apiUrl: 'https://api.vault.dev',
    tenantId: 'my-tenant',
  );

  runApp(const VaultExampleApp());
}

class VaultExampleApp extends StatelessWidget {
  const VaultExampleApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Vault SDK Example',
      theme: ThemeData(
        colorScheme: ColorScheme.fromSeed(seedColor: Colors.blue),
        useMaterial3: true,
      ),
      home: const AuthScreen(),
    );
  }
}

/// Authentication screen
class AuthScreen extends StatefulWidget {
  const AuthScreen({super.key});

  @override
  State<AuthScreen> createState() => _AuthScreenState();
}

class _AuthScreenState extends State<AuthScreen> {
  final _emailController = TextEditingController();
  final _passwordController = TextEditingController();
  final _auth = VaultAuth();
  final _session = VaultSession();
  final _biometric = VaultBiometric();

  bool _isLoading = false;
  String? _error;
  bool _isBiometricAvailable = false;

  @override
  void initState() {
    super.initState();
    _checkBiometricAvailability();
    _checkExistingSession();
  }

  Future<void> _checkBiometricAvailability() async {
    final available = await _biometric.isAvailable();
    setState(() {
      _isBiometricAvailable = available;
    });
  }

  Future<void> _checkExistingSession() async {
    final isAuthenticated = await _session.isAuthenticated();
    if (isAuthenticated && mounted) {
      Navigator.of(context).pushReplacement(
        MaterialPageRoute(builder: (_) => const HomeScreen()),
      );
    }
  }

  Future<void> _signInWithEmail() async {
    setState(() {
      _isLoading = true;
      _error = null;
    });

    try {
      final result = await _auth.signInWithEmail(
        email: _emailController.text.trim(),
        password: _passwordController.text,
      );

      if (result.success && mounted) {
        Navigator.of(context).pushReplacement(
          MaterialPageRoute(builder: (_) => const HomeScreen()),
        );
      } else if (result.mfaRequired) {
        // Handle MFA
        _showMfaDialog(result.availableMethods);
      }
    } on VaultException catch (e) {
      setState(() {
        _error = e.message;
      });
    } finally {
      setState(() {
        _isLoading = false;
      });
    }
  }

  Future<void> _signInWithBiometric() async {
    setState(() {
      _isLoading = true;
      _error = null;
    });

    try {
      final session = await _biometric.authenticateWithBiometrics();
      if (session != null && mounted) {
        Navigator.of(context).pushReplacement(
          MaterialPageRoute(builder: (_) => const HomeScreen()),
        );
      }
    } on VaultBiometricException catch (e) {
      setState(() {
        _error = e.message;
      });
    } finally {
      setState(() {
        _isLoading = false;
      });
    }
  }

  Future<void> _signInWithOAuth(OAuthProvider provider) async {
    setState(() {
      _isLoading = true;
      _error = null;
    });

    try {
      await _auth.signInWithOAuth(provider: provider);
      // OAuth flow continues in external browser/app
      // The callback should be handled by deep linking
    } on VaultException catch (e) {
      setState(() {
        _error = e.message;
        _isLoading = false;
      });
    }
  }

  Future<void> _sendMagicLink() async {
    final email = _emailController.text.trim();
    if (email.isEmpty) return;

    setState(() {
      _isLoading = true;
      _error = null;
    });

    try {
      await _auth.sendMagicLink(email);
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(content: Text('Magic link sent! Check your email.')),
        );
      }
    } on VaultException catch (e) {
      setState(() {
        _error = e.message;
      });
    } finally {
      setState(() {
        _isLoading = false;
      });
    }
  }

  void _showMfaDialog(List<String> methods) {
    showDialog(
      context: context,
      builder: (context) => MfaDialog(
        methods: methods,
        onSubmit: (code) async {
          Navigator.pop(context);
          // Retry sign in with MFA code
          try {
            final result = await _auth.signInWithEmail(
              email: _emailController.text.trim(),
              password: _passwordController.text,
              mfaCode: code,
            );

            if (result.success && mounted) {
              Navigator.of(context).pushReplacement(
                MaterialPageRoute(builder: (_) => const HomeScreen()),
              );
            }
          } on VaultException catch (e) {
            setState(() {
              _error = e.message;
            });
          }
        },
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Vault SDK Example'),
      ),
      body: Padding(
        padding: const EdgeInsets.all(16.0),
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            TextField(
              controller: _emailController,
              decoration: const InputDecoration(
                labelText: 'Email',
                border: OutlineInputBorder(),
              ),
              keyboardType: TextInputType.emailAddress,
            ),
            const SizedBox(height: 16),
            TextField(
              controller: _passwordController,
              decoration: const InputDecoration(
                labelText: 'Password',
                border: OutlineInputBorder(),
              ),
              obscureText: true,
            ),
            const SizedBox(height: 8),
            Align(
              alignment: Alignment.centerRight,
              child: TextButton(
                onPressed: () async {
                  final email = _emailController.text.trim();
                  if (email.isNotEmpty) {
                    await _auth.sendPasswordResetEmail(email);
                    ScaffoldMessenger.of(context).showSnackBar(
                      const SnackBar(
                        content: Text('Password reset email sent!'),
                      ),
                    );
                  }
                },
                child: const Text('Forgot password?'),
              ),
            ),
            if (_error != null)
              Padding(
                padding: const EdgeInsets.only(bottom: 16),
                child: Text(
                  _error!,
                  style: const TextStyle(color: Colors.red),
                  textAlign: TextAlign.center,
                ),
              ),
            ElevatedButton(
              onPressed: _isLoading ? null : _signInWithEmail,
              child: _isLoading
                  ? const SizedBox(
                      height: 20,
                      width: 20,
                      child: CircularProgressIndicator(strokeWidth: 2),
                    )
                  : const Text('Sign In'),
            ),
            const SizedBox(height: 8),
            TextButton(
              onPressed: _isLoading ? null : _sendMagicLink,
              child: const Text('Send Magic Link'),
            ),
            if (_isBiometricAvailable) ...[
              const SizedBox(height: 16),
              ElevatedButton.icon(
                onPressed: _isLoading ? null : _signInWithBiometric,
                icon: const Icon(Icons.fingerprint),
                label: const Text('Sign In with Biometrics'),
              ),
            ],
            const SizedBox(height: 24),
            const Divider(),
            const SizedBox(height: 8),
            const Text(
              'Or continue with:',
              textAlign: TextAlign.center,
              style: TextStyle(color: Colors.grey),
            ),
            const SizedBox(height: 16),
            Row(
              mainAxisAlignment: MainAxisAlignment.spaceEvenly,
              children: [
                _OAuthButton(
                  icon: Icons.g_mobiledata,
                  label: 'Google',
                  onPressed: () => _signInWithOAuth(OAuthProvider.google),
                ),
                _OAuthButton(
                  icon: Icons.apple,
                  label: 'Apple',
                  onPressed: () => _signInWithOAuth(OAuthProvider.apple),
                ),
                _OAuthButton(
                  icon: Icons.code,
                  label: 'GitHub',
                  onPressed: () => _signInWithOAuth(OAuthProvider.github),
                ),
              ],
            ),
          ],
        ),
      ),
    );
  }

  @override
  void dispose() {
    _emailController.dispose();
    _passwordController.dispose();
    super.dispose();
  }
}

/// OAuth button widget
class _OAuthButton extends StatelessWidget {
  final IconData icon;
  final String label;
  final VoidCallback onPressed;

  const _OAuthButton({
    required this.icon,
    required this.label,
    required this.onPressed,
  });

  @override
  Widget build(BuildContext context) {
    return Column(
      children: [
        IconButton(
          onPressed: onPressed,
          icon: Icon(icon),
          iconSize: 32,
        ),
        Text(label, style: const TextStyle(fontSize: 12)),
      ],
    );
  }
}

/// MFA dialog
class MfaDialog extends StatefulWidget {
  final List<String> methods;
  final Function(String code) onSubmit;

  const MfaDialog({
    super.key,
    required this.methods,
    required this.onSubmit,
  });

  @override
  State<MfaDialog> createState() => _MfaDialogState();
}

class _MfaDialogState extends State<MfaDialog> {
  final _codeController = TextEditingController();

  @override
  Widget build(BuildContext context) {
    return AlertDialog(
      title: const Text('Two-Factor Authentication'),
      content: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          const Text('Enter your authentication code:'),
          const SizedBox(height: 16),
          TextField(
            controller: _codeController,
            decoration: const InputDecoration(
              labelText: 'Code',
              border: OutlineInputBorder(),
            ),
            keyboardType: TextInputType.number,
            maxLength: 6,
          ),
        ],
      ),
      actions: [
        TextButton(
          onPressed: () => Navigator.pop(context),
          child: const Text('Cancel'),
        ),
        ElevatedButton(
          onPressed: () {
            widget.onSubmit(_codeController.text);
          },
          child: const Text('Verify'),
        ),
      ],
    );
  }

  @override
  void dispose() {
    _codeController.dispose();
    super.dispose();
  }
}

/// Home screen (shown after authentication)
class HomeScreen extends StatefulWidget {
  const HomeScreen({super.key});

  @override
  State<HomeScreen> createState() => _HomeScreenState();
}

class _HomeScreenState extends State<HomeScreen> {
  final _session = VaultSession();
  final _orgs = VaultOrganizations();
  final _auth = VaultAuth();
  final _biometric = VaultBiometric();

  VaultUser? _user;
  List<Organization> _organizations = [];
  bool _isBiometricEnabled = false;
  bool _isLoading = true;

  @override
  void initState() {
    super.initState();
    _loadData();
  }

  Future<void> _loadData() async {
    final user = await _session.getCurrentUser();
    final orgs = await _orgs.list();
    final biometricEnabled = await _biometric.isBiometricLoginEnabled();

    setState(() {
      _user = user;
      _organizations = orgs;
      _isBiometricEnabled = biometricEnabled;
      _isLoading = false;
    });
  }

  Future<void> _signOut() async {
    await _session.signOut();
    if (mounted) {
      Navigator.of(context).pushReplacement(
        MaterialPageRoute(builder: (_) => const AuthScreen()),
      );
    }
  }

  Future<void> _toggleBiometric() async {
    try {
      if (_isBiometricEnabled) {
        await _biometric.disableBiometricLogin();
      } else {
        await _biometric.enableBiometricLogin();
      }
      setState(() {
        _isBiometricEnabled = !_isBiometricEnabled;
      });
    } on VaultException catch (e) {
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text(e.message)),
      );
    }
  }

  Future<void> _createOrganization() async {
    final result = await showDialog<Map<String, String>>(
      context: context,
      builder: (context) => const CreateOrgDialog(),
    );

    if (result != null) {
      try {
        await _orgs.create(
          name: result['name']!,
          slug: result['slug']!,
          description: result['description'],
        );
        _loadData(); // Refresh list
      } on VaultException catch (e) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text(e.message)),
        );
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Dashboard'),
        actions: [
          IconButton(
            onPressed: _signOut,
            icon: const Icon(Icons.logout),
            tooltip: 'Sign Out',
          ),
        ],
      ),
      body: _isLoading
          ? const Center(child: CircularProgressIndicator())
          : SingleChildScrollView(
              padding: const EdgeInsets.all(16),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  // User profile card
                  Card(
                    child: Padding(
                      padding: const EdgeInsets.all(16),
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          Row(
                            children: [
                              CircleAvatar(
                                child: Text(_user?.initials ?? '?'),
                              ),
                              const SizedBox(width: 16),
                              Expanded(
                                child: Column(
                                  crossAxisAlignment: CrossAxisAlignment.start,
                                  children: [
                                    Text(
                                      _user?.displayName ?? 'Unknown',
                                      style: Theme.of(context)
                                          .textTheme
                                          .titleLarge,
                                    ),
                                    Text(_user?.email ?? ''),
                                  ],
                                ),
                              ),
                            ],
                          ),
                          const SizedBox(height: 8),
                          if (_user?.emailVerified == true)
                            const Chip(
                              label: Text('Verified'),
                              avatar: Icon(Icons.verified, size: 18),
                            ),
                        ],
                      ),
                    ),
                  ),
                  const SizedBox(height: 24),

                  // Biometric settings
                  const Text(
                    'Security',
                    style: TextStyle(fontSize: 18, fontWeight: FontWeight.bold),
                  ),
                  const SizedBox(height: 8),
                  SwitchListTile(
                    title: const Text('Biometric Login'),
                    subtitle: const Text('Use Face ID or fingerprint to sign in'),
                    value: _isBiometricEnabled,
                    onChanged: (value) => _toggleBiometric(),
                  ),
                  const SizedBox(height: 24),

                  // Organizations
                  Row(
                    mainAxisAlignment: MainAxisAlignment.spaceBetween,
                    children: [
                      const Text(
                        'Organizations',
                        style: TextStyle(
                            fontSize: 18, fontWeight: FontWeight.bold),
                      ),
                      IconButton(
                        onPressed: _createOrganization,
                        icon: const Icon(Icons.add),
                        tooltip: 'Create Organization',
                      ),
                    ],
                  ),
                  const SizedBox(height: 8),
                  if (_organizations.isEmpty)
                    const Card(
                      child: Padding(
                        padding: EdgeInsets.all(16),
                        child: Text('No organizations yet'),
                      ),
                    )
                  else
                    ..._organizations.map((org) => Card(
                          child: ListTile(
                            leading: org.logoUrl != null
                                ? CircleAvatar(
                                    backgroundImage: NetworkImage(org.logoUrl!),
                                  )
                                : CircleAvatar(
                                    child: Text(org.name[0]),
                                  ),
                            title: Text(org.name),
                            subtitle: Text('${org.memberCount} members'),
                            trailing: org.ssoRequired
                                ? const Chip(label: Text('SSO'))
                                : null,
                            onTap: () {
                              // Navigate to organization details
                            },
                          ),
                        )),
                ],
              ),
            ),
    );
  }
}

/// Create organization dialog
class CreateOrgDialog extends StatefulWidget {
  const CreateOrgDialog({super.key});

  @override
  State<CreateOrgDialog> createState() => _CreateOrgDialogState();
}

class _CreateOrgDialogState extends State<CreateOrgDialog> {
  final _nameController = TextEditingController();
  final _slugController = TextEditingController();
  final _descriptionController = TextEditingController();

  @override
  Widget build(BuildContext context) {
    return AlertDialog(
      title: const Text('Create Organization'),
      content: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          TextField(
            controller: _nameController,
            decoration: const InputDecoration(
              labelText: 'Name',
              border: OutlineInputBorder(),
            ),
          ),
          const SizedBox(height: 16),
          TextField(
            controller: _slugController,
            decoration: const InputDecoration(
              labelText: 'Slug (URL-friendly)',
              border: OutlineInputBorder(),
              hintText: 'my-organization',
            ),
          ),
          const SizedBox(height: 16),
          TextField(
            controller: _descriptionController,
            decoration: const InputDecoration(
              labelText: 'Description (optional)',
              border: OutlineInputBorder(),
            ),
            maxLines: 2,
          ),
        ],
      ),
      actions: [
        TextButton(
          onPressed: () => Navigator.pop(context),
          child: const Text('Cancel'),
        ),
        ElevatedButton(
          onPressed: () {
            Navigator.pop(context, {
              'name': _nameController.text,
              'slug': _slugController.text,
              'description': _descriptionController.text.isEmpty
                  ? null
                  : _descriptionController.text,
            });
          },
          child: const Text('Create'),
        ),
      ],
    );
  }

  @override
  void dispose() {
    _nameController.dispose();
    _slugController.dispose();
    _descriptionController.dispose();
    super.dispose();
  }
}
