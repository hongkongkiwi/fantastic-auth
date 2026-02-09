import UIKit
import Combine

// MARK: - VaultProfileViewController

public class VaultProfileViewController: UIViewController {
    
    // MARK: - Properties
    
    public var onLogout: (() -> Void)?
    public var onDeleteAccount: (() -> Void)?
    
    private let theme: VaultTheme
    private var cancellables = Set<AnyCancellable>()
    private var user: User? { VaultAuth.shared.currentUser }
    
    // MARK: - UI Components
    
    private lazy var scrollView: UIScrollView = {
        let scrollView = UIScrollView()
        scrollView.translatesAutoresizingMaskIntoConstraints = false
        return scrollView
    }()
    
    private lazy var contentView: UIView = {
        let view = UIView()
        view.translatesAutoresizingMaskIntoConstraints = false
        return view
    }()
    
    private lazy var avatarImageView: UIImageView = {
        let imageView = UIImageView()
        imageView.translatesAutoresizingMaskIntoConstraints = false
        imageView.contentMode = .scaleAspectFill
        imageView.clipsToBounds = true
        imageView.layer.cornerRadius = 50
        imageView.backgroundColor = theme.surfaceColor
        imageView.tintColor = theme.primaryColor
        imageView.image = UIImage(systemName: "person.circle.fill")
        return imageView
    }()
    
    private lazy var nameLabel: UILabel = {
        let label = UILabel()
        label.translatesAutoresizingMaskIntoConstraints = false
        label.font = theme.titleFont
        label.textColor = theme.textColor
        label.textAlignment = .center
        return label
    }()
    
    private lazy var emailLabel: UILabel = {
        let label = UILabel()
        label.translatesAutoresizingMaskIntoConstraints = false
        label.font = theme.bodyFont
        label.textColor = theme.secondaryTextColor
        label.textAlignment = .center
        return label
    }()
    
    private lazy var verifiedBadge: UIImageView = {
        let imageView = UIImageView()
        imageView.translatesAutoresizingMaskIntoConstraints = false
        imageView.image = UIImage(systemName: "checkmark.seal.fill")
        imageView.tintColor = theme.successColor
        imageView.isHidden = true
        return imageView
    }()
    
    private lazy var infoCard: UIView = {
        let view = UIView()
        view.translatesAutoresizingMaskIntoConstraints = false
        view.backgroundColor = theme.surfaceColor
        view.layer.cornerRadius = theme.cornerRadius
        return view
    }()
    
    private lazy var memberSinceLabel: InfoRow = {
        InfoRow(theme: theme, icon: "calendar", title: "Member Since", value: "")
    }()
    
    private lazy var organizationLabel: InfoRow = {
        InfoRow(theme: theme, icon: "building.2", title: "Organization", value: "")
    }()
    
    private lazy var biometricSection: UIView = {
        let view = createSection(title: "Security")
        return view
    }()
    
    private lazy var biometricToggle: ToggleRow = {
        let row = ToggleRow(theme: theme, icon: BiometricAuth.shared.biometricType.iconName, title: "\(BiometricAuth.shared.biometricType.displayName) Login")
        row.toggle.addTarget(self, action: #selector(biometricToggleChanged), for: .valueChanged)
        return row
    }()
    
    private lazy var mfaRow: ButtonRow = {
        let row = ButtonRow(theme: theme, icon: "lock.shield", title: "Two-Factor Authentication")
        row.action = { [weak self] in
            self?.showMFASettings()
        }
        return row
    }()
    
    private lazy var logoutButton: VaultButton = {
        let button = VaultButton(theme: theme, title: "Sign Out", style: .secondary)
        button.translatesAutoresizingMaskIntoConstraints = false
        button.addTarget(self, action: #selector(logoutTapped), for: .touchUpInside)
        return button
    }()
    
    private lazy var deleteAccountButton: UIButton = {
        let button = UIButton(type: .system)
        button.translatesAutoresizingMaskIntoConstraints = false
        button.setTitle("Delete Account", for: .normal)
        button.setTitleColor(theme.errorColor, for: .normal)
        button.titleLabel?.font = theme.captionFont
        button.addTarget(self, action: #selector(deleteAccountTapped), for: .touchUpInside)
        return button
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
        setupBindings()
        updateUI()
    }
    
    public override func viewWillAppear(_ animated: Bool) {
        super.viewWillAppear(animated)
        updateUI()
    }
    
    // MARK: - Setup
    
    private func setupUI() {
        title = "Profile"
        view.backgroundColor = theme.backgroundColor
        
        view.addSubview(scrollView)
        scrollView.addSubview(contentView)
        
        // Add subviews
        [avatarImageView, nameLabel, emailLabel, verifiedBadge,
         infoCard, biometricSection, logoutButton, deleteAccountButton]
            .forEach { contentView.addSubview($0) }
        
        // Info card content
        [memberSinceLabel, createSeparator(), organizationLabel].forEach {
            infoCard.addSubview($0)
        }
        
        // Biometric section content
        [biometricToggle, createSeparator(), mfaRow].forEach {
            biometricSection.addSubview($0)
        }
        
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
            
            avatarImageView.topAnchor.constraint(equalTo: contentView.topAnchor, constant: 24),
            avatarImageView.centerXAnchor.constraint(equalTo: contentView.centerXAnchor),
            avatarImageView.widthAnchor.constraint(equalToConstant: 100),
            avatarImageView.heightAnchor.constraint(equalToConstant: 100),
            
            nameLabel.topAnchor.constraint(equalTo: avatarImageView.bottomAnchor, constant: 16),
            nameLabel.leadingAnchor.constraint(equalTo: contentView.leadingAnchor, constant: theme.padding),
            nameLabel.trailingAnchor.constraint(equalTo: contentView.trailingAnchor, constant: -theme.padding),
            
            verifiedBadge.centerYAnchor.constraint(equalTo: nameLabel.centerYAnchor),
            verifiedBadge.leadingAnchor.constraint(equalTo: nameLabel.trailingAnchor, constant: 4),
            verifiedBadge.widthAnchor.constraint(equalToConstant: 20),
            verifiedBadge.heightAnchor.constraint(equalToConstant: 20),
            
            emailLabel.topAnchor.constraint(equalTo: nameLabel.bottomAnchor, constant: 4),
            emailLabel.leadingAnchor.constraint(equalTo: contentView.leadingAnchor, constant: theme.padding),
            emailLabel.trailingAnchor.constraint(equalTo: contentView.trailingAnchor, constant: -theme.padding),
            
            infoCard.topAnchor.constraint(equalTo: emailLabel.bottomAnchor, constant: 24),
            infoCard.leadingAnchor.constraint(equalTo: contentView.leadingAnchor, constant: theme.padding),
            infoCard.trailingAnchor.constraint(equalTo: contentView.trailingAnchor, constant: -theme.padding),
            
            memberSinceLabel.topAnchor.constraint(equalTo: infoCard.topAnchor),
            memberSinceLabel.leadingAnchor.constraint(equalTo: infoCard.leadingAnchor),
            memberSinceLabel.trailingAnchor.constraint(equalTo: infoCard.trailingAnchor),
            memberSinceLabel.heightAnchor.constraint(equalToConstant: 56),
            
            organizationLabel.topAnchor.constraint(equalTo: memberSinceLabel.bottomAnchor),
            organizationLabel.leadingAnchor.constraint(equalTo: infoCard.leadingAnchor),
            organizationLabel.trailingAnchor.constraint(equalTo: infoCard.trailingAnchor),
            organizationLabel.heightAnchor.constraint(equalToConstant: 56),
            organizationLabel.bottomAnchor.constraint(equalTo: infoCard.bottomAnchor),
            
            biometricSection.topAnchor.constraint(equalTo: infoCard.bottomAnchor, constant: 24),
            biometricSection.leadingAnchor.constraint(equalTo: contentView.leadingAnchor, constant: theme.padding),
            biometricSection.trailingAnchor.constraint(equalTo: contentView.trailingAnchor, constant: -theme.padding),
            
            biometricToggle.topAnchor.constraint(equalTo: biometricSection.topAnchor),
            biometricToggle.leadingAnchor.constraint(equalTo: biometricSection.leadingAnchor),
            biometricToggle.trailingAnchor.constraint(equalTo: biometricSection.trailingAnchor),
            biometricToggle.heightAnchor.constraint(equalToConstant: 56),
            
            mfaRow.topAnchor.constraint(equalTo: biometricToggle.bottomAnchor),
            mfaRow.leadingAnchor.constraint(equalTo: biometricSection.leadingAnchor),
            mfaRow.trailingAnchor.constraint(equalTo: biometricSection.trailingAnchor),
            mfaRow.heightAnchor.constraint(equalToConstant: 56),
            mfaRow.bottomAnchor.constraint(equalTo: biometricSection.bottomAnchor),
            
            logoutButton.topAnchor.constraint(equalTo: biometricSection.bottomAnchor, constant: 32),
            logoutButton.leadingAnchor.constraint(equalTo: contentView.leadingAnchor, constant: theme.padding),
            logoutButton.trailingAnchor.constraint(equalTo: contentView.trailingAnchor, constant: -theme.padding),
            logoutButton.heightAnchor.constraint(equalToConstant: 50),
            
            deleteAccountButton.topAnchor.constraint(equalTo: logoutButton.bottomAnchor, constant: 16),
            deleteAccountButton.centerXAnchor.constraint(equalTo: contentView.centerXAnchor),
            deleteAccountButton.bottomAnchor.constraint(equalTo: contentView.bottomAnchor, constant: -24)
        ])
    }
    
    private func setupBindings() {
        VaultAuth.shared.$currentUser
            .receive(on: DispatchQueue.main)
            .sink { [weak self] _ in
                self?.updateUI()
            }
            .store(in: &cancellables)
    }
    
    private func updateUI() {
        guard let user = user else {
            // Not logged in
            return
        }
        
        nameLabel.text = user.name ?? user.email
        emailLabel.text = user.email
        verifiedBadge.isHidden = !user.emailVerified
        
        // Format member since date
        let formatter = DateFormatter()
        formatter.dateStyle = .medium
        memberSinceLabel.value = formatter.string(from: user.createdAt)
        
        // Organization
        organizationLabel.value = VaultAuth.shared.currentOrganization?.name ?? "Personal"
        
        // Biometric
        biometricToggle.toggle.isOn = BiometricAuth.shared.isBiometricLoginEnabled
        biometricToggle.isHidden = !BiometricAuth.shared.isAvailable
    }
    
    // MARK: - Actions
    
    @objc private func biometricToggleChanged() {
        guard let user = user else { return }
        
        if biometricToggle.toggle.isOn {
            // Show password prompt to enable biometric
            let alert = UIAlertController(
                title: "Enable \(BiometricAuth.shared.biometricType.displayName)",
                message: "Please enter your password to enable \(BiometricAuth.shared.biometricType.displayName) login",
                preferredStyle: .alert
            )
            
            alert.addTextField { textField in
                textField.placeholder = "Password"
                textField.isSecureTextEntry = true
            }
            
            alert.addAction(UIAlertAction(title: "Cancel", style: .cancel) { [weak self] _ in
                self?.biometricToggle.toggle.isOn = false
            })
            
            alert.addAction(UIAlertAction(title: "Enable", style: .default) { [weak self] _ in
                guard let password = alert.textFields?.first?.text else {
                    self?.biometricToggle.toggle.isOn = false
                    return
                }
                
                Task {
                    do {
                        _ = try await BiometricAuth.shared.enableBiometricLogin(
                            email: user.email,
                            password: password
                        )
                    } catch {
                        await MainActor.run {
                            self?.biometricToggle.toggle.isOn = false
                            self?.showError(error.localizedDescription)
                        }
                    }
                }
            })
            
            present(alert, animated: true)
        } else {
            // Disable biometric
            try? BiometricAuth.shared.disableBiometricLogin()
        }
    }
    
    @objc private func logoutTapped() {
        let alert = UIAlertController(
            title: "Sign Out",
            message: "Are you sure you want to sign out?",
            preferredStyle: .alert
        )
        
        alert.addAction(UIAlertAction(title: "Cancel", style: .cancel))
        alert.addAction(UIAlertAction(title: "Sign Out", style: .destructive) { [weak self] _ in
            Task {
                do {
                    try await VaultAuth.shared.logout()
                    await MainActor.run {
                        self?.onLogout?()
                    }
                } catch {
                    await MainActor.run {
                        self?.showError(error.localizedDescription)
                    }
                }
            }
        })
        
        present(alert, animated: true)
    }
    
    @objc private func deleteAccountTapped() {
        let alert = UIAlertController(
            title: "Delete Account",
            message: "This action cannot be undone. All your data will be permanently deleted.",
            preferredStyle: .alert
        )
        
        alert.addTextField { textField in
            textField.placeholder = "Type DELETE to confirm"
        }
        
        alert.addAction(UIAlertAction(title: "Cancel", style: .cancel))
        alert.addAction(UIAlertAction(title: "Delete", style: .destructive) { [weak self] _ in
            guard let text = alert.textFields?.first?.text, text == "DELETE" else {
                return
            }
            
            self?.onDeleteAccount?()
        })
        
        present(alert, animated: true)
    }
    
    private func showMFASettings() {
        let alert = UIAlertController(
            title: "Two-Factor Authentication",
            message: "MFA settings coming soon",
            preferredStyle: .alert
        )
        alert.addAction(UIAlertAction(title: "OK", style: .default))
        present(alert, animated: true)
    }
    
    private func showError(_ message: String) {
        let alert = UIAlertController(
            title: "Error",
            message: message,
            preferredStyle: .alert
        )
        alert.addAction(UIAlertAction(title: "OK", style: .default))
        present(alert, animated: true)
    }
    
    // MARK: - Helpers
    
    private func createSection(title: String) -> UIView {
        let view = UIView()
        view.translatesAutoresizingMaskIntoConstraints = false
        view.backgroundColor = theme.surfaceColor
        view.layer.cornerRadius = theme.cornerRadius
        
        let label = UILabel()
        label.translatesAutoresizingMaskIntoConstraints = false
        label.font = theme.captionFont
        label.textColor = theme.secondaryTextColor
        label.text = title.uppercased()
        
        // Actually, let's not add the label to the view to avoid complexity
        // Just return the styled view
        
        return view
    }
    
    private func createSeparator() -> UIView {
        let view = UIView()
        view.translatesAutoresizingMaskIntoConstraints = false
        view.backgroundColor = theme.borderColor
        view.heightAnchor.constraint(equalToConstant: 1).isActive = true
        return view
    }
}

// MARK: - InfoRow

class InfoRow: UIView {
    private let theme: VaultTheme
    private let iconView: UIImageView
    let valueLabel: UILabel
    
    var value: String {
        get { valueLabel.text ?? "" }
        set { valueLabel.text = newValue }
    }
    
    init(theme: VaultTheme, icon: String, title: String, value: String = "") {
        self.theme = theme
        self.iconView = UIImageView()
        self.valueLabel = UILabel()
        
        super.init(frame: .zero)
        
        iconView.image = UIImage(systemName: icon)
        iconView.tintColor = theme.primaryColor
        iconView.translatesAutoresizingMaskIntoConstraints = false
        
        let titleLabel = UILabel()
        titleLabel.text = title
        titleLabel.font = theme.captionFont
        titleLabel.textColor = theme.secondaryTextColor
        titleLabel.translatesAutoresizingMaskIntoConstraints = false
        
        valueLabel.text = value
        valueLabel.font = theme.bodyFont
        valueLabel.textColor = theme.textColor
        valueLabel.translatesAutoresizingMaskIntoConstraints = false
        
        addSubview(iconView)
        addSubview(titleLabel)
        addSubview(valueLabel)
        
        NSLayoutConstraint.activate([
            iconView.leadingAnchor.constraint(equalTo: leadingAnchor, constant: 16),
            iconView.centerYAnchor.constraint(equalTo: centerYAnchor),
            iconView.widthAnchor.constraint(equalToConstant: 24),
            iconView.heightAnchor.constraint(equalToConstant: 24),
            
            titleLabel.leadingAnchor.constraint(equalTo: iconView.trailingAnchor, constant: 12),
            titleLabel.topAnchor.constraint(equalTo: topAnchor, constant: 10),
            
            valueLabel.leadingAnchor.constraint(equalTo: iconView.trailingAnchor, constant: 12),
            valueLabel.topAnchor.constraint(equalTo: titleLabel.bottomAnchor, constant: 2)
        ])
    }
    
    required init?(coder: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }
}

// MARK: - ToggleRow

class ToggleRow: UIView {
    private let theme: VaultTheme
    let toggle: UISwitch
    
    init(theme: VaultTheme, icon: String, title: String) {
        self.theme = theme
        
        let iconView = UIImageView(image: UIImage(systemName: icon))
        iconView.tintColor = theme.primaryColor
        iconView.translatesAutoresizingMaskIntoConstraints = false
        
        let titleLabel = UILabel()
        titleLabel.text = title
        titleLabel.font = theme.bodyFont
        titleLabel.textColor = theme.textColor
        titleLabel.translatesAutoresizingMaskIntoConstraints = false
        
        self.toggle = UISwitch()
        toggle.translatesAutoresizingMaskIntoConstraints = false
        
        super.init(frame: .zero)
        
        addSubview(iconView)
        addSubview(titleLabel)
        addSubview(toggle)
        
        NSLayoutConstraint.activate([
            iconView.leadingAnchor.constraint(equalTo: leadingAnchor, constant: 16),
            iconView.centerYAnchor.constraint(equalTo: centerYAnchor),
            iconView.widthAnchor.constraint(equalToConstant: 24),
            iconView.heightAnchor.constraint(equalToConstant: 24),
            
            titleLabel.leadingAnchor.constraint(equalTo: iconView.trailingAnchor, constant: 12),
            titleLabel.centerYAnchor.constraint(equalTo: centerYAnchor),
            
            toggle.trailingAnchor.constraint(equalTo: trailingAnchor, constant: -16),
            toggle.centerYAnchor.constraint(equalTo: centerYAnchor)
        ])
    }
    
    required init?(coder: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }
}

// MARK: - ButtonRow

class ButtonRow: UIView {
    private let theme: VaultTheme
    var action: (() -> Void)?
    
    init(theme: VaultTheme, icon: String, title: String) {
        self.theme = theme
        
        super.init(frame: .zero)
        
        let iconView = UIImageView(image: UIImage(systemName: icon))
        iconView.tintColor = theme.primaryColor
        iconView.translatesAutoresizingMaskIntoConstraints = false
        
        let titleLabel = UILabel()
        titleLabel.text = title
        titleLabel.font = theme.bodyFont
        titleLabel.textColor = theme.textColor
        titleLabel.translatesAutoresizingMaskIntoConstraints = false
        
        let chevron = UIImageView(image: UIImage(systemName: "chevron.right"))
        chevron.tintColor = theme.secondaryTextColor
        chevron.translatesAutoresizingMaskIntoConstraints = false
        
        addSubview(iconView)
        addSubview(titleLabel)
        addSubview(chevron)
        
        NSLayoutConstraint.activate([
            iconView.leadingAnchor.constraint(equalTo: leadingAnchor, constant: 16),
            iconView.centerYAnchor.constraint(equalTo: centerYAnchor),
            iconView.widthAnchor.constraint(equalToConstant: 24),
            iconView.heightAnchor.constraint(equalToConstant: 24),
            
            titleLabel.leadingAnchor.constraint(equalTo: iconView.trailingAnchor, constant: 12),
            titleLabel.centerYAnchor.constraint(equalTo: centerYAnchor),
            
            chevron.trailingAnchor.constraint(equalTo: trailingAnchor, constant: -16),
            chevron.centerYAnchor.constraint(equalTo: centerYAnchor)
        ])
        
        let tapGesture = UITapGestureRecognizer(target: self, action: #selector(tapped))
        addGestureRecognizer(tapGesture)
    }
    
    @objc private func tapped() {
        action?()
    }
    
    required init?(coder: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }
}
