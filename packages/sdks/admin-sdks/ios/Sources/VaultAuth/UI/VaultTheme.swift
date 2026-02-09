import UIKit

// MARK: - VaultTheme

public struct VaultTheme {
    public let primaryColor: UIColor
    public let secondaryColor: UIColor
    public let backgroundColor: UIColor
    public let surfaceColor: UIColor
    public let errorColor: UIColor
    public let successColor: UIColor
    public let textColor: UIColor
    public let secondaryTextColor: UIColor
    public let buttonTextColor: UIColor
    public let borderColor: UIColor
    
    public let cornerRadius: CGFloat
    public let buttonCornerRadius: CGFloat
    public let spacing: CGFloat
    public let padding: CGFloat
    
    public let titleFont: UIFont
    public let bodyFont: UIFont
    public let buttonFont: UIFont
    public let captionFont: UIFont
    
    public static let `default` = VaultTheme()
    
    public init(
        primaryColor: UIColor = .systemBlue,
        secondaryColor: UIColor = .systemIndigo,
        backgroundColor: UIColor = .systemBackground,
        surfaceColor: UIColor = .secondarySystemBackground,
        errorColor: UIColor = .systemRed,
        successColor: UIColor = .systemGreen,
        textColor: UIColor = .label,
        secondaryTextColor: UIColor = .secondaryLabel,
        buttonTextColor: UIColor = .white,
        borderColor: UIColor = .separator,
        cornerRadius: CGFloat = 8,
        buttonCornerRadius: CGFloat = 12,
        spacing: CGFloat = 16,
        padding: CGFloat = 24,
        titleFont: UIFont = .systemFont(ofSize: 28, weight: .bold),
        bodyFont: UIFont = .systemFont(ofSize: 16),
        buttonFont: UIFont = .systemFont(ofSize: 16, weight: .semibold),
        captionFont: UIFont = .systemFont(ofSize: 14)
    ) {
        self.primaryColor = primaryColor
        self.secondaryColor = secondaryColor
        self.backgroundColor = backgroundColor
        self.surfaceColor = surfaceColor
        self.errorColor = errorColor
        self.successColor = successColor
        self.textColor = textColor
        self.secondaryTextColor = secondaryTextColor
        self.buttonTextColor = buttonTextColor
        self.borderColor = borderColor
        self.cornerRadius = cornerRadius
        self.buttonCornerRadius = buttonCornerRadius
        self.spacing = spacing
        self.padding = padding
        self.titleFont = titleFont
        self.bodyFont = bodyFont
        self.buttonFont = buttonFont
        self.captionFont = captionFont
    }
}

// MARK: - VaultTextField

public class VaultTextField: UITextField {
    private let theme: VaultTheme
    private let padding = UIEdgeInsets(top: 12, left: 12, bottom: 12, right: 12)
    
    public init(theme: VaultTheme, placeholder: String? = nil) {
        self.theme = theme
        super.init(frame: .zero)
        self.placeholder = placeholder
        setup()
    }
    
    required init?(coder: NSCoder) {
        self.theme = .default
        super.init(coder: coder)
        setup()
    }
    
    private func setup() {
        backgroundColor = theme.surfaceColor
        textColor = theme.textColor
        font = theme.bodyFont
        layer.cornerRadius = theme.cornerRadius
        layer.borderWidth = 1
        layer.borderColor = theme.borderColor.cgColor
        autocapitalizationType = .none
        autocorrectionType = .no
        
        attributedPlaceholder = NSAttributedString(
            string: placeholder ?? "",
            attributes: [.foregroundColor: theme.secondaryTextColor]
        )
    }
    
    public override func textRect(forBounds bounds: CGRect) -> CGRect {
        return bounds.inset(by: padding)
    }
    
    public override func placeholderRect(forBounds bounds: CGRect) -> CGRect {
        return bounds.inset(by: padding)
    }
    
    public override func editingRect(forBounds bounds: CGRect) -> CGRect {
        return bounds.inset(by: padding)
    }
    
    public func setError(_ isError: Bool) {
        layer.borderColor = isError ? theme.errorColor.cgColor : theme.borderColor.cgColor
    }
}

// MARK: - VaultButton

public class VaultButton: UIButton {
    private let theme: VaultTheme
    private let style: Style
    
    public enum Style {
        case primary
        case secondary
        case text
    }
    
    public init(theme: VaultTheme, title: String, style: Style = .primary) {
        self.theme = theme
        self.style = style
        super.init(frame: .zero)
        setTitle(title, for: .normal)
        setup()
    }
    
    required init?(coder: NSCoder) {
        self.theme = .default
        self.style = .primary
        super.init(coder: coder)
        setup()
    }
    
    private func setup() {
        titleLabel?.font = theme.buttonFont
        layer.cornerRadius = theme.buttonCornerRadius
        
        switch style {
        case .primary:
            backgroundColor = theme.primaryColor
            setTitleColor(theme.buttonTextColor, for: .normal)
        case .secondary:
            backgroundColor = theme.surfaceColor
            setTitleColor(theme.primaryColor, for: .normal)
            layer.borderWidth = 1
            layer.borderColor = theme.primaryColor.cgColor
        case .text:
            backgroundColor = .clear
            setTitleColor(theme.primaryColor, for: .normal)
        }
        
        heightAnchor.constraint(equalToConstant: 50).isActive = true
    }
    
    public override var isEnabled: Bool {
        didSet {
            alpha = isEnabled ? 1.0 : 0.6
        }
    }
}

// MARK: - VaultLabel

public class VaultLabel: UILabel {
    private let theme: VaultTheme
    
    public init(theme: VaultTheme, text: String? = nil, style: TextStyle = .body) {
        self.theme = theme
        super.init(frame: .zero)
        self.text = text
        applyStyle(style)
    }
    
    required init?(coder: NSCoder) {
        self.theme = .default
        super.init(coder: coder)
    }
    
    public enum TextStyle {
        case title
        case subtitle
        case body
        case caption
        case error
    }
    
    private func applyStyle(_ style: TextStyle) {
        switch style {
        case .title:
            font = theme.titleFont
            textColor = theme.textColor
            textAlignment = .center
        case .subtitle:
            font = theme.bodyFont
            textColor = theme.secondaryTextColor
            textAlignment = .center
        case .body:
            font = theme.bodyFont
            textColor = theme.textColor
        case .caption:
            font = theme.captionFont
            textColor = theme.secondaryTextColor
        case .error:
            font = theme.captionFont
            textColor = theme.errorColor
            textAlignment = .center
        }
        
        numberOfLines = 0
    }
}

// MARK: - LoadingView

class LoadingView: UIView {
    private let activityIndicator = UIActivityIndicatorView(style: .large)
    private let label = UILabel()
    
    override init(frame: CGRect) {
        super.init(frame: frame)
        setup()
    }
    
    required init?(coder: NSCoder) {
        super.init(coder: coder)
        setup()
    }
    
    private func setup() {
        backgroundColor = UIColor.black.withAlphaComponent(0.4)
        
        activityIndicator.translatesAutoresizingMaskIntoConstraints = false
        label.translatesAutoresizingMaskIntoConstraints = false
        
        addSubview(activityIndicator)
        addSubview(label)
        
        label.text = "Loading..."
        label.textColor = .white
        label.font = .systemFont(ofSize: 16, weight: .medium)
        
        NSLayoutConstraint.activate([
            activityIndicator.centerXAnchor.constraint(equalTo: centerXAnchor),
            activityIndicator.centerYAnchor.constraint(equalTo: centerYAnchor),
            
            label.topAnchor.constraint(equalTo: activityIndicator.bottomAnchor, constant: 12),
            label.centerXAnchor.constraint(equalTo: centerXAnchor)
        ])
    }
    
    func show(in view: UIView) {
        frame = view.bounds
        view.addSubview(self)
        activityIndicator.startAnimating()
    }
    
    func hide() {
        activityIndicator.stopAnimating()
        removeFromSuperview()
    }
}
