//! Supabase authentication data structures and error types.
//!
//! This module defines the data structures that mirror Supabase Auth API responses,
//! providing type-safe deserialization of authentication data. These structures
//! represent the exact format that Supabase returns during authentication flows.
//!
//! # Supabase Auth Flow
//!
//! When a user authenticates with Supabase, the response includes:
//! - JWT tokens for session management
//! - User profile information and metadata
//! - Identity provider details
//! - Application-specific metadata
//!
//! # Examples
//!
//! ```json
//! {
//!   "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
//!   "token_type": "bearer",
//!   "expires_in": 3600,
//!   "expires_at": 1234567890,
//!   "refresh_token": "v1.M2YwOTQxNzktZGYwNi00...",
//!   "user": { ... }
//! }
//! ```

use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

/// Complete authentication response from Supabase Auth API.
///
/// This structure represents the full response returned by Supabase when a user
/// successfully authenticates (login/register). It contains both the session
/// tokens needed for API access and the complete user profile information.
///
/// # JWT Token Usage
///
/// The `access_token` should be included in the `Authorization` header of
/// subsequent API requests as: `Bearer {access_token}`.
///
/// # Token Expiration
///
/// - `expires_in`: Seconds until the access token expires
/// - `expires_at`: Unix timestamp when the token expires
/// - `refresh_token`: Used to obtain new access tokens when they expire
///
/// # Examples
///
/// ```rust
/// use serde_json;
/// use crate::handlers::data::AuthResponse;
///
/// let json_response = r#"
/// {
///   "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
///   "token_type": "bearer",
///   "expires_in": 3600,
///   "expires_at": 1234567890,
///   "refresh_token": "refresh_token_here",
///   "user": { ... }
/// }
/// "#;
///
/// let auth: AuthResponse = serde_json::from_str(json_response)?;
/// println!("User {} authenticated", auth.user.email);
/// ```
#[derive(Debug, Serialize, Deserialize)]
pub struct AuthResponse {
    /// JWT access token for API authentication
    /// Format: Base64-encoded JWT with header.payload.signature
    pub access_token: String,

    /// Token type, typically "bearer" for JWT tokens
    pub token_type: String,

    /// Number of seconds until the access token expires
    /// Typically 3600 (1 hour) for Supabase
    pub expires_in: i64,

    /// Unix timestamp indicating when the access token expires
    /// Used for client-side token expiration checking
    pub expires_at: i64,

    /// Refresh token for obtaining new access tokens
    /// Should be stored securely and used when access_token expires
    pub refresh_token: String,

    /// Complete user profile and metadata information
    pub user: User,
}

/// Complete user profile information from Supabase Auth.
///
/// This structure contains all user data returned by Supabase Auth, including
/// both system-managed fields (like timestamps and verification status) and
/// custom application metadata. The structure mirrors Supabase's internal
/// user representation.
///
/// # Field Categories
///
/// - **Identity**: `id`, `email`, `phone` - Core identification
/// - **Verification**: `email_confirmed_at`, `phone_verified` - Account verification status
/// - **Sessions**: `last_sign_in_at`, `aud` - Authentication tracking
/// - **Metadata**: `app_metadata`, `user_metadata` - Custom data storage
/// - **Identities**: External identity provider information
/// - **Timestamps**: `created_at`, `updated_at` - Account lifecycle
///
/// # Usage Notes
///
/// - `id` is the primary key for the user across all Supabase services
/// - `aud` (audience) is typically your Supabase project reference
/// - `role` is the database role, separate from custom application roles
/// - Metadata should be used for application-specific user data
#[derive(Debug, Serialize, Deserialize)]
pub struct User {
    /// Unique user identifier (UUID)
    /// This is the primary key used across all Supabase services
    pub id: Uuid,

    /// Audience claim (typically your Supabase project reference)
    /// Used for JWT validation and multi-tenant applications
    pub aud: String,

    /// Database role assigned to the user
    /// Usually "authenticated" for regular users, separate from app roles
    pub role: String,

    /// User's email address
    /// Primary identifier for authentication and communication
    pub email: String,

    /// Timestamp when email was confirmed (ISO 8601 format)
    /// None if email verification is pending
    pub email_confirmed_at: Option<String>,

    /// User's phone number
    /// May be empty string if not provided during registration
    pub phone: String,

    /// Timestamp of the user's last successful login (ISO 8601 format)
    /// None for newly registered users who haven't logged in yet
    pub last_sign_in_at: Option<String>,

    /// Application metadata managed by Supabase
    /// Contains provider information and system-level data
    pub app_metadata: AppMetadata,

    /// Custom user metadata set by your application
    /// Contains application-specific user information
    pub user_metadata: UserMetadata,

    /// List of identity providers linked to this account
    /// Supports multiple authentication methods (email, OAuth, etc.)
    pub identities: Vec<Identity>,

    /// Account creation timestamp (ISO 8601 format)
    pub created_at: String,

    /// Last profile update timestamp (ISO 8601 format)
    pub updated_at: String,

    /// Whether this is an anonymous user session
    /// True for anonymous auth, false for authenticated users
    pub is_anonymous: bool,
}

/// System-managed metadata for authentication providers.
///
/// This structure contains information managed by Supabase about how the user
/// authenticated and which providers are available to them. This data is
/// read-only from the application perspective and is managed by Supabase Auth.
///
/// # Provider Information
///
/// - `provider`: The primary authentication method used (e.g., "email", "google", "github")
/// - `providers`: All authentication methods available or used by this user
///
/// # Common Provider Values
///
/// - `"email"` - Email/password authentication
/// - `"google"` - Google OAuth
/// - `"github"` - GitHub OAuth
/// - `"discord"` - Discord OAuth
/// - `"facebook"` - Facebook OAuth
/// - `"apple"` - Apple Sign In
#[derive(Debug, Serialize, Deserialize)]
pub struct AppMetadata {
    /// Primary authentication provider used for this account
    /// Examples: "email", "google", "github", "discord"
    pub provider: String,

    /// List of all authentication providers associated with this account
    /// Allows users to link multiple auth methods to one account
    pub providers: Vec<String>,
}

/// Custom user metadata set by your application.
///
/// This structure contains application-specific user information that you
/// set during registration or profile updates. Unlike `AppMetadata`, this
/// data is fully under your application's control and can be modified.
///
/// # Custom Fields
///
/// You can extend this structure with additional fields as needed for your
/// application. Common additions include profile pictures, preferences,
/// settings, etc.
///
/// # Verification Status
///
/// The verification fields indicate whether the user has confirmed their
/// email address and phone number through Supabase's verification flows.
#[derive(Debug, Serialize, Deserialize)]
pub struct UserMetadata {
    /// User's email address (duplicated from User.email)
    /// Maintained for consistency with Supabase's metadata structure
    pub email: String,

    /// Whether the user has verified their email address
    /// Set to true after clicking email confirmation link
    pub email_verified: bool,

    /// User's display name or full name
    /// Optional field set during registration or profile updates
    pub name: Option<String>,

    /// Whether the user has verified their phone number
    /// Set to true after SMS verification process
    pub phone_verified: bool,

    /// Application-specific user role for authorization
    /// Different from the database role in User.role
    pub role: Role,

    /// Subject identifier for the user
    /// Typically matches the user ID, used for JWT claims
    pub sub: String,
}

/// Identity provider information for a user account.
///
/// Supabase supports multiple identity providers per user account. Each
/// identity represents a different way the user can authenticate (email,
/// Google, GitHub, etc.). This allows users to link multiple auth methods
/// to a single account.
///
/// # Identity Linking
///
/// When a user signs in with a new provider using the same email address,
/// Supabase can automatically link the identities or create separate accounts
/// based on your configuration.
///
/// # Use Cases
///
/// - Social login integration (Google, GitHub, etc.)
/// - Multiple authentication methods per user
/// - Migration from legacy authentication systems
/// - Enterprise SSO integration
#[derive(Debug, Serialize, Deserialize)]
pub struct Identity {
    /// Unique identifier for this specific identity
    /// Different from user ID - one user can have multiple identities
    pub identity_id: String,

    /// Provider-specific user identifier
    /// For OAuth providers, this is typically the provider's user ID
    pub id: String,

    /// Supabase user ID this identity belongs to
    /// Links the identity back to the main user account
    pub user_id: String,

    /// Provider-specific user data and claims
    /// Contains information received from the identity provider
    pub identity_data: IdentityData,

    /// Name of the identity provider
    /// Examples: "email", "google", "github", "discord"
    pub provider: String,

    /// Last time this identity was used for authentication
    /// None if this identity hasn't been used to sign in yet
    pub last_sign_in_at: Option<String>,

    /// When this identity was first linked to the account
    pub created_at: String,

    /// Last time this identity's data was updated
    pub updated_at: String,

    /// Email address associated with this identity
    /// May differ from the main account email for linked accounts
    pub email: String,
}

/// Provider-specific user data from external identity providers.
///
/// This structure contains the raw user information received from external
/// authentication providers (Google, GitHub, etc.). The exact fields present
/// depend on the provider and the scopes requested during authentication.
///
/// # Provider Variations
///
/// Different providers return different fields:
/// - **Google**: email, name, picture, email_verified
/// - **GitHub**: login, name, email, avatar_url
/// - **Discord**: username, email, avatar
/// - **Email**: Basic email and verification status
///
/// # Data Freshness
///
/// This data is updated each time the user authenticates with the provider,
/// so it may be more current than the main user profile data.
#[derive(Debug, Serialize, Deserialize)]
pub struct IdentityData {
    /// Email address from the identity provider
    /// Primary identifier for most providers
    pub email: String,

    /// Whether the provider has verified this email address
    /// Indicates the provider's confidence in the email's validity
    pub email_verified: bool,

    /// Display name from the identity provider
    /// May be username, full name, or display name depending on provider
    pub name: Option<String>,

    /// Whether the provider has verified the phone number
    /// Not all providers support phone verification
    pub phone_verified: bool,

    /// Provider-specific role or account type
    /// Optional field that varies by provider (e.g., GitHub organization role)
    pub role: Option<String>,

    /// Subject identifier from the identity provider
    /// Unique identifier for the user within that provider's system
    pub sub: String,
}

/// Application-specific user roles for authorization.
///
/// This enum defines the permission levels available within your application.
/// It's separate from Supabase's database roles and is used for application-level
/// authorization decisions.
///
/// # Role Hierarchy
///
/// The roles are ordered by permission level (User < Admin), allowing for
/// easy comparison operations to check if a user has sufficient privileges.
///
/// # Serialization
///
/// Roles are serialized to lowercase strings in JSON:
/// - `User` → `"user"`
/// - `Admin` → `"admin"`
///
/// # Usage Examples
///
/// ```rust
/// use crate::handlers::data::Role;
///
/// let user_role = Role::User;
/// let admin_role = Role::Admin;
///
/// // Check if user has admin privileges
/// if user_role >= Role::Admin {
///     println!("User has admin access");
/// }
///
/// // Role comparison
/// assert!(Role::Admin > Role::User);
/// ```
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    /// Standard user with basic application access
    /// Can perform user-level operations on their own data
    User,

    /// Administrator with elevated privileges
    /// Can perform admin operations and access other users' data
    Admin,
}

impl From<&str> for Role {
    /// Converts a string to a Role enum.
    ///
    /// This implementation defaults to `User` for any unrecognized role string,
    /// providing a safe fallback that doesn't accidentally grant elevated privileges.
    ///
    /// # Arguments
    ///
    /// * `value` - String representation of the role
    ///
    /// # Returns
    ///
    /// * `Role::Admin` for "admin"
    /// * `Role::User` for any other value (including "user")
    ///
    /// # Examples
    ///
    /// ```rust
    /// use crate::handlers::data::Role;
    ///
    /// assert_eq!(Role::from("admin"), Role::Admin);
    /// assert_eq!(Role::from("user"), Role::User);
    /// assert_eq!(Role::from("unknown"), Role::User); // Safe default
    /// ```
    fn from(value: &str) -> Self {
        match value {
            "admin" => Self::Admin,
            _ => Self::User, // Default to least privileged role for security
        }
    }
}

/// Comprehensive error types for authentication operations.
///
/// This enum covers all possible error scenarios that can occur during
/// authentication flows with Supabase. Each variant provides specific
/// context about the failure to enable appropriate error handling and
/// user messaging.
///
/// # Error Categories
///
/// - **Supabase**: Errors returned by Supabase Auth API
/// - **Request**: Network and HTTP client errors
/// - **Parse**: JSON deserialization failures
/// - **Other**: Unexpected or unclassified errors
///
/// # Error Handling Strategy
///
/// ```rust
/// use crate::handlers::data::AuthError;
///
/// match auth_result {
///     Err(AuthError::Supabase { code: 400, .. }) => {
///         // Handle validation errors (weak password, invalid email, etc.)
///     },
///     Err(AuthError::Request(_)) => {
///         // Handle network connectivity issues
///     },
///     Err(AuthError::Parse(_)) => {
///         // Handle malformed responses
///     },
///     _ => {
///         // Handle other unexpected errors
///     }
/// }
/// ```
///
/// # JSON Serialization
///
/// Errors are serialized with a `type` field for client-side handling:
/// ```json
/// {
///   "type": "supabase",
///   "code": 400,
///   "error_code": "invalid_credentials",
///   "msg": "Invalid login credentials"
/// }
/// ```
#[derive(Debug, Serialize, Deserialize, Error)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AuthError {
    /// Error response directly from Supabase Auth API.
    ///
    /// This variant contains the exact error information returned by Supabase,
    /// including HTTP status codes and specific error identifiers.
    ///
    /// # Common Supabase Errors
    ///
    /// - `400`: Invalid request (weak password, invalid email format)
    /// - `401`: Invalid credentials (wrong email/password)
    /// - `422`: User already exists (duplicate email)
    /// - `429`: Rate limit exceeded
    /// - `500`: Supabase internal server error
    #[error("Supabase error {code}: {msg} ({error_code})")]
    Supabase {
        /// HTTP status code from Supabase API
        code: u16,
        /// Machine-readable error identifier for programmatic handling
        error_code: String,
        /// Human-readable error message with debugging information
        msg: String,
    },

    /// Network or HTTP client request failures.
    ///
    /// This variant covers connectivity issues, timeouts, DNS resolution
    /// failures, and other network-related problems that prevent successful
    /// communication with Supabase.
    ///
    /// # Common Scenarios
    ///
    /// - Network connectivity issues
    /// - DNS resolution failures
    /// - Connection timeouts
    /// - TLS/SSL certificate errors
    /// - Proxy configuration problems
    #[error("Request failed: {0}")]
    Request(String),

    /// JSON parsing or deserialization failures.
    ///
    /// This variant occurs when Supabase returns a response that doesn't
    /// match the expected JSON structure, indicating either an API change
    /// or a malformed response.
    ///
    /// # Common Causes
    ///
    /// - Supabase API changes
    /// - Malformed JSON responses
    /// - Unexpected response structure
    /// - Character encoding issues
    #[error("Failed to parse response: {0}")]
    Parse(String),

    /// Unexpected or unclassified errors.
    ///
    /// This variant serves as a catch-all for errors that don't fit into
    /// the other categories, ensuring comprehensive error coverage.
    ///
    /// # Usage
    ///
    /// Typically used for:
    /// - Unexpected application state
    /// - Third-party library errors
    /// - Configuration issues
    /// - Edge cases not covered by other variants
    #[error("Unexpected response: {0}")]
    Other(String),
}
