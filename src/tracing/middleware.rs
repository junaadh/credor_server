//! Request logging middleware for comprehensive HTTP request/response tracking.
//!
//! This middleware automatically logs all incoming HTTP requests with detailed
//! context including timing, status codes, user information, and request metadata.

use actix_web::{
    Error, HttpMessage,
    dev::{Service, ServiceRequest, ServiceResponse, Transform},
};
use chrono::Utc;
use futures::future::{Ready, ok};
use serde_json::json;
use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
    time::Instant,
};
use uuid::Uuid;

use crate::{AppState, auth_middleware::AuthMiddleware};

/// Request logging middleware that captures comprehensive request/response data.
///
/// This middleware automatically logs:
/// - Request method, path, and query parameters
/// - Response status codes and timing
/// - User information (if authenticated)
/// - IP addresses and user agents
/// - Error details for failed requests
#[derive(Clone)]
pub struct RequestLoggingMiddleware;

impl RequestLoggingMiddleware {
    pub fn new() -> Self {
        Self
    }
}

impl Default for RequestLoggingMiddleware {
    fn default() -> Self {
        Self::new()
    }
}

impl<S, B> Transform<S, ServiceRequest> for RequestLoggingMiddleware
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type InitError = ();
    type Transform = RequestLoggingService<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ok(RequestLoggingService { service })
    }
}

/// Request logging service implementation.
pub struct RequestLoggingService<S> {
    service: S,
}

impl<S, B> Service<ServiceRequest> for RequestLoggingService<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>>>>;

    fn poll_ready(&self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.service.poll_ready(cx)
    }

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let start_time = Instant::now();
        let request_id = Uuid::new_v4();

        // Extract request information
        let method = req.method().to_string();
        let path = req.path().to_string();
        let query_string = req.query_string().to_string();
        let remote_addr = req
            .connection_info()
            .realip_remote_addr()
            .unwrap_or("unknown")
            .to_string();

        let user_agent = req
            .headers()
            .get("user-agent")
            .and_then(|h| h.to_str().ok())
            .unwrap_or("unknown")
            .to_string();

        let content_length = req
            .headers()
            .get("content-length")
            .and_then(|h| h.to_str().ok())
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(0);

        // Try to extract user information from auth middleware
        let user_id = req.extensions().get::<AuthMiddleware>().map(|auth| auth.id);
        let user_role = req
            .extensions()
            .get::<AuthMiddleware>()
            .map(|auth| auth.role);

        // Create request context
        let request_context = json!({
            "request_id": request_id,
            "method": method,
            "path": path,
            "query_string": query_string,
            "remote_addr": remote_addr,
            "user_agent": user_agent,
            "content_length": content_length,
            "user_id": user_id,
            "user_role": user_role,
            "timestamp": Utc::now()
        });

        // Log incoming request
        let log_ctx = request_context.clone();
        let method_clone = method.clone();
        let path_clone = path.clone();
        // Fetch db_writer from app data
        let db_writer = req
            .app_data::<actix_web::web::Data<AppState>>()
            .map(|x| x.db.clone());

        if let Some(db_writer) = db_writer.clone() {
            tokio::spawn({
                let db_writer = db_writer.clone();
                async move {
                    crate::tracing::log_event(
                        db_writer,
                        "INFO",
                        "http_request",
                        &format!("{} {}", method_clone, path_clone),
                        user_id,
                        Some(log_ctx),
                    )
                    .await;
                }
            });
        }

        // Move req into the future so it can be used after .await
        let fut = self.service.call(req);

        Box::pin(async move {
            let response = fut.await?;
            let duration = start_time.elapsed();
            let status_code = response.status().as_u16();

            // Create response context
            let response_context = json!({
                "request_id": request_id,
                "status_code": status_code,
                "duration_ms": duration.as_millis(),
                "duration_ns": duration.as_nanos(),
                "response_size": response.headers().get("content-length")
                    .and_then(|h| h.to_str().ok())
                    .and_then(|s| s.parse::<u64>().ok())
                    .unwrap_or(0),
                "cache_status": response.headers().get("cache-control")
                    .and_then(|h| h.to_str().ok())
                    .unwrap_or("none"),
                "content_type": response.headers().get("content-type")
                    .and_then(|h| h.to_str().ok())
                    .unwrap_or("unknown")
            });

            // Merge request and response context
            let mut full_context = request_context;
            if let Some(obj) = full_context.as_object_mut() {
                if let Some(resp_obj) = response_context.as_object() {
                    obj.extend(resp_obj.clone());
                }
            }

            // Determine log level based on status code
            let log_level = match status_code {
                200..=299 => "INFO",
                300..=399 => "INFO",
                400..=499 => "WARN",
                500..=599 => "ERROR",
                _ => "INFO",
            };

            // Log response
            let log_message = format!(
                "{} {} {} {}ms",
                method.clone(),
                path.clone(),
                status_code,
                duration.as_millis()
            );

            // To fetch db_writer again, we need req. But req was moved into fut above.
            // Instead, we can require that db_writer is cloned above and moved into the async block.
            // However, since db_writer is only needed for logging, we can fetch it again from response.request().
            // But ServiceResponse<B> does not expose the original ServiceRequest directly.
            // Instead, we can pass db_writer into the async block above.
            // To fix the diagnostics, let's fetch db_writer before moving req.

            // Instead, let's fetch db_writer before moving req, and move it into the async block.
            // (Already done above.)

            if let Some(db_writer) = db_writer.clone() {
                tokio::spawn({
                    let db_writer = db_writer.clone();
                    let log_message = log_message.clone();
                    let full_context = full_context.clone();
                    async move {
                        crate::tracing::log_event(
                            db_writer,
                            log_level,
                            "http_response",
                            &log_message,
                            user_id,
                            Some(full_context),
                        )
                        .await;
                    }
                });
            }

            // Log performance warnings for slow requests
            if duration.as_millis() > 2000 {
                let perf_context = json!({
                    "request_id": request_id,
                    "slow_request": true,
                    "duration_ms": duration.as_millis(),
                    "threshold_ms": 2000,
                    "method": method.clone(),
                    "path": path.clone()
                });

                if let Some(db_writer) = db_writer.clone() {
                    tokio::spawn({
                        let db_writer = db_writer.clone();
                        let method = method.clone();
                        let path = path.clone();
                        let perf_context = perf_context.clone();
                        async move {
                            crate::tracing::log_event(
                                db_writer,
                                "WARN",
                                "performance",
                                &format!(
                                    "Slow request detected: {} {} ({}ms)",
                                    method,
                                    path,
                                    duration.as_millis()
                                ),
                                user_id,
                                Some(perf_context),
                            )
                            .await;
                        }
                    });
                }
            }

            // Log security events for suspicious activity
            if should_log_security_event(method.as_str(), path.as_str(), status_code, &user_agent) {
                let security_context = json!({
                    "request_id": request_id,
                    "security_event": true,
                    "suspicious_activity": classify_suspicious_activity(&path, status_code),
                    "remote_addr": remote_addr,
                    "user_agent": user_agent
                });

                if let Some(db_writer) = db_writer {
                    tokio::spawn({
                        let db_writer = db_writer.clone();
                        let method = method.clone();
                        let path = path.clone();
                        let remote_addr = remote_addr.clone();
                        let security_context = security_context.clone();
                        async move {
                            crate::tracing::log_security_event(
                                db_writer,
                                "SUSPICIOUS_REQUEST",
                                &format!(
                                    "Suspicious request pattern: {} {} -> {}",
                                    method, path, status_code
                                ),
                                user_id,
                                Some(&remote_addr),
                                Some(security_context),
                            )
                            .await;
                        }
                    });
                }
            }

            Ok(response)
        })
    }
}

/// Determine if a request should trigger a security log event.
fn should_log_security_event(
    _method: &str,
    path: &str,
    status_code: u16,
    user_agent: &str,
) -> bool {
    // Ensure method and path are used consistently as references
    // Log potential security issues
    match status_code {
        401 | 403 => true,                      // Unauthorized/Forbidden attempts
        404 if is_sensitive_path(path) => true, // Probing for sensitive endpoints
        _ => is_suspicious_user_agent(user_agent) || is_potential_attack_pattern(path),
    }
}

/// Check if a path is considered sensitive.
fn is_sensitive_path(path: &str) -> bool {
    let sensitive_patterns = [
        "/admin",
        "/api/admin",
        "/.env",
        "/config",
        "/backup",
        "/database",
        "/internal",
    ];

    sensitive_patterns
        .iter()
        .any(|pattern| path.contains(pattern))
}

/// Check if user agent appears suspicious.
fn is_suspicious_user_agent(user_agent: &str) -> bool {
    let suspicious_patterns = [
        "bot", "crawler", "scanner", "sqlmap", "nikto", "nmap", "masscan",
    ];

    let ua_lower = user_agent.to_lowercase();
    suspicious_patterns
        .iter()
        .any(|pattern| ua_lower.contains(pattern))
}

/// Check for potential attack patterns in the path.
fn is_potential_attack_pattern(path: &str) -> bool {
    let attack_patterns = [
        "../",          // Directory traversal
        "..\\",         // Windows directory traversal
        "union select", // SQL injection
        "<script",      // XSS attempt
        "javascript:",  // XSS attempt
        "eval(",        // Code injection
        "system(",      // Command injection
        "exec(",        // Command injection
    ];

    let path_lower = path.to_lowercase();
    attack_patterns
        .iter()
        .any(|pattern| path_lower.contains(pattern))
}

/// Classify the type of suspicious activity.
fn classify_suspicious_activity(path: &str, status_code: u16) -> &'static str {
    if status_code == 401 || status_code == 403 {
        "unauthorized_access_attempt"
    } else if status_code == 404 && is_sensitive_path(path) {
        "sensitive_endpoint_probing"
    } else if is_potential_attack_pattern(path) {
        "potential_injection_attempt"
    } else {
        "unknown_suspicious_activity"
    }
}

/// Extract real IP address considering proxy headers.
pub fn extract_real_ip(req: &ServiceRequest) -> String {
    // Check various headers for real IP
    let headers_to_check = [
        "x-forwarded-for",
        "x-real-ip",
        "x-client-ip",
        "cf-connecting-ip", // Cloudflare
        "true-client-ip",   // Cloudflare Enterprise
    ];

    for header_name in &headers_to_check {
        if let Some(header_value) = req.headers().get(*header_name) {
            if let Ok(ip_str) = header_value.to_str() {
                // Take the first IP if multiple are present (comma-separated)
                let first_ip = ip_str.split(',').next().unwrap_or("").trim();
                if !first_ip.is_empty() && first_ip != "unknown" {
                    return first_ip.to_string();
                }
            }
        }
    }

    // Fallback to connection info
    req.connection_info()
        .realip_remote_addr()
        .unwrap_or("unknown")
        .to_string()
}

/// Generate a correlation ID for request tracking across services.
pub fn generate_correlation_id() -> String {
    format!("req_{}", Uuid::new_v4().simple())
}

/// Extract request fingerprint for rate limiting and security analysis.
pub fn generate_request_fingerprint(req: &ServiceRequest) -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let mut hasher = DefaultHasher::new();

    // Hash combination of IP, User-Agent, and path
    extract_real_ip(req).hash(&mut hasher);
    req.headers()
        .get("user-agent")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("unknown")
        .hash(&mut hasher);
    req.path().hash(&mut hasher);

    format!("{:x}", hasher.finish())
}
