mod config;
mod handlers;

use axum::{
    Router,
    routing::post,
};
use std::sync::Arc;
use tokio::sync::RwLock;
use tower::ServiceBuilder;
use tower_http::trace::TraceLayer;
use tracing::{error, info, warn};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use config::ServerConfig;

#[tokio::main]
async fn main() {
    // Initialize tracing
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "server=debug,tower_http=debug,axum::rejection=trace".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    info!("Starting PODB server");

    // Load server configuration
    let config = ServerConfig::load_or_default("config.toml");
    info!(
        "Loaded configuration: bind address {}",
        config.bind_address()
    );

    // Parse initial admins from config
    let initial_admins = match config.parse_initial_admins() {
        Ok(admins) => {
            info!("Loaded {} initial admins from config", admins.len());
            admins
        }
        Err(e) => {
            if !config.membership.initial_admins.is_empty() {
                warn!(
                    "Failed to parse initial admins from config: {}. Starting with empty admin set.",
                    e
                );
            } else {
                info!("No initial admins specified in config");
            }
            Vec::new()
        }
    };

    // Initialize shared state with initial admins
    let membership_service = if initial_admins.is_empty() {
        handlers::MembershipService::new()
    } else {
        match handlers::MembershipService::new_with_initial_admins(initial_admins) {
            Ok(service) => service,
            Err(e) => {
                error!(
                    "Failed to initialize membership service with initial admins: {:?}",
                    e
                );
                std::process::exit(1);
            }
        }
    };
    let shared_state = Arc::new(RwLock::new(membership_service));

    let app = Router::new()
        .route("/membership/accept-invite", post(handlers::accept_invite))
        .route("/membership/prove-is-admin", post(handlers::prove_is_admin))
        .route("/posts/add", post(handlers::add_post))
        .with_state(shared_state)
        .layer(ServiceBuilder::new().layer(TraceLayer::new_for_http()));

    let bind_addr = config.bind_address();
    info!("Starting HTTP server on {}", bind_addr);
    let listener = tokio::net::TcpListener::bind(&bind_addr).await.unwrap();
    info!("Server ready to accept connections");

    axum::serve(listener, app).await.unwrap();
}
