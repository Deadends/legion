use anyhow::Result;
use actix_web::{web, App, HttpServer, middleware, HttpResponse};
use actix_cors::Cors;
use actix_files::Files;
use std::sync::Arc;
use legion_prover::{ApplicationService, http_server::configure_routes};

#[actix_web::main]
async fn main() -> Result<()> {
    let app_service = Arc::new(ApplicationService::new()?);
    let addr = "127.0.0.1:8080";

    println!("🚀 Legion HTTP Server starting on http://{}", addr);
    println!("📡 Endpoints:");
    println!("   POST /api/register");
    println!("   POST /api/login");
    #[cfg(feature = "webauthn")]
    {
        println!("   POST /api/webauthn/register/start");
        println!("   POST /api/webauthn/register/finish");
        println!("   POST /api/webauthn/auth/start");
        println!("   POST /api/webauthn/auth/finish");
        println!("   GET  /api/protected");
    }
    println!("\n🌐 Open http://localhost:8080 in your browser");

    HttpServer::new(move || {
        let cors = Cors::permissive();
        
        App::new()
            .wrap(cors)
            .wrap(middleware::Logger::default())
            .app_data(web::Data::new(app_service.clone()))
            .configure(configure_routes)
            .service(Files::new("/", ".").index_file("webauthn_client.html"))
    })
    .bind(addr)?
    .run()
    .await?;

    Ok(())
}
