// src/main.rs
use actix_web::{App, HttpServer, middleware};
use dotenv::dotenv;

mod routes;
mod services;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();

    println!("🚀 Auth Service running at http://localhost:8081");

    HttpServer::new(|| {
        App::new()
            .wrap(middleware::Logger::default())
            .configure(routes::init)
    })
    .bind(("127.0.0.1", 8081))?
    .run()
    .await
}