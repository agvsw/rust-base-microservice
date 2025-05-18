use actix_web::{HttpRequest, HttpResponse, Responder};
use crate::services::jwt_service;

pub async fn protected(req: HttpRequest) -> impl Responder {
    let auth_header = req
        .headers()
        .get("Authorization")
        .and_then(|v| v.to_str().ok());

    if let Some(auth_header) = auth_header {
        if let Some(token) = auth_header.strip_prefix("Bearer ") {
            match jwt_service::validate_jwt(token).await {
                Ok(claims) => return HttpResponse::Ok().json(claims),
                Err(err) => return HttpResponse::Unauthorized().body(err),
            }
        }
    }
    HttpResponse::Unauthorized().body("Missing or invalid Authorization header")
}