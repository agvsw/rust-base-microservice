use actix_web::web;

mod auth_controller;

pub fn init(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::resource("/protected")
            .route(web::get().to(auth_controller::protected))
    );
}