use rocket::State;
use rocket_contrib::{Json, Value};

use ::auth::{AuthBasicSuccess, AuthToken, IsAdmin};
use ::config::Config;
use ::tokens;
use ::messages;
use ::database::MutexConnection;

#[get("/")]
fn sign_in(config: State<Config>, auth: AuthBasicSuccess) -> Json<Value> {
    Json(json!({
        "token": tokens::build_token(&config.secret, auth.uid, auth.adm)
    }))
}

#[post("/", data="<credentials>")]
fn create_user(conn: State<MutexConnection>, credentials: Json<messages::CreateUserCredentials>, _auth: AuthToken, _adm: IsAdmin) -> Json<messages::UserID> {
    let conn = conn.lock()
        .expect("db connection lock");
    let uid:u32 = ::auth::register_user(&conn, &credentials.name, &credentials.pass, &credentials.admin)
        .unwrap(); // TODO: error handling
    Json(messages::UserID {
        uid
    })
}

// TODO: google and facebook endpoints
