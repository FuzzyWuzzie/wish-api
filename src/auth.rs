use bcrypt::{hash, verify, DEFAULT_COST};
use rocket::http::Status;
use rocket::request::{self, FromRequest, Request};
use rocket::Outcome;
use rocket::State;
use std::sync::Mutex;
use rusqlite::Connection;
use base64;

use config::Config;
use tokens;
use errors::Error;

#[derive(Debug)]
pub struct AuthBasicSuccess {
    pub uid: u32,
    pub adm: bool,
}

#[derive(Debug)]
pub struct AuthToken {
    pub uid: u32,
    pub adm: bool,
}

pub struct IsAdmin();

impl<'a, 'r> FromRequest<'a, 'r> for AuthToken {
    type Error = ();

    fn from_request(request: &'a Request<'r>) -> request::Outcome<AuthToken, ()> {
        let auths: Vec<_> = request.headers().get("Authorization").collect();
        if auths.len() != 1 {
            return Outcome::Failure((Status::Unauthorized, ()));
        }
        let auth: Vec<&str> = auths[0].split(' ').collect();
        if auth.len() != 2 || auth[0] != "Bearer" {
            return Outcome::Failure((Status::Unauthorized, ()));
        }
        let token = auth[1];

        let config = request.guard::<State<Config>>()?;
        let token = match tokens::validate_token(&config.secret, &token) {
            Ok(tok) => tok,
            Err(_) => {
                println!("Invalid token!");
                return Outcome::Failure((Status::Unauthorized, ()));
            }
        };

        Outcome::Success(token)
    }
}

impl<'a, 'r> FromRequest<'a, 'r> for IsAdmin {
    type Error = ();

    fn from_request(request: &'a Request<'r>) -> request::Outcome<IsAdmin, ()> {
        let token = request.guard::<AuthToken>()?;
        if !token.adm {
            return Outcome::Failure((Status::Unauthorized, ()));
        }

        Outcome::Success(IsAdmin())
    }
}

impl<'a, 'r> FromRequest<'a, 'r> for AuthBasicSuccess {
    type Error = ();

    fn from_request(request: &'a Request<'r>) -> request::Outcome<AuthBasicSuccess, ()> {
        let auths: Vec<_> = request.headers().get("Authorization").collect();
        if auths.len() != 1 {
            return Outcome::Failure((Status::Unauthorized, ()));
        }

        let auth: Vec<&str> = auths[0].split(' ').collect();
        if auth.len() != 2 || auth[0] != "Basic" {
            return Outcome::Failure((Status::Unauthorized, ()));
        }

        let auth = auth[1];
        let auth = match base64::decode(&auth) {
            Ok(a) => a,
            Err(_) => return Outcome::Failure((Status::Unauthorized, ())) 
        };
        let auth: String = match String::from_utf8(auth) {
            Ok(a) => a,
            Err(_) => return Outcome::Failure((Status::Unauthorized, ())) 
        };

        let auth: Vec<&str> = auth.split(':').collect();
        if auth.len() < 2 {
            return Outcome::Failure((Status::Unauthorized, ()));
        }
        let user: &str = auth[0];
        let pass: &str = &auth[1..].join(":");

        let conn = request.guard::<State<Mutex<Connection>>>()?;
        let conn = conn.lock()
            .expect("Database lock");
        // TODO: check email or google or facebook instead of name
        let mut stmt = conn.prepare("select id, pass, admin from users where name=?1")
            .expect("prepare select");
        let (uid, hash, adm): (u32, String, bool) = match stmt.query_row(&[&user], |row| {
            let admin: i32 = row.get(2);
            (row.get(0), row.get(1), admin == 1)
        }) {
            Ok(data) => data,
            Err(_) => return Outcome::Failure((Status::Unauthorized, ())),
        };

        match verify(pass, &hash) {
            Ok(_) => Outcome::Success(AuthBasicSuccess { uid, adm }),
            Err(_) => Outcome::Failure((Status::Unauthorized, ()))
        }
    }
}

pub fn register_user(conn: &Connection, name: &str, pass: &str, admin: &bool) -> Result<u32, Error> {
    let hashed_pass = hash(pass, DEFAULT_COST)?;

    let adm: i32 = if *admin { 1 } else { 0 };
    conn.execute(
        "insert into users(name, pass, admin) values(?1, ?2, ?3)",
        &[&name, &hashed_pass, &adm],
    )?;

    let mut stmt = conn.prepare("select id from users order by id desc limit 1")?;
    let id:u32 = stmt.query_row(&[], |row| row.get(0))?;

    Ok(id)
}
