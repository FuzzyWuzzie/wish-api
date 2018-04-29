#![feature(plugin)]
#![plugin(rocket_codegen)]

extern crate rocket;
extern crate rocket_contrib;
#[macro_use]
extern crate serde_derive;
extern crate argparse;
extern crate rusqlite;
extern crate toml;
extern crate base64;
extern crate bcrypt;

use argparse::{ArgumentParser, Store, StoreTrue};

mod auth;
mod config;
mod database;
mod messages;
mod routes;
mod tokens;
mod errors;

fn main() {
    let mut create_admin_user = false;
    let mut name = String::new();
    let mut pass = String::new();
    {
        let mut parser = ArgumentParser::new();
        parser.set_description("wish server!");
        parser.refer(&mut create_admin_user).add_option(
            &["-a"],
            StoreTrue,
            "create admin user, must supply --name & --pass",
        );
        parser
            .refer(&mut name)
            .add_option(&["--name"], Store, "the username");
        parser
            .refer(&mut pass)
            .add_option(&["--pass"], Store, "the password");

        parser.parse_args_or_exit();
    }

    let config = config::Config::load("config.toml")
        .expect("Unable to open and parse config.toml!");

    let db = database::get_connection("wishes.db")
        .expect("Unable to open database connection (wishes.db)!");
    {
        let conn = db.lock()
            .expect("Database lock");
        database::initialize_tables(&conn)
            .expect("Could not initialize database tables!");    
    }

    if create_admin_user {
        println!("Creating user...");
        let conn = db.lock()
            .expect("Database lock");
        auth::register_user(&conn, &name, &pass, &true)
            .expect("Failed to create admin user!");
        println!(
            "Created admin user with name '{}'!", name);
    }
    else {
        rocket::ignite()
            .manage(config)
            .manage(db)
            .mount("/auth", routes![routes::auth::sign_in, routes::auth::create_user, routes::auth::refresh_token])
            .launch();
    }
}
