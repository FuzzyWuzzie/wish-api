#![feature(plugin)]
#![plugin(rocket_codegen)]

extern crate rocket;

fn main() {
    rocket::ignite().launch();
}
