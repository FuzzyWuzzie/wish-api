use rusqlite::{Connection, Error};
use std::sync::Mutex;

pub type MutexConnection = Mutex<Connection>;

pub fn initialize_tables(conn: &Connection) -> Result<(), Error> {
    match conn.execute(
        "CREATE TABLE users (
        id integer primary key,
        name varchar(255) not null,
        email varchar(255) default null,
        google varchar(255) default null,
        facebook varchar(255) default null,
        picture text default null,
        pass varchar(60) not null,
        admin integer not null
    )",
        &[],
    ) {
        Ok(_) => println!("Created users table!"),
        Err(e) => println!(
            "Didn't create users table: {:?}",
            match e {
                Error::SqliteFailure(_, desc) => match desc {
                    Some(deets) => deets,
                    None => "?".to_string(),
                },
                _ => format!("{:?}", e),
            }
        ),
    };

    println!("Initialized tables!");
    Ok(())
}

pub fn get_connection(location: &str) -> Result<MutexConnection, Error> {
    let conn = Connection::open(location)?;
    Ok(Mutex::new(conn))
}
