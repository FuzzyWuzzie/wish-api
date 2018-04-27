use std::io;
use std::fs::File;
use std::io::prelude::*;
use toml;

#[derive(Deserialize)]
pub struct Config {
    pub secret: String,
}

impl Config {
    pub fn load(filename: &str) -> Result<Config, io::Error> {
        let mut config_file = File::open(filename)?;
        let mut contents = String::new();
        config_file.read_to_string(&mut contents)?;
        match toml::from_str(&contents) {
            Ok(c) => Ok(c),
            Err(_) => Err(io::Error::new(io::ErrorKind::InvalidData, "couldn't parse config.toml"))
        }
    }
}