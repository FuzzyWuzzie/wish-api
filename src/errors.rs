use rusqlite;
use bcrypt;

#[derive(Debug)]
pub enum Error {
    DatabaseError(rusqlite::Error),
    PasswordError(bcrypt::BcryptError)
}

impl From<rusqlite::Error> for Error {
    fn from(error:rusqlite::Error) -> Self {
        Error::DatabaseError(error)
    }
}

impl From<bcrypt::BcryptError> for Error {
    fn from(error:bcrypt::BcryptError) -> Self {
        Error::PasswordError(error)
    }
}
