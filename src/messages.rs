#[derive(Serialize, Deserialize, Debug)]
pub struct CreateUserCredentials {
    pub name:String,
    pub pass:String,
    pub admin:bool
}

#[derive(Serialize, Deserialize, Debug)]
pub struct UserID {
    pub uid:u32
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Token {
    pub token:String
}
