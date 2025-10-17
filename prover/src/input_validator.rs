// Input validation for authentication credentials
use anyhow::{Result, bail};

const MIN_USERNAME_LEN: usize = 3;
const MAX_USERNAME_LEN: usize = 32;
const MIN_PASSWORD_LEN: usize = 8;
const MAX_PASSWORD_LEN: usize = 128;

pub fn validate_username(username: &[u8]) -> Result<()> {
    if username.len() < MIN_USERNAME_LEN {
        bail!("Username too short");
    }
    if username.len() > MAX_USERNAME_LEN {
        bail!("Username too long");
    }
    
    for &byte in username {
        if byte == 0 || byte < 32 || byte == 127 {
            bail!("Invalid characters in username");
        }
    }
    
    Ok(())
}

pub fn validate_password(password: &[u8]) -> Result<()> {
    if password.len() < MIN_PASSWORD_LEN {
        bail!("Password too short");
    }
    if password.len() > MAX_PASSWORD_LEN {
        bail!("Password too long");
    }
    
    if password.contains(&0) {
        bail!("Invalid characters in password");
    }
    
    Ok(())
}
