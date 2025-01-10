use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use clap::{Parser, Subcommand};
use enigo::{Enigo, Key, KeyboardControllable};
use rand::{thread_rng, Rng};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::io;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use thiserror::Error;

const DATA_FILE: &str = "key.dat";

fn mask_private_key(key: &str) -> String {
    if key.len() <= 10 {
        return "[PROTECTED]".to_string();
    }
    format!("{}...{}", &key[..5], &key[key.len()-5..])
}

fn get_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[derive(Error, Debug)]
pub enum WalletError {
    #[error("Invalid password")]
    InvalidPassword,
    #[error("Wallet not found: {0}")]
    WalletNotFound(String),
    #[error("Wallet already exists: {0}")]
    WalletAlreadyExists(String),
    #[error("IO error: {0}")]
    IoError(#[from] io::Error),
    #[error("Encryption error: {0}")]
    EncryptionError(String),
    #[error("File format error: {0}")]
    FileFormatError(String),
    #[error("JSON error: {0}")]
    JsonError(#[from] serde_json::Error),
}

type Result<T> = std::result::Result<T, WalletError>;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    AddWallet {
        #[arg(short, long)]
        name: String,
        #[arg(short, long)]
        private_key: String,
        #[arg(short, long)]
        password: String,
    },
    RemoveWallet {
        #[arg(short, long)]
        name: String,
        #[arg(short, long)]
        password: String,
    },
    ListWallets {
        #[arg(short, long)]
        password: String,
    },
    TypeKey {
        #[arg(short, long)]
        name: String,
        #[arg(short, long)]
        password: String,
    },
    ExportKey {
        #[arg(short, long)]
        password: String,
        #[arg(short, long)]
        file: String,
    },
    ChangePassword {
        #[arg(short, long)]
        old_password: String,
        #[arg(short, long)]
        new_password: String,
    },
}

#[derive(Serialize, Deserialize, Clone)]
struct Wallet {
    name: String,
    encrypted_private_key: Vec<u8>,
    nonce: Vec<u8>,
    key: Vec<u8>,
    created_at: u64,
    last_accessed: u64,
}

#[derive(Serialize, Deserialize)]
struct WalletData {
    wallets: HashMap<String, Wallet>,
    password_hash: String,
}

impl WalletData {
    fn new(password: &str) -> Result<Self> {
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        let password_hash = argon2
            .hash_password(password.as_bytes(), &salt)
            .map_err(|e| WalletError::EncryptionError(e.to_string()))?
            .to_string();

        Ok(WalletData {
            wallets: HashMap::new(),
            password_hash,
        })
    }

    fn save_to_file(&self) -> Result<()> {
        let json = serde_json::to_string(self)?;
        fs::write(DATA_FILE, json)?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Ok(mut perms) = fs::metadata(DATA_FILE).and_then(|m| Ok(m.permissions())) {
                perms.set_mode(0o600);
                let _ = fs::set_permissions(DATA_FILE, perms);
            }
        }

        Ok(())
    }

    fn load_from_file() -> Result<Self> {
        let json = fs::read_to_string(DATA_FILE)?;
        let data: WalletData = serde_json::from_str(&json)?;
        Ok(data)
    }

    fn verify_password(&self, password: &str) -> bool {
        if let Ok(parsed_hash) = PasswordHash::new(&self.password_hash) {
            Argon2::default()
                .verify_password(password.as_bytes(), &parsed_hash)
                .is_ok()
        } else {
            false
        }
    }

    fn add_wallet(&mut self, name: String, private_key: String, password: &str) -> Result<()> {
        if !self.verify_password(password) {
            return Err(WalletError::InvalidPassword);
        }

        if self.wallets.contains_key(&name) {
            return Err(WalletError::WalletAlreadyExists(name));
        }

        let key = thread_rng().gen::<[u8; 32]>().to_vec();
        let cipher = Aes256Gcm::new_from_slice(&key)
            .map_err(|e| WalletError::EncryptionError(e.to_string()))?;
        let nonce_bytes = thread_rng().gen::<[u8; 12]>();
        let nonce = Nonce::from_slice(&nonce_bytes);

        let encrypted_private_key = cipher
            .encrypt(nonce, private_key.as_bytes())
            .map_err(|e| WalletError::EncryptionError(e.to_string()))?;

        let wallet = Wallet {
            name: name.clone(),
            encrypted_private_key,
            nonce: nonce_bytes.to_vec(),
            key,
            created_at: get_timestamp(),
            last_accessed: get_timestamp(),
        };

        self.wallets.insert(name.clone(), wallet);
        self.save_to_file()?;
        println!("Wallet '{}' added successfully!", name);
        Ok(())
    }

    fn remove_wallet(&mut self, name: &str, password: &str) -> Result<()> {
        if !self.verify_password(password) {
            return Err(WalletError::InvalidPassword);
        }

        if !self.wallets.contains_key(name) {
            return Err(WalletError::WalletNotFound(name.to_string()));
        }

        self.wallets.remove(name);
        self.save_to_file()?;
        println!("Wallet '{}' removed successfully!", name);
        Ok(())
    }

    fn get_wallet_key(&self, name: &str, password: &str) -> Result<String> {
        if !self.verify_password(password) {
            return Err(WalletError::InvalidPassword);
        }

        let wallet = self.wallets
            .get(name)
            .ok_or_else(|| WalletError::WalletNotFound(name.to_string()))?;

        let cipher = Aes256Gcm::new_from_slice(&wallet.key)
            .map_err(|e| WalletError::EncryptionError(e.to_string()))?;
        let nonce = Nonce::from_slice(&wallet.nonce);

        let private_key = cipher
            .decrypt(nonce, wallet.encrypted_private_key.as_slice())
            .map_err(|e| WalletError::EncryptionError(e.to_string()))?;

        String::from_utf8(private_key)
            .map_err(|e| WalletError::EncryptionError(e.to_string()))
    }

    fn update_last_accessed(&mut self, name: &str) -> Result<()> {
        if let Some(wallet) = self.wallets.get_mut(name) {
            wallet.last_accessed = get_timestamp();
            self.save_to_file()?;
        }
        Ok(())
    }

    fn list_wallets(&mut self, password: &str) -> Result<()> {
        if !self.verify_password(password) {
            return Err(WalletError::InvalidPassword);
        }

        println!("\nAvailable wallets:");
        println!("------------------");
        
        let wallet_names: Vec<String> = self.wallets.keys().cloned().collect();
        for name in wallet_names {
            match self.get_wallet_key(&name, password) {
                Ok(key) => {
                    println!("Name: {}", name);
                    println!("Key:  {}", mask_private_key(&key));
                    println!("------------------");
                    let _ = self.update_last_accessed(&name);
                }
                Err(e) => {
                    println!("Warning: Could not decrypt wallet '{}': {}", name, e);
                }
            }
        }

        self.check_security_status()?;
        Ok(())
    }

    fn check_security_status(&self) -> Result<()> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Ok(metadata) = fs::metadata(DATA_FILE) {
                if metadata.permissions().mode() & 0o777 != 0o600 {
                    println!("\nSecurity Warning: Wallet file permissions are too open.");
                    println!("Recommended: chmod 600 {}", DATA_FILE);
                }
            }
        }

        let current_time = get_timestamp();
        for wallet in self.wallets.values() {
            if current_time - wallet.created_at < 60 && 
               wallet.last_accessed - wallet.created_at < 60 {
                println!("\nSecurity Warning: Rapid access detected for wallet '{}'", wallet.name);
            }
        }

        Ok(())
    }

    fn export_all_keys(&mut self, password: &str, file_path: &str) -> Result<()> {
        if !self.verify_password(password) {
            return Err(WalletError::InvalidPassword);
        }

        // Read the template file
        let mut content = fs::read_to_string(file_path)?;
        
        // Collect wallet names first to avoid borrowing issues
        let wallet_names: Vec<String> = self.wallets.keys().cloned().collect();
        
        // Track which wallets were replaced
        let mut replaced_wallets = Vec::new();
        let mut missing_wallets = Vec::new();
        
        // Replace each wallet placeholder with its key
        for name in wallet_names {
            let placeholder = format!("[{}]", name);
            if content.contains(&placeholder) {
                match self.get_wallet_key(&name, password) {
                    Ok(key) => {
                        content = content.replace(&placeholder, &key);
                        replaced_wallets.push(name.clone());
                        let _ = self.update_last_accessed(&name);
                    }
                    Err(e) => {
                        println!("Warning: Could not decrypt wallet '{}': {}", name, e);
                    }
                }
            } else {
                missing_wallets.push(name);
            }
        }

        // Write the updated content back to the file
        fs::write(file_path, content)?;

        // Print summary
        if !replaced_wallets.is_empty() {
            println!("\nSuccessfully replaced keys for wallets:");
            for name in replaced_wallets {
                println!("- {}", name);
            }
        }

        if !missing_wallets.is_empty() {
            println!("\nWallets without placeholders in the file:");
            for name in missing_wallets {
                println!("- {}", name);
            }
        }

        Ok(())
    }

    fn change_password(&mut self, old_password: &str, new_password: &str) -> Result<()> {
        if !self.verify_password(old_password) {
            return Err(WalletError::InvalidPassword);
        }

        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        self.password_hash = argon2
            .hash_password(new_password.as_bytes(), &salt)
            .map_err(|e| WalletError::EncryptionError(e.to_string()))?
            .to_string();

        self.save_to_file()?;
        println!("Password changed successfully!");
        Ok(())
    }
}

fn simulate_typing(text: &str) -> Result<()> {
    let mut enigo = Enigo::new();
    println!("Starting typing in 5 seconds... Move your cursor to the target input field.");
    
    // Initial countdown
    for i in (1..=5).rev() {
        println!("Starting in {}...", i);
        thread::sleep(Duration::from_secs(1));
    }

    // Wait additional random time to avoid timing patterns
    let mut rng = thread_rng();
    thread::sleep(Duration::from_millis(rng.gen_range(100..500)));

    let chars: Vec<char> = text.chars().collect();
    for (_i, &c) in chars.iter().enumerate() {
        // Add random delays between keystrokes
        thread::sleep(Duration::from_millis(rng.gen_range(50..150)));
        
        // 20% chance to make a "mistake"
        if rng.gen_ratio(1, 5) {
            // Type a random character
            let wrong_char = (b'a' + rng.gen_range(0..26)) as char;
            enigo.key_sequence(&wrong_char.to_string());
            thread::sleep(Duration::from_millis(rng.gen_range(100..300)));
            
            // Press backspace to correct it
            enigo.key_click(Key::Backspace);
            thread::sleep(Duration::from_millis(rng.gen_range(50..150)));
        }

        // 10% chance to move cursor around
        if rng.gen_ratio(1, 10) {
            enigo.key_click(Key::LeftArrow);
            thread::sleep(Duration::from_millis(rng.gen_range(50..150)));
            enigo.key_click(Key::RightArrow);
            thread::sleep(Duration::from_millis(rng.gen_range(50..150)));
        }

        // Type the actual character
        enigo.key_sequence(&c.to_string());
    }

    Ok(())
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::AddWallet {
            name,
            private_key,
            password,
        } => {
            println!("Adding wallet '{}'...", name);
            let mut wallet_data = match WalletData::load_from_file() {
                Ok(data) => data,
                Err(_) => {
                    println!("No existing wallet file found. Creating new...");
                    WalletData::new(&password)?
                }
            };
            
            match wallet_data.add_wallet(name.clone(), private_key, &password) {
                Ok(_) => (),
                Err(WalletError::InvalidPassword) => {
                    eprintln!("Error: Invalid password");
                    std::process::exit(1);
                }
                Err(WalletError::WalletAlreadyExists(_)) => {
                    eprintln!("Error: A wallet with this name already exists");
                    std::process::exit(1);
                }
                Err(e) => {
                    eprintln!("Error adding wallet: {}", e);
                    std::process::exit(1);
                }
            }
        }

        Commands::RemoveWallet { name, password } => {
            println!("Removing wallet '{}'...", name);
            let mut wallet_data = match WalletData::load_from_file() {
                Ok(data) => data,
                Err(e) => {
                    eprintln!("Error loading wallet data: {}", e);
                    std::process::exit(1);
                }
            };

            match wallet_data.remove_wallet(&name, &password) {
                Ok(_) => (),
                Err(WalletError::InvalidPassword) => {
                    eprintln!("Error: Invalid password");
                    std::process::exit(1);
                }
                Err(WalletError::WalletNotFound(_)) => {
                    eprintln!("Error: Wallet not found");
                    std::process::exit(1);
                }
                Err(e) => {
                    eprintln!("Error removing wallet: {}", e);
                    std::process::exit(1);
                }
            }
        }

        Commands::ListWallets { password } => {
            let mut wallet_data = match WalletData::load_from_file() {
                Ok(data) => data,
                Err(e) => {
                    eprintln!("Error loading wallet data: {}", e);
                    std::process::exit(1);
                }
            };

            match wallet_data.list_wallets(&password) {
                Ok(_) => (),
                Err(WalletError::InvalidPassword) => {
                    eprintln!("Error: Invalid password");
                    std::process::exit(1);
                }
                Err(e) => {
                    eprintln!("Error listing wallets: {}", e);
                    std::process::exit(1);
                }
            }
        }

        Commands::TypeKey { name, password } => {
            let mut wallet_data = match WalletData::load_from_file() {
                Ok(data) => data,
                Err(e) => {
                    eprintln!("Error loading wallet data: {}", e);
                    std::process::exit(1);
                }
            };

            match wallet_data.get_wallet_key(&name, &password) {
                Ok(key) => {
                    println!("Retrieved key for wallet '{}'", name);
                    let _ = wallet_data.update_last_accessed(&name);
                    if let Err(e) = simulate_typing(&key) {
                        eprintln!("Error during typing: {}", e);
                        std::process::exit(1);
                    }
                }
                Err(WalletError::InvalidPassword) => {
                    eprintln!("Error: Invalid password");
                    std::process::exit(1);
                }
                Err(WalletError::WalletNotFound(_)) => {
                    eprintln!("Error: Wallet not found");
                    std::process::exit(1);
                }
                Err(e) => {
                    eprintln!("Error retrieving wallet key: {}", e);
                    std::process::exit(1);
                }
            }
        }

        Commands::ExportKey { password, file } => {
            println!("Exporting wallet keys...");
            let mut wallet_data = match WalletData::load_from_file() {
                Ok(data) => data,
                Err(e) => {
                    eprintln!("Error loading wallet data: {}", e);
                    std::process::exit(1);
                }
            };

            match wallet_data.export_all_keys(&password, &file) {
                Ok(_) => (),
                Err(WalletError::InvalidPassword) => {
                    eprintln!("Error: Invalid password");
                    std::process::exit(1);
                }
                Err(e) => {
                    eprintln!("Error exporting keys: {}", e);
                    std::process::exit(1);
                }
            }
        }

        Commands::ChangePassword {
            old_password,
            new_password,
        } => {
            println!("Changing password...");
            let mut wallet_data = match WalletData::load_from_file() {
                Ok(data) => data,
                Err(e) => {
                    eprintln!("Error loading wallet data: {}", e);
                    std::process::exit(1);
                }
            };

            match wallet_data.change_password(&old_password, &new_password) {
                Ok(_) => (),
                Err(WalletError::InvalidPassword) => {
                    eprintln!("Error: Invalid old password");
                    std::process::exit(1);
                }
                Err(e) => {
                    eprintln!("Error changing password: {}", e);
                    std::process::exit(1);
                }
            }
        }
    }

    Ok(())
}