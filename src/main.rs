use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, Generate, Key, KeyInit},
};
use pbkdf2::Pbkdf2;
use rand::{
    SeedableRng, TryRng,
    rngs::{StdRng, SysRng},
};
use std::{fs, io, process::Command};

fn main() {
    loop {
        let mut buf = String::new();
        io::stdin().read_line(&mut buf).unwrap();
        let queries: Vec<&str> = buf.split_whitespace().collect();
        if queries[0] == "write" {
            let file_name = queries[1];
            write_file(file_name);
        } else if queries[0] == "read" {
            let file_name = queries[1];
            read_file(file_name);
        } else if queries[0] == "edit" {
            let file_name = queries[1];
            edit_file(file_name);
        } else if queries[0] == "quit" {
            break;
        } else {
            println!("I don't know what that means");
        }
    }
}

fn write_file(file_name: &str) {
    if let Ok(exists) = fs::exists(file_name)
        && exists
    {
        eprintln!("Naughty boy trying to overwrite uh nono!!");
        return;
    }
    let output = Command::new("mktemp")
        .output()
        .expect("Failed to execute mktemp");

    if !output.status.success() {
        eprintln!("Couldn't create your file");
        return;
    }
    let temp_file_name = String::from_utf8(output.stdout).unwrap();
    let mut output = Command::new("nvim")
        .arg(temp_file_name.trim())
        .spawn()
        .expect("Failed to execute nvim");

    output.wait().unwrap();
    let contents = fs::read_to_string(temp_file_name.trim()).unwrap();
    let password = rpassword::prompt_password("Enter your password: ");
    if password.is_err() {
        eprintln!("Password lowk wrong pack it up");
        return;
    }
    let password = password.unwrap();

    let password = password.as_bytes();
    let pbkdf2 = Pbkdf2::default(); // Uses `Algorithm::default()` and `Params::RECOMMENDED`
    let mut salt = [0u8; 16];

    let mut rng = StdRng::try_from_rng(&mut SysRng).unwrap();
    rng.try_fill_bytes(&mut salt).unwrap();
    let mut pwhash = [0u8; 32];

    pbkdf2.hash_password_into(password, &salt, &mut pwhash);

    let key = Key::<Aes256Gcm>::from(pwhash);

    let cipher = Aes256Gcm::new(&key);

    let nonce = Nonce::generate(); // MUST be unique per message
    let ciphertext = cipher.encrypt(&nonce, contents.as_bytes()).unwrap();
    let mut enc_contents: Vec<u8> = vec![];
    enc_contents.extend(nonce.as_slice());
    enc_contents.extend(salt.as_slice());
    enc_contents.extend(ciphertext);
    fs::write(file_name.trim(), enc_contents).expect("Couldn't write the file");
    println!("success");
}

fn read_file(file_name: &str) {
    let Ok(enc_contents) = fs::read(file_name.trim()) else {
        eprintln!("Please enter a valid file name");
        return;
    };
    let password = rpassword::prompt_password("Enter your password: ");
    if password.is_err() {
        eprintln!("Password lowk wrong pack it up");
        return;
    }
    let password = password.unwrap();
    let password = password.as_bytes();
    let pbkdf2 = Pbkdf2::default(); // Uses `Algorithm::default()` and `Params::RECOMMENDED`
    let salt = &enc_contents[12..28];

    let mut pwhash = [0u8; 32];

    pbkdf2.hash_password_into(password, salt, &mut pwhash);

    let key = Key::<Aes256Gcm>::from(pwhash);

    let cipher = Aes256Gcm::new(&key);
    let nonce = Nonce::try_from(&enc_contents[0..12]).expect("File has been tampered with");

    let Ok(plaintext) = cipher.decrypt(&nonce, &enc_contents[28..]) else {
        eprintln!("Wrong password!!!");
        return;
    };

    let plaintext = String::from_utf8(plaintext).unwrap();

    println!("plaintext: {}", plaintext);
}

fn edit_file(file_name: &str) {
    let Ok(enc_contents) = fs::read(file_name.trim()) else {
        eprintln!("Please enter a valid file name");
        return;
    };
    let password = rpassword::prompt_password("Enter your password: ");
    if password.is_err() {
        eprintln!("Password lowk wrong pack it up");
        return;
    }
    let password = password.unwrap();
    let password = password.as_bytes();
    let pbkdf2 = Pbkdf2::default(); // Uses `Algorithm::default()` and `Params::RECOMMENDED`
    let salt = &enc_contents[12..28];

    let mut pwhash = [0u8; 32];

    pbkdf2.hash_password_into(password, salt, &mut pwhash);

    let key = Key::<Aes256Gcm>::from(pwhash);

    let cipher = Aes256Gcm::new(&key);
    let nonce = Nonce::try_from(&enc_contents[0..12]).expect("File has been tampered with");

    let Ok(plaintext) = cipher.decrypt(&nonce, &enc_contents[28..]) else {
        eprintln!("Wrong password!!!");
        return;
    };

    let plaintext = String::from_utf8(plaintext).unwrap();
    let output = Command::new("mktemp")
        .output()
        .expect("Failed to execute mktemp");

    if !output.status.success() {
        eprintln!("Couldn't create your file");
        return;
    }
    let temp_file_name = String::from_utf8(output.stdout).unwrap();
    fs::write(temp_file_name.trim(), plaintext).unwrap();

    let mut output = Command::new("nvim")
        .arg(temp_file_name.trim())
        .spawn()
        .expect("Failed to execute nvim");

    output.wait().unwrap();
    let contents = fs::read_to_string(temp_file_name.trim()).unwrap();

    let nonce = Nonce::generate(); // have to regenerate to preven nonce reuse
    let ciphertext = cipher.encrypt(&nonce, contents.as_bytes()).unwrap();
    let mut enc_contents: Vec<u8> = vec![];
    enc_contents.extend(nonce.as_slice());
    enc_contents.extend(salt);
    enc_contents.extend(ciphertext);
    fs::write(file_name.trim(), enc_contents).expect("Couldn't write the file");
    println!("success");
}
