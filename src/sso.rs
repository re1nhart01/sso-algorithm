use base64::prelude::*;
use rand::{
    rngs::StdRng,
    seq::{index, SliceRandom},
    Rng, SeedableRng,
};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

// алгоритм "SSO (Super Simple Algorithm)", працює по принципу передачі спеціальної строки в метод енкріпт, і реверснуту строку в декріпт
// сам алгоритм працює так, ключ S_e2xe5re6ae4oe3n_Е, має бути S_, має бути _E, start, end

// every two symbol xor, every 5 rotate, every 6 and every 4 or, every 3 not

// ключ можна сгенерити с полезної строки маски тоесть береться символ наприклад b в ключі рандомної строки, і береться с словника:

// b == 5a, і тд.

// методи encrypt, decrypt, generate key, shuffle voc, shuffle key, create_voc,
static STRING_VALUES: &str =
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=[]{}|;:',.<>?/~`";

static KEY_START: &str = "S_";
static KEY_END: &str = "_E0";
static ALGO_OP_START: &str = "e";
const OP_VEC: [&'static str; 6] = ["o", "x", "a", "n", "l", "r"];
const MASK_SIZE: usize = 92;

pub enum IntoBase {
    AES,
    BASE64,
    None,
}

pub enum key_size {
    sso_8,
    sso_16,
    sso_32,
    sso_64,
    sso_128,
    sso_256,
}

type Vocabular = HashMap<String, String>;

pub struct SSO32 {
    pub voc: Vocabular,
    pub into_selected: IntoBase,
}

pub trait ISSO32 {
    fn encrypt(&self, key: String, data: String, into: &IntoBase) -> String;
    fn decrypt(&self, key: String, encrypted_data: String, from: &IntoBase) -> String;
    fn generate_key(&self, salt: String, voc: Vocabular, key_len: key_size) -> String;
    fn shuffle_voc(&self, voc: Vocabular) -> Vocabular;
    fn create_voc(&self, mask: [u8; MASK_SIZE]) -> Vocabular;
    fn new() -> Self;
}

impl ISSO32 for SSO32 {
    fn encrypt(&self, key: String, data: String, into: &IntoBase) -> String {
        let into_data = match into {
            IntoBase::BASE64 => base64::encode(data),
            IntoBase::AES => base64::encode(data),
            IntoBase::None => base64::encode(data),
        };
        let mut result: Vec<u8> = Vec::new();

        let key_plain_vec: Vec<&str> = key.split("+").collect();
        let key_plain: String = key_plain_vec[1].to_string();
        let data_plain_vec: Vec<&str> = into_data.split("").filter(|&x| !x.is_empty()).collect();
        let key_data_split: Vec<&str> = key_plain
            .split("e")
            .filter(|&x| !x.is_empty())
            .collect::<Vec<&str>>();

        for path in data_plain_vec.iter() {
            let mut current_byte: u8 = String::from(path.to_owned()).into_bytes()[0];
            for key_path in key_data_split.iter() {
                let key_str_path = *key_path;
                let (operation, every_byte) = take_oops(key_str_path);
                //"o", "x", "a", "n", "l", "r"

                let byte_as: u8 = every_byte.parse().unwrap();

                let current_crypted_byte: u8 = match operation.as_str() {
                    "x" => xor(current_byte, byte_as),
                    "o" => u8::try_from(arithmetic_remove(current_byte as i16, byte_as as i16))
                        .unwrap(),
                    "a" => {
                        u8::try_from(arithmetic_add(current_byte as i16, byte_as as i16)).unwrap()
                    }
                    "n" => not(current_byte),
                    "l" => shift_l(current_byte, byte_as),
                    "r" => shift_r(current_byte, byte_as),
                    _ => 0,
                }
                .into();

                current_byte = current_crypted_byte;
            }
            result.push(current_byte);
        }

        return to_hex(result.as_slice());
    }

    fn decrypt(&self, key: String, encrypted_data: String, from: &IntoBase) -> String {
        let mut result: Vec<u8> = Vec::new();
        let key_plain_vec: Vec<&str> = key.split("+").collect();
        let key_plain: Vec<&str> = key_plain_vec[1]
            .split("e")
            .filter(|&x| !x.is_empty())
            .collect::<Vec<&str>>();

        let from_hex_encrypted_data: Vec<u8> = from_hex(encrypted_data.clone().as_str());

        for encrypted_byte in from_hex_encrypted_data.iter().rev() {
            let mut current_byte = encrypted_byte.clone();

            for key_path in key_plain.iter().rev() {
                let key_str_path = *key_path;
                let (operation, every_byte) = take_oops(key_str_path);
                //"o", "x", "a", "n", "l", "r"

                let byte_as: u8 = every_byte.parse().unwrap();

                let current_decrypted_byte: u8 = match operation.as_str() {
                    "x" => xor(current_byte, byte_as),
                    "o" => {
                        u8::try_from(arithmetic_add(current_byte as i16, byte_as as i16)).unwrap()
                    }
                    "a" => u8::try_from(arithmetic_remove(current_byte as i16, byte_as as i16))
                        .unwrap(),
                    "n" => not(current_byte),
                    "l" => shift_r(current_byte, byte_as),
                    "r" => shift_l(current_byte, byte_as),
                    _ => 0,
                };

                current_byte = current_decrypted_byte;
            }

            result.push(current_byte);
        }

        let string_representation = String::from_utf8_lossy(&result)
            .chars()
            .rev()
            .collect::<String>();

        let final_result = match from {
            IntoBase::BASE64 => base64::decode(string_representation),
            IntoBase::AES => base64::decode(string_representation),
            IntoBase::None => base64::decode(string_representation),
        };

        return String::from_utf8(final_result.unwrap()).unwrap();
    }

    fn generate_key(&self, salt: String, voc: Vocabular, key_len: key_size) -> String {
        let key_len_v = get_key_size(key_len);
        let mut result_key: String = String::from("");

        let salted_key = generate_random_string_from_salt(&salt.clone(), key_len_v as usize);

        for value in salted_key.chars() {
            let value_as_string: String = value.to_string();
            let string_from_voc = voc.get(&value_as_string).expect("HEEEE");

            result_key += string_from_voc;
        }

        return add_key_signatures(result_key, key_len_v);
    }

    fn shuffle_voc(&self, voc: Vocabular) -> Vocabular {
        let mut rng = rand::thread_rng();
        let mut shuffled_voc: HashMap<String, String> = HashMap::new();
        let mut original_voc_vector: Vec<&String> = voc.values().collect::<Vec<&String>>();
        original_voc_vector.shuffle(&mut rng);

        for (index, char) in STRING_VALUES.chars().into_iter().enumerate() {
            let str_clip = char.to_string();
            let original_clip: String = original_voc_vector[index].clone().into();
            shuffled_voc.insert(str_clip, original_clip);
        }

        return shuffled_voc;
    }

    fn create_voc(&self, mask: [u8; MASK_SIZE]) -> Vocabular {
        let mut result: HashMap<String, String> = HashMap::new();

        for (index, value) in mask.iter().enumerate() {
            let current_string_values_cursor: String =
                STRING_VALUES.chars().nth(index).unwrap().to_string();
            let rand_mask_value = get_random_value(*value as u64);

            let generated_voc_v = generate_algo_str(rand_mask_value);

            result.insert(
                current_string_values_cursor.clone(),
                generated_voc_v.clone(),
            );
        }

        return result;
    }

    fn new() -> Self {
        return Self {
            voc: HashMap::new(),
            into_selected: IntoBase::None,
        };
    }
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn from_hex(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}

pub fn get_key_size(sz: key_size) -> u16 {
    match sz {
        key_size::sso_8 => 8,
        key_size::sso_16 => 16,
        key_size::sso_32 => 32,
        key_size::sso_64 => 64,
        key_size::sso_128 => 128,
        key_size::sso_256 => 256,
    }
}

fn get_random_value(seed: u64) -> u32 {
    let mut rng = StdRng::seed_from_u64(seed);
    rng.gen_range(0..100) // Генерируем число от 0 до 99
}

fn generate_algo_str(v: u32) -> String {
    let mut rng = rand::thread_rng();

    let rand_num = rng.gen_range(0..254);

    let ending_op = OP_VEC[rng.gen_range(0..OP_VEC.len())];

    return format!("{}{}{}", ALGO_OP_START, rand_num, ending_op);
}

fn generate_random_string_from_salt(salt: &str, length: usize) -> String {
    // Hash the salt using SHA-256 to create a seed for random number generation
    let mut hasher = Sha256::new();
    hasher.update(salt);
    let hash = hasher.finalize();

    let seed: [u8; 32] = hash.into();
    let mut rng = StdRng::from_seed(seed);

    let charset: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ\
                           abcdefghijklmnopqrstuvwxyz\
                           0123456789";
    let random_string: String = (0..length)
        .map(|_| {
            let idx = rng.gen_range(0..charset.len());
            charset[idx] as char
        })
        .collect();

    return random_string;
}

fn add_key_signatures(key: String, key_size: u16) -> String {
    let mut signature: String = format!("{{\"algo\": \"sso\", sz: \"{}\"}}", key_size);
    let sign_b64: String = base64::encode(signature);

    return format!("{}+{}+{}{}", KEY_START, key, sign_b64, KEY_END);
}

fn take_oops(key_path: &str) -> (String, String) {
    if key_path.len() <= 0 {
        return ("".to_owned(), "".to_owned());
    }
    let char_iter = key_path.clone().chars();
    return (
        char_iter.clone().skip(key_path.len() - 1).collect(),
        String::from(key_path)[0..key_path.len() - 1].to_string(),
    );
}

//encrypt (data.charCodeAt(i) + key) % 256
//decrypt (encryptedData[i] - key + 256) % 256
fn arithmetic_add(op1: i16, op2: i16) -> i16 {
    return (op1 + op2) % 256;
}

fn arithmetic_remove(op1: i16, op2: i16) -> i16 {
    return (op1 - op2 + 256) % 256;
}

fn or(op1: u8, op2: u8) -> u8 {
    return if op1 - op2 < 0 { op1 } else { op1 - op2 };
}

fn not(op1: u8) -> u8 {
    return !op1;
}

fn xor(op1: u8, op2: u8) -> u8 {
    return op1 ^ op2;
}

fn shift_l(op1: u8, shift: u8) -> u8 {
    return op1.rotate_left(u32::from(shift));
}

fn shift_r(op1: u8, shift: u8) -> u8 {
    return op1.rotate_right(u32::from(shift));
}
