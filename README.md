Here’s the README in English based on the provided code and comments:

---

# SSO (Super Simple Algorithm)

The SSO (Super Simple Algorithm) works by passing a special string to the encryption method and a reversed string to the decryption method. The algorithm follows these principles:

- The key must start with `S_` and end with `_E` (Start and End markers).
- Every two symbols are XORed.
- Every 5 symbols are rotated.
- Every 6th and 4th symbols are ORed.
- Every 3rd symbol is negated (NOT operation).

### Key Generation

A key can be generated from a useful string by selecting a character (e.g., `b`) from a random string and then mapping it using a predefined dictionary, for example:

`b == 5a`, and so on.

### Methods:

- `encrypt()`
- `decrypt()`
- `generate_key()`
- `shuffle_voc()`
- `shuffle_key()`
- `create_voc()`

### Example Usage:

```rust
let sso_algo = SSO32::new();

// Example mask
let mask = [
    37, 224, 231, 113, 122, 239, 79, 78, 50, 157, 230, 23, 145, 157, 164, 144, 93, 235, 178,
    87, 101, 204, 84, 228, 30, 228, 240, 179, 125, 54, 81, 243, 152, 236, 49, 241, 188, 66, 73,
    5, 156, 203, 81, 132, 27, 1, 33, 64, 175, 65, 75, 31, 237, 18, 28, 152, 70, 243, 73, 253,
    100, 4, 57, 175, 76, 252, 225, 229, 26, 39, 78, 24, 61, 237, 159, 121, 106, 31, 225, 30,
    162, 119, 133, 161, 99, 153, 6, 50, 170, 220, 211, 212,
];

// Create a vocabulary from the mask
let voc = sso_algo.create_voc(mask);
println!("{:?}", voc);

// Shuffle the vocabulary
let shuffled_voc = sso_algo.shuffle_voc(voc.clone());
println!("{:?}", shuffled_voc);

// Generate a key from a string and the vocabulary
let key = sso_algo.generate_key(
    "Hello World!!!".to_owned(),
    voc.clone(),
    sso::key_size::sso_256,
);

// Track the encryption time
let start = SystemTime::now();
let since_the_epoch = start
    .duration_since(UNIX_EPOCH)
    .expect("Time went backwards");

// Encrypt a large string
let result: String = sso_algo.encrypt(
    key.clone(),
    "Lorem Ipsum is simply dummy text of the printing and typesetting industry...".to_owned(),
    &sso::IntoBase::AES
);

// End the encryption time
let end = SystemTime::now();
let end_the_epoch = end
    .duration_since(UNIX_EPOCH)
    .expect("Time went backwards");

println!("{}", result);
println!("Encryption time (ms): {}", end_the_epoch.as_millis() - since_the_epoch.as_millis());

// Decrypt the result
let decrypted: String = sso_algo.decrypt(key.clone(), result.clone(), &sso::IntoBase::AES);
println!("{}", decrypted);
```

### How It Works:
1. **Mask**: A mask is defined as a set of numbers, which are then used to create a vocabulary.
2. **Shuffle**: The vocabulary is shuffled for randomness.
3. **Key Generation**: A key is generated from the input string using the shuffled vocabulary.
4. **Encryption**: The input text is encrypted using the generated key and a base algorithm such as AES.
5. **Decryption**: The text is decrypted back to its original form using the same key.
