use std::time::{SystemTime, UNIX_EPOCH};

use sso::{ISSO32, SSO32};

mod sso;

fn main() {
    let sso_algo = SSO32::new();

    let mask = [
        37, 224, 231, 113, 122, 239, 79, 78, 50, 157, 230, 23, 145, 157, 164, 144, 93, 235, 178,
        87, 101, 204, 84, 228, 30, 228, 240, 179, 125, 54, 81, 243, 152, 236, 49, 241, 188, 66, 73,
        5, 156, 203, 81, 132, 27, 1, 33, 64, 175, 65, 75, 31, 237, 18, 28, 152, 70, 243, 73, 253,
        100, 4, 57, 175, 76, 252, 225, 229, 26, 39, 78, 24, 61, 237, 159, 121, 106, 31, 225, 30,
        162, 119, 133, 161, 99, 153, 6, 50, 170, 220, 211, 212,
    ];

    let voc = sso_algo.create_voc(mask);

    println!("{:?}", voc);

    let shuffled_voc = sso_algo.shuffle_voc(voc.clone());

    println!("{:?}", shuffled_voc);

    let key = sso_algo.generate_key(
        "Hello World!!!".to_owned(),
        voc.clone(),
        sso::key_size::sso_256,
    );
    let start = SystemTime::now();
    let since_the_epoch = start
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards");
    let result: String = sso_algo.encrypt(key.clone(), "Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem IpsumLorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem IpsumLorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem IpsumLorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem IpsumLorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem IpsumLorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum".to_owned(), &sso::IntoBase::AES);
    let end = SystemTime::now();
    let end_the_epoch = end.duration_since(UNIX_EPOCH).expect("Time went backwards");

    println!("{}", result);

    println!(
        "{}",
        end_the_epoch.as_millis() - since_the_epoch.as_millis()
    );

    let decrypted: String = sso_algo.decrypt(key.clone(), result.clone(), &sso::IntoBase::AES);

    println!("{}", decrypted);
}
