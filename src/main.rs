use rayon::prelude::*;
use tfhe::prelude::*;
use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint32};

fn main() {
    let config = ConfigBuilder::all_disabled()
        .enable_default_integers()
        .build();

    let (client_key, server_keys) = generate_keys(config);

    let clear_xs = [4294967281u32, 64646];
    let clear_ys = [99848u32, u32::MAX];

    let xs = clear_xs
        .iter()
        .copied()
        .map(|value| FheUint32::try_encrypt(value, &client_key))
        .collect::<Result<Vec<_>, _>>()
        .unwrap();

    let ys = clear_ys
        .iter()
        .copied()
        .map(|value| FheUint32::try_encrypt(value, &client_key))
        .collect::<Result<Vec<_>, _>>()
        .unwrap();

    rayon::broadcast(|_| {
        set_server_key(server_keys.clone());
    });

    let results = xs
        .par_iter()
        .zip(ys.par_iter())
        .map(|(x, y)| x * y)
        .collect::<Vec<_>>();

    for (i, result) in results.iter().enumerate() {
        let expected = clear_xs[i] * clear_ys[i];
        let decrypted: u32 = result.decrypt(&client_key);

        assert_eq!(decrypted, expected);
    }
}
