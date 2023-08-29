use rayon::prelude::*;
use tfhe::prelude::*;
use std::time::{Instant};
use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint16};

fn main() {
    let config = ConfigBuilder::all_disabled()
        .enable_default_integers()
        .build();

    let (client_key, server_keys) = generate_keys(config);

    let clear_xs = [1u16,2u16,3u16,4u16,5u16,6u16,1u16,2u16,3u16,4u16,5u16,6u16,1u16,2u16,3u16,4u16,5u16,6u16,1u16,2u16,3u16,4u16,5u16,6u16,1u16,2u16,3u16,4u16,5u16,6u16,1u16,2u16,3u16,4u16,5u16,6u16,1u16,2u16,3u16,4u16,5u16,6u16,1u16,2u16,3u16,4u16,5u16,6u16,1u16,2u16,3u16,4u16,5u16,6u16,1u16,2u16,3u16,4u16,5u16,6u16,1u16,2u16,3u16,4u16,5u16,6u16,1u16,2u16,3u16,4u16,5u16,6u16,1u16,2u16,3u16,4u16,5u16,6u16,1u16,2u16,3u16,4u16,5u16,6u16,1u16,2u16,3u16,4u16,5u16,6u16,1u16,2u16,3u16,4u16,5u16,6u16,1u16,2u16,3u16,4u16,5u16,6u16];
    let clear_ys = [6u16,5u16,4u16,3u16,2u16,1u16,1u16,2u16,3u16,4u16,5u16,6u16,1u16,2u16,3u16,4u16,5u16,6u16,1u16,2u16,3u16,4u16,5u16,6u16,1u16,2u16,3u16,4u16,5u16,6u16,1u16,2u16,3u16,4u16,5u16,6u16,1u16,2u16,3u16,4u16,5u16,6u16,1u16,2u16,3u16,4u16,5u16,6u16,1u16,2u16,3u16,4u16,5u16,6u16,1u16,2u16,3u16,4u16,5u16,6u16,1u16,2u16,3u16,4u16,5u16,6u16,1u16,2u16,3u16,4u16,5u16,6u16,1u16,2u16,3u16,4u16,5u16,6u16,1u16,2u16,3u16,4u16,5u16,6u16,1u16,2u16,3u16,4u16,5u16,6u16,1u16,2u16,3u16,4u16,5u16,6u16,1u16,2u16,3u16,4u16,5u16,6u16];
    
    let xs = clear_xs
        .iter()
        .copied()
        .map(|value| FheUint16::try_encrypt(value, &client_key))
        .collect::<Result<Vec<_>, _>>()
        .unwrap();

    let ys = clear_ys
        .iter()
        .copied()
        .map(|value| FheUint16::try_encrypt(value, &client_key))
        .collect::<Result<Vec<_>, _>>()
        .unwrap();

    // start time
    let start_time = Instant::now();
    rayon::broadcast(|_| {
        set_server_key(server_keys.clone());
    });

    let results = xs
        .par_iter()
        .zip(ys.par_iter())
        .map(|(x, y)| x * y)
        .collect::<Vec<_>>();

    let end_time = Instant::now();
    let elapsed_time = end_time - start_time;
    println!("time：{:?}", elapsed_time);
        
    for (i, result) in results.iter().enumerate() {
        let expected = clear_xs[i] * clear_ys[i];
        let decrypted: u16 = result.decrypt(&client_key);

        assert_eq!(decrypted, expected);
    }

}
