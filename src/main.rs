use rayon::prelude::*;
use tfhe::prelude::*;
use std::time::{Instant};
use std::sync::mpsc::{channel, RecvError};
use rayon::ThreadPool;
// use threadpool::ThreadPool;
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

    // rayon::broadcast(|_| {
    //     set_server_key(server_keys.clone());
    // });
    // let start_time = Instant::now();
    // let results = xs
    //     .par_iter()
    //     .zip(ys.par_iter())
    //     .map(|(x, y)| x * y)
    //     .collect::<Vec<_>>();

    let start_time = Instant::now();
    let pool = rayon::ThreadPoolBuilder::new().num_threads(64).build().unwrap();
    let (tx, rx) = channel();
    let count = xs.len();
    let mut results :Vec<FheUint16> = vec![];
    for i in 0..count {
        let tx = tx.clone();
        let a = xs[i].clone();
        let b = ys[i].clone();
        let s = server_keys.clone();
        pool.install(move || {
            set_server_key(s);
            let res = a * b;
            tx.send(res).expect("Could not send data!");
        });
    }

    for _ in 0..count {
        let res = rx.recv().unwrap();
        results.push(res);
    }

    // set_server_key(server_keys.clone());
    // let start_time = Instant::now();
    // let mut results :Vec<FheUint16> = vec![];
    // for i in 0..xs.len() {
    //     results.push(xs[i].clone() * ys[i.clone()].clone() );
    // }


    let end_time = Instant::now();
    let elapsed_time = end_time - start_time;
    println!("time：{:?}", elapsed_time);
        
    for (i, result) in results.iter().enumerate() {
        let expected = clear_xs[i] * clear_ys[i];
        let decrypted: u16 = result.decrypt(&client_key);

        assert_eq!(decrypted, expected);
    }

}
