use rayon::prelude::*;
use tfhe::prelude::*;
use std::time::{Instant};
use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint32};

fn main() {
    let config = ConfigBuilder::all_disabled()
        .enable_default_integers()
        .build();

    let (client_key, server_keys) = generate_keys(config);

    let clear_xs = [4294967281u32, 64646 , 4294967281u32, 64646, 4294967281u32, 64646, 4294967281u32, 64646, 4294967281u32, 64646, 4294967281u32, 64646, 4294967281u32, 64646, 4294967281u32, 64646];
    let clear_ys = [99848u32, u32::MAX ,99848u32, u32::MAX,99848u32, u32::MAX,99848u32, u32::MAX,99848u32, u32::MAX,99848u32, u32::MAX,99848u32, u32::MAX,99848u32, u32::MAX];

    // let clear_xs = vec![17,-24,-22,4,26,-2,-24,17,-12,-16,-17,19,-26,1,20,22,-22,15,-12,1,9,-26,8,17,24,-23,-4,15,-27,-21,-27,-10,-19,-27,-15,8,-19,-27,4,-4,-29,-12,-1,-3,-5,6,-25,5,-9,-12,-12,-21,11,21,-19,20,14,-14,27,13,22,-5,-31,-7,11,-12,-26,-29,17,-30,7,-27,15,1,19,14,0,-10,17,-21,-28,-24,-15,-21,23,22,15,23,0,13,19,15,-12,-15,0,-32,29,2,16,8,-22,-6,14,-27,28,-5,5,15,-28,13,-2,-27,17,-27,7,-6,-21,-13,-7,16,28,-15,12,22,0,-22,-6,7];
    // let clear_ys =vec![16,20,-24,-24,10,-20,2,13,2,13,-24,5,5,21,26,-13,-15,27,9,-14,4,-10,22,-2,-29,-3,-29,-27,-10,-5,5,29,-17,-22,22,-5,16,-31,2,-19,-17,19,24,8,-32,-12,-18,-30,-26,17,-30,10,-18,20,30,-32,-11,-9,10,-29,19,15,0,-15,3,-6,5,-2,8,6,-6,-21,7,17,-30,20,9,-22,-15,19,-24,-7,9,-20,-31,-8,-32,-24,-13,-10,0,13,5,-17,-19,-18,-31,-27,-14,19,-21,-24,-26,7,9,5,-17,-10,0,19,17,-6,20,10,5,-14,-26,25,-8,-19,-17,-17,-1,-28,-22,16,7,20];
    
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

    // 记录开始时间
    let start_time = Instant::now();
    rayon::broadcast(|_| {
        set_server_key(server_keys.clone());
    });

    let results = xs
        .par_iter()
        .zip(ys.par_iter())
        .map(|(x, y)| x * y)
        .collect::<Vec<_>>();

        // 记录结束时间
    let end_time = Instant::now();

    // 计算时间间隔
    let elapsed_time = end_time - start_time;

    // 输出时间间隔
    println!("代码运行时间：{:?}", elapsed_time);
        
    for (i, result) in results.iter().enumerate() {
        let expected = clear_xs[i] * clear_ys[i];
        let decrypted: u32 = result.decrypt(&client_key);

        assert_eq!(decrypted, expected);
    }

}
