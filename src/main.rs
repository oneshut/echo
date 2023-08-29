
use bincode::{self, Error};
// use iron::status::Status::Ok;

use std::io::Cursor;

use tfhe::prelude::*;
use tfhe::{ConfigBuilder, ServerKey, generate_keys, set_server_key, FheUint8, FheUint32, integer, CompressedFheUint32, CompressedServerKey, CompactFheUint32List};

use rayon::prelude::*;
use rayon::iter::ParallelIterator;



fn main() -> Result<(), Box<dyn std::error::Error>>{



    // 生成参数
    let config = ConfigBuilder::all_disabled()
        .enable_default_integers()
        .build();

    println!("begin generating key!");

    // 生成密钥
    let (client_key, server_key) = generate_keys(config);

    // 序列化serverkey
    let mut serialized_serverkey = Vec::new();
    bincode::serialize_into(&mut serialized_serverkey, &server_key)?;

    // 两个128的向量
    let vec1 = vec![17,-24,-22,4,26,-2,-24,17,-12,-16,-17,19,-26,1,20,22,-22,15,-12,1,9,-26,8,17,24,-23,-4,15,-27,-21,-27,-10,-19,-27,-15,8,-19,-27,4,-4,-29,-12,-1,-3,-5,6,-25,5,-9,-12,-12,-21,11,21,-19,20,14,-14,27,13,22,-5,-31,-7,11,-12,-26,-29,17,-30,7,-27,15,1,19,14,0,-10,17,-21,-28,-24,-15,-21,23,22,15,23,0,13,19,15,-12,-15,0,-32,29,2,16,8,-22,-6,14,-27,28,-5,5,15,-28,13,-2,-27,17,-27,7,-6,-21,-13,-7,16,28,-15,12,22,0,-22,-6,7];
    let vec2 = vec![16,20,-24,-24,10,-20,2,13,2,13,-24,5,5,21,26,-13,-15,27,9,-14,4,-10,22,-2,-29,-3,-29,-27,-10,-5,5,29,-17,-22,22,-5,16,-31,2,-19,-17,19,24,8,-32,-12,-18,-30,-26,17,-30,10,-18,20,30,-32,-11,-9,10,-29,19,15,0,-15,3,-6,5,-2,8,6,-6,-21,7,17,-30,20,9,-22,-15,19,-24,-7,9,-20,-31,-8,-32,-24,-13,-10,0,13,5,-17,-19,-18,-31,-27,-14,19,-21,-24,-26,7,9,5,-17,-10,0,19,17,-6,20,10,5,-14,-26,25,-8,-19,-17,-17,-1,-28,-22,16,7,20];


    let mut ciphertexts1 :Vec<Vec<u8>>= vec![];
    let mut ciphertexts2 :Vec<Vec<u8>>= vec![];


    let mut res_clear = 0;

    // 压缩密文，并且序列化
    for i in 0..128 {
        let  ct_1 = CompressedFheUint32::try_encrypt((vec1[i]) as u64, &client_key)?;
        let  ct_2 = CompressedFheUint32::try_encrypt((vec2[i]) as u64, &client_key)?;


        res_clear = res_clear + vec1[i]*vec2[i];
        let mut serialized_data = Vec::new();
        bincode::serialize_into(&mut serialized_data, &ct_1)?;
        ciphertexts1.push(serialized_data);

        let mut serialized_data_2 = Vec::new();
        bincode::serialize_into(&mut serialized_data_2, &ct_2)?;

        ciphertexts2.push(serialized_data_2);


    };







    let computed_result = server_function(ciphertexts1,ciphertexts2, &serialized_serverkey)?;



    let result:FheUint32 = bincode::deserialize(&computed_result)?;

    let result_clear:u64 = result.decrypt(&client_key);


    println!("expected {}, get {}", res_clear, result_clear);



    Ok(())

}




//测试函数，不用管
#[test]
fn test_mul() -> Result<(), Box<dyn std::error::Error>> {

    use tfhe::prelude::*;
    use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint32};


    let config = ConfigBuilder::all_disabled()
        .enable_default_integers()
        .build();

    println!("begin generating key!");
    let (client_key, server_keys) = generate_keys(config);
    set_server_key(server_keys);
    println!("end generating key!");



    let mut a = FheUint32::try_encrypt(4294967281 as u32, &client_key)?;
    let mut b = FheUint32::try_encrypt(30, &client_key)?;

    println!("begin mul");
    a = a * &b;
    println!("end evaluation!");



    Ok(())


}


// 接口函数，serialize_ciphers1：向量一密文序列化，serialize_ciphers2:向量二密文序列化，serialize_server_key：serverkey序列化。
fn server_function(serialize_ciphers1: Vec<Vec<u8>>, serialize_ciphers2: Vec<Vec<u8>>, serialize_server_key: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {

    // 对比向量1，2的长度
    assert_eq!(serialize_ciphers1.len(), serialize_ciphers2.len());


    // deserialize serverkey
    let mut serialized_data =  Cursor::new( serialize_server_key);



    // !!!!             如果从前端传过来的，就用这段代码 反序列化
    // let mut compressedserverkey: CompressedServerKey =  bincode::deserialize_from( &mut serialized_data)?;
    // let serverkey = ServerKey :: from(compressedserverkey);

    // !!!!             如果本地做测试，使用这段反序列化
    let serverkey :ServerKey = bincode::deserialize_from( &mut serialized_data)?;
    set_server_key(serverkey.clone());



    let mut ciphers1:Vec<FheUint32> = vec![];
    let mut ciphers2:Vec<FheUint32> = vec![];
    for i in 0..128{
        // 压缩密文反序列化
        let mut temp =  Cursor::new(&serialize_ciphers1[i] );
        let ct: CompressedFheUint32 =  bincode::deserialize_from( &mut temp)?;
        // 密文解压
        ciphers1.push(ct.decompress());

        let mut temp =  Cursor::new(&serialize_ciphers2[i] );
        let ct: CompressedFheUint32 =  bincode::deserialize_from( &mut temp)?;
        ciphers2.push(ct.decompress());


    };

    println!("ciphers lens {}", ciphers1.len());


    //并行计算乘法；
    rayon::broadcast(|_| {
        set_server_key(serverkey.clone());
    });

    let ciphersmul = ciphers1
        .par_iter()
        .zip(ciphers2.par_iter())
        .map(|(x, y)| x * y)
        .collect::<Vec<_>>();


    let mut result  = FheUint32::try_encrypt_trivial(0)?;
    for i in 0..ciphersmul.len() {
        result = result +  &ciphersmul[i];

    };

    // serialize result 注意，返回的密文没有压缩！
    let serialized_result = bincode::serialize(&result)?;


    Ok(serialized_result)

}


