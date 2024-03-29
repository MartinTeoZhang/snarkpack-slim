// 导入Bls12_381曲线和Fr字段，用于构造zk-SNARK
use ark_bls12_381::{Bls12_381, Fr};
// 导入Field trait中的One方法，用于获取Fr字段的单位元
use ark_ff::One;
// 导入Groth16 zk-SNARK构造函数和验证键准备函数
use ark_groth16::{prepare_verifying_key, Groth16, PreparedVerifyingKey};
// 导入snarkpack库，用于聚合证明
use snarkpack;
use snarkpack::proof::AggregateProof;
// 导入Transcript trait，用于聚合证明过程中的信息记录
use snarkpack::transcript::Transcript;

// 引入自定义约束模块
mod constraints;
// 使用constraints模块中的Benchmark结构
use crate::constraints::Benchmark;
// 导入随机数生成库
use rand_core::SeedableRng;

// 导入std::time::Instant，用于记录程序运行时间
use std::time::Instant;

// 输出文件
use std::fs::File;
use std::io::prelude::*; // 引入Write trait使得.write_all()方法可用
use std::io::{self, Write};
// 序列化和反序列化
use std::io::BufWriter;
use ark_serialize::{CanonicalSerialize, CanonicalDeserialize};

// 定义一个测试函数来演示Groth16证明聚合
#[test]
fn groth16_aggregation() {
    // 定义约束系统的大小和证明数量
    let num_constraints = 1098; // 约束系统的大小，即将被证明的语句的复杂度
    let nproofs = 8; // 将要生成和聚合的证明数量
    
    // 初始化随机数生成器
    let mut rng = rand_chacha::ChaChaRng::seed_from_u64(1u64); // 使用固定种子初始化随机数生成器，以确保结果的可重复性
    
    // 生成Groth16的参数
    let params = {
        let c = Benchmark::<Fr>::new(num_constraints); // 创建一个新的Benchmark约束系统实例
        Groth16::<Bls12_381>::generate_random_parameters_with_reduction(c, &mut rng).unwrap() // 使用Groth16算法和随机数生成器生成zk-SNARK参数
    };
    
    // 准备验证密钥
    let pvk = prepare_verifying_key(&params.vk); // 使用生成的参数中的验证密钥（vk）准备一个用于验证的密钥（pvk）
    
    // 准备snarkpack所需的SRS（Structured Reference String），并根据证明数量进行专门化
    let srs = snarkpack::srs::setup_fake_srs::<Bls12_381, _>(&mut rng, nproofs); // 使用随机数生成器和证明数量生成一个SRS
    let (prover_srs, ver_srs) = srs.specialize(nproofs); // 根据证明数量将SRS分为用于证明者（prover）和验证者（verifier）的部分
    
    // 创建所有证明
    let proofs = (0..nproofs)
        .map(|_| {
            let c = Benchmark::new(num_constraints); // 对于每个证明，创建一个新的Benchmark约束系统实例
            Groth16::<Bls12_381>::create_random_proof_with_reduction(c, &params, &mut rng) // 使用Groth16算法生成一个证明
                .expect("proof creation failed")
        })
        .collect::<Vec<_>>(); // 收集生成的证明到一个向量中


    // 验证至少能验证一个证明
    let inputs: Vec<_> = [Fr::one(); 2].to_vec(); // 创建一个包含两个单位元的输入向量，用于证明验证
    let all_inputs = (0..nproofs).map(|_| inputs.clone()).collect::<Vec<_>>(); // 为每个证明复制这个输入向量

    // 假设`proofs[1]`是你想要计算大小的证明
    let proof = &proofs[1];
    let proof_str = format!("{:?}",  proof);
    let bytes = proof_str.len(); // 计算字节长度
    println!("单个证明的字节数: {}", bytes);  

    // // 开始计时
    // let start = Instant::now();

    let r = Groth16::<Bls12_381>::verify_proof(&pvk, &proofs[1], &inputs).unwrap(); // 验证第二个证明（索引为1）是否有效
    assert!(r); // 断言验证结果为true

    // // 结束计时
    // let duration = start.elapsed();
    // // 输出消耗的时间
    // println!("约束规模:{:?}单个证明验证耗时: {:?}",num_constraints, duration);


    // 使用Merlin来创建prover的transcript，用于记录聚合证明过程中的信息
    let mut prover_transcript = snarkpack::transcript::new_merlin_transcript(b"test aggregation");
    prover_transcript.append(b"public-inputs", &all_inputs);

    // // 开始计时
    // let start = Instant::now();
    // 聚合证明
    let aggregate_proof = snarkpack::aggregate_proofs(&prover_srs, &mut prover_transcript, &proofs)
        .expect("error in aggregation");

    // // 结束计时
    // let duration = start.elapsed();
    // // 输出消耗的时间
    // println!("聚合证明生成耗时: {:?}", duration);

    // 创建verifier的transcript
    let mut ver_transcript = snarkpack::transcript::new_merlin_transcript(b"test aggregation");
    ver_transcript.append(b"public-inputs", &all_inputs);


    // 假设`proofs[1]`是你想要计算大小的证明
    let proof_str = format!("{:?}", aggregate_proof);
    let bytes = proof_str.len(); // 计算字节长度
    println!("聚合证明的字节数: {}", bytes);  

    // let mut file = File::create("agg_proof_output.txt").expect("Cannot create file");
    // file.write_all(proof_str.as_bytes()).expect("Cannot write to file");

    // let all_inputs_str = format!("{:?}", all_inputs);
    // let mut file = File::create("all_input_output.txt").expect("Cannot create file");
    // file.write_all(all_inputs_str.as_bytes()).expect("Cannot write to file");

    // let pvk_str = format!("{:?}", pvk);
    // let mut file = File::create("pvk_output.txt").expect("Cannot create file");
    // file.write_all(pvk_str.as_bytes()).expect("Cannot write to file");

    // let ver_srs_str = format!("{:?}", ver_srs);
    // let mut file = File::create("ver_srs_output.txt").expect("Cannot create file");
    // file.write_all(ver_srs_str.as_bytes()).expect("Cannot write to file");
    
    // 序列化聚合证明 修改可见性，在src/lib.rs加上pub mod proof;
    let mut compressed_bytes = Vec::new();
    aggregate_proof.serialize_compressed(&mut compressed_bytes).unwrap();
    
    write_to_file("agg_proof_output.txt", compressed_bytes.as_slice()).expect("写入失败");

    let mut file = File::open("agg_proof_output.txt").expect("无法打开文件");
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer).expect("读取失败");

    let a_uncompressed: snarkpack::proof::AggregateProof<Bls12_381> = snarkpack::proof::AggregateProof::deserialize_compressed(&*buffer).unwrap();
    
    assert_eq!(aggregate_proof, a_uncompressed);
    let aggregate_proof = a_uncompressed;

    // 序列化pvk
    let mut compressed_bytes = Vec::new();
    pvk.serialize_compressed(&mut compressed_bytes).unwrap();
    write_to_file("pvk_output.txt", compressed_bytes.as_slice()).expect("写入失败");

    let mut file = File::open("pvk_output.txt").expect("无法打开文件");
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer).expect("读取失败");

    let a_uncompressed: PreparedVerifyingKey<Bls12_381> = PreparedVerifyingKey::deserialize_compressed(&*buffer).unwrap();
    assert_eq!(pvk, a_uncompressed);
    let pvk = a_uncompressed;

    
    // 序列化ver_srs 修改src/srs.rs中的VerifierSRS结构体的serialize_compressed和deserialize_compressed
    let mut compressed_bytes = Vec::new();
    ver_srs.serialize_compressed(&mut compressed_bytes).unwrap();
    write_to_file("ver_srs_output.txt", compressed_bytes.as_slice()).expect("写入失败");

    let mut file = File::open("ver_srs_output.txt").expect("无法打开文件");
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer).expect("读取失败");

    let a_uncompressed: snarkpack::srs::VerifierSRS<Bls12_381> = snarkpack::srs::VerifierSRS::deserialize_compressed(&*buffer).unwrap();
    assert_eq!(ver_srs, a_uncompressed);
    let ver_srs = a_uncompressed;


    // ver_transcript 可以在合约上再生成

    // all_inputs 考虑先在合约上生成（因为不同的ZKP可能存在特殊性）


    // // 开始计时
    // let start = Instant::now();
    // 验证聚合证明
    snarkpack::verify_aggregate_proof(
        &ver_srs,
        &pvk,
        &all_inputs,
        &aggregate_proof,
        &mut rng,
        &mut ver_transcript,
    )
    .expect("error in verification");
    // // 结束计时
    // let duration = start.elapsed();
    // // 输出消耗的时间
    // println!("证明数量:{:?}聚合证明验证耗时: {:?}",nproofs, duration);

}

// 这个函数尝试创建一个文件并写入内容，如果成功则返回Ok(())，如果失败则返回错误
fn write_to_file(filename: &str, content: &[u8]) -> Result<(), io::Error> {
    let mut file = File::create(filename)?;
    file.write_all(content)?;
    Ok(())
}
