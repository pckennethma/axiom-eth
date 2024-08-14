use std::str::FromStr;

use axiom_eth::{
    halo2_base::{
        gates::RangeChip,
        halo2_proofs::halo2curves::bn256::{Fq2, G1Affine, G2Affine},
        utils::{testing::base_test, BigPrimeField},
        Context,
    },
    zkevm_hashes::util::eth_types::ToLittleEndian,
};
use ethers_core::types::U256;
use halo2_ecc::{
    bn254::{pairing::PairingChip, Fp2Chip, FpChip},
    ecc::EccChip,
};
use itertools::Itertools;
use num_bigint::{self, BigUint};

use super::{
    types::{Proof, VerifyingKey},
    verify_proof,
};

pub fn string_to_g1(s: String) -> [u64; 4] {
    let mut arr = [0; 4];
    let mut big_int = BigUint::from_str(&s).unwrap();
    let modulus: u128 = 1 << 64;
    for item in &mut arr {
        *item = (big_int.clone() % modulus).try_into().unwrap();
        big_int -= *item;
        big_int /= modulus;
    }
    arr
}

pub fn string_to_g2(s: String, r: String) -> ([u64; 4], [u64; 4]) {
    (string_to_g1(s), string_to_g1(r))
}

pub fn vec_to_g1(s: [String; 3]) -> G1Affine {
    let s = s.into_iter().map(string_to_g1).collect_vec();
    G1Affine {
        x: s[0].into(),
        y: s[1].into(),
    }
}

pub fn vec_to_g2(s: [[String; 2]; 3]) -> G2Affine {
    let s = s
        .into_iter()
        .map(|s| string_to_g2(s[0].clone(), s[1].clone()))
        .collect_vec();
    G2Affine {
        x: Fq2 {
            c0: s[0].0.into(),
            c1: s[0].1.into(),
        },
        y: Fq2 {
            c0: s[1].0.into(),
            c1: s[1].1.into(),
        },
    }
}

pub fn read_input(path: String, path2: String, path3: String) -> (VerifyingKey, Proof, Vec<U256>) {
    let pf_str = std::fs::read_to_string(path).unwrap();
    let pf: serde_json::Value = serde_json::from_str(pf_str.as_str()).unwrap();
    let vk_alpha_1: [String; 3] = serde_json::from_value(pf["vk_alpha_1"].clone()).unwrap();
    let vk_beta_2: [[String; 2]; 3] = serde_json::from_value(pf["vk_beta_2"].clone()).unwrap();
    let vk_gamma_2: [[String; 2]; 3] = serde_json::from_value(pf["vk_gamma_2"].clone()).unwrap();
    let vk_delta_2: [[String; 2]; 3] = serde_json::from_value(pf["vk_delta_2"].clone()).unwrap();
    let alpha_g1 = vec_to_g1(vk_alpha_1);
    let beta_g2 = vec_to_g2(vk_beta_2);
    let gamma_g2 = vec_to_g2(vk_gamma_2);
    let delta_g2 = vec_to_g2(vk_delta_2);
    let ic: Vec<[String; 3]> = serde_json::from_value(pf["IC"].clone()).unwrap();
    let gamma_abc_g1 = ic.into_iter().map(|s| vec_to_g1(s.clone())).collect_vec();
    let vk = VerifyingKey {
        alpha_g1,
        beta_g2,
        gamma_g2,
        delta_g2,
        gamma_abc_g1,
    };
    let pf_str = std::fs::read_to_string(path2).unwrap();
    let pf: serde_json::Value = serde_json::from_str(pf_str.as_str()).unwrap();
    let a: [String; 3] = serde_json::from_value(pf["pi_a"].clone()).unwrap();
    let b: [[String; 2]; 3] = serde_json::from_value(pf["pi_b"].clone()).unwrap();
    let c: [String; 3] = serde_json::from_value(pf["pi_c"].clone()).unwrap();
    let a = vec_to_g1(a);
    let b = vec_to_g2(b);
    let c = vec_to_g1(c);
    let proof = Proof { a, b, c };
    let pf_str = std::fs::read_to_string(path3).unwrap();
    let pf: serde_json::Value = serde_json::from_str(pf_str.as_str()).unwrap();
    let pi: Vec<String> = serde_json::from_value(pf.clone()).unwrap();
    let pi = pi
        .into_iter()
        .map(|p| U256::from_str(p.as_str()).unwrap())
        .collect_vec();
    (vk, proof, pi)
}

#[test]
pub fn read_puzzle_input() {
    read_input(
        "src/groth16/verifier/test_data/puzzle.json".to_string(),
        "src/groth16/verifier/test_data/proof.json".to_string(),
        "src/groth16/verifier/test_data/public_inputs.json".to_string(),
    );
}

#[allow(clippy::too_many_arguments)]
fn basic_g1_tests<F: BigPrimeField>(
    ctx: &mut Context<F>,
    range: &RangeChip<F>,
    limb_bits: usize,
    num_limbs: usize,
    vk: VerifyingKey,
    proof: Proof,
    public_inputs: Vec<U256>,
    max_len: usize,
) {
    let fp_chip = FpChip::<F>::new(range, limb_bits, num_limbs);
    let fp2_chip = Fp2Chip::<F>::new(&fp_chip);
    let g1_chip = EccChip::new(&fp_chip);
    let g2_chip = EccChip::new(&fp2_chip);
    let pairing_chip = PairingChip::new(&fp_chip);
    let p = proof.assign(ctx, &g1_chip, &g2_chip);
    let vk = vk.assign(ctx, &g1_chip, &g2_chip, max_len + 1);
    let mut public_inputs = public_inputs
        .into_iter()
        .map(|p| ctx.load_witness(F::from_bytes_le(&p.to_le_bytes())))
        .collect_vec();
    let zero = ctx.load_witness(F::from(0));
    public_inputs.resize(max_len, zero);
    verify_proof(
        ctx,
        range,
        &pairing_chip,
        &g1_chip,
        &g2_chip,
        &vk,
        &p,
        &public_inputs,
    );
}

#[test]
fn test_puzzle() {
    base_test().k(20).lookup_bits(19).run(|ctx, range| {
        let (vk, proof, public_inputs) = read_input(
            "src/groth16/verifier/test_data/puzzle.json".to_string(),
            "src/groth16/verifier/test_data/proof.json".to_string(),
            "src/groth16/verifier/test_data/public_inputs.json".to_string(),
        );
        basic_g1_tests(ctx, range, 88, 3, vk, proof, public_inputs, 20);
    });
}

#[test]
fn test_default() {
    base_test().k(20).lookup_bits(19).run(|ctx, range| {
        let (vk, proof, public_inputs) = read_input(
            "src/groth16/verifier/test_data/default.json".to_string(),
            "src/groth16/verifier/test_data/default_proof.json".to_string(),
            "src/groth16/verifier/test_data/default_public_inputs.json".to_string(),
        );
        basic_g1_tests(ctx, range, 88, 3, vk, proof, public_inputs, 20);
    });
}
