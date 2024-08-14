use std::str::FromStr;

use axiom_eth::{
    halo2_proofs::halo2curves::bn256::Fr,
    snark_verifier::util::arithmetic::fe_from_big,
    utils::{component::utils::compute_poseidon, hilo::HiLo},
    Field,
};
use itertools::Itertools;
use lazy_static::lazy_static;
use num_bigint::BigUint;

use super::{
    get_groth16_consts_from_max_pi, Groth16VerifierComponentInput, Groth16VerifierComponentOutput,
    Groth16VerifierComponentParams, Groth16VerifierComponentProof,
    Groth16VerifierComponentVerificationKey, Groth16VerifierInput,
};
use crate::groth16::{
    native::verify_groth16, vec_to_hilo_pair, vec_to_hilo_point, HiLoPair, HiLoPoint,
    NUM_FE_PER_CHUNK, NUM_FE_PROOF,
};

macro_rules! deserialize_key {
    ($json: expr, $val: expr) => {
        serde_json::from_value($json[$val].clone()).unwrap()
    };
}
use crate::utils::flatten::InputFlatten;

const DEFAULT_JSON: &str = include_str!("./test_data/default.json");
const DEFAULT_PROOF_JSON: &str = include_str!("./test_data/default_proof.json");
const DEFAULT_PUBLIC_INPUTS_JSON: &str = include_str!("./test_data/default_public_inputs.json");

pub fn flatten_groth16_input<F: Field>(input: Groth16VerifierInput<F>, max_pi: usize) -> Vec<F> {
    let constants = get_groth16_consts_from_max_pi(max_pi);
    let res = verify_groth16(input.clone(), constants.max_pi);
    let flattened_vkey = input.vk.flatten();
    assert_eq!(constants.num_fe_hilo_vkey, flattened_vkey.len());
    let num_public_inputs = input.num_public_inputs.to_bytes_le()[0];
    let packed_vkey = bytepack(flattened_vkey, Some(vec![num_public_inputs]));
    assert_eq!(packed_vkey.len(), constants.num_fe_vkey);

    let flattened_proof = input.proof.flatten_vec();
    assert_eq!(4 + 8 + 4, flattened_proof.len());
    let packed_proof = bytepack(flattened_proof, None);
    assert_eq!(packed_proof.len(), NUM_FE_PROOF);

    let mut packed_fe = packed_vkey;
    packed_fe.extend(packed_proof);
    assert_eq!(packed_fe.len(), constants.num_fe_per_input_without_pi);
    packed_fe.extend(input.public_inputs);
    assert_eq!(packed_fe.len(), constants.num_fe_per_input);
    packed_fe.resize_with(constants.max_num_fe_per_input_no_hash, || F::ZERO);
    let hash = compute_poseidon(&packed_fe);
    packed_fe.push(hash);
    let packed_fe_with_res = packed_fe
        .chunks(NUM_FE_PER_CHUNK)
        .collect::<Vec<_>>()
        .iter()
        .enumerate()
        .flat_map(|(idx, x)| {
            let mut bytes = x.to_vec();
            let mut arr: [u8; 32] = [0; 32];
            if idx == constants.num_chunks - 1 {
                arr[31] = res as u8;
                bytes[0] += F::from_bytes_le(&arr);
            } else {
                arr[31] = 2;
                bytes[0] += F::from_bytes_le(&arr);
            }
            bytes
        })
        .collect::<Vec<_>>();
    packed_fe_with_res
}

fn bytepack<F: Field>(input: Vec<F>, bytes_to_add: Option<Vec<u8>>) -> Vec<F> {
    let mut bytes: Vec<u8> = input
        .iter()
        .flat_map(|x| {
            // decompose(x, 16, 8)
            x.to_bytes_le()[..16].to_vec()
        })
        .collect::<Vec<_>>();
    if let Some(bytes_to_add) = bytes_to_add {
        bytes.extend(bytes_to_add);
    }
    bytes
        .chunks(31)
        .collect::<Vec<_>>()
        .iter()
        .map(|x| F::from_bytes_le(x))
        .collect::<Vec<_>>()
}

pub fn default_groth16_input(max_pi: usize) -> Groth16VerifierInput<Fr> {
    parse_input(
        DEFAULT_JSON.to_string(),
        DEFAULT_PROOF_JSON.to_string(),
        DEFAULT_PUBLIC_INPUTS_JSON.to_string(),
        max_pi,
    )
}

pub fn default_groth16_subquery_input(max_pi: usize) -> Vec<Groth16VerifierComponentInput<Fr>> {
    let input = default_groth16_input(max_pi);
    let raw_chunks = flatten_groth16_input(input, max_pi);
    raw_chunks
        .chunks(NUM_FE_PER_CHUNK)
        .map(|x| Groth16VerifierComponentInput {
            packed_bytes: x.to_vec().into(),
        })
        .collect_vec()
}

pub fn read_and_parse_input(
    vk_path: String,
    pf_path: String,
    pub_path: String,
    max_pi: usize,
) -> Groth16VerifierInput<Fr> {
    let vk_string = std::fs::read_to_string(vk_path).unwrap();
    let pf_string = std::fs::read_to_string(pf_path).unwrap();
    let pub_string = std::fs::read_to_string(pub_path).unwrap();
    parse_input(vk_string, pf_string, pub_string, max_pi)
}

pub fn parse_input(
    vk_string: String,
    pf_string: String,
    pub_string: String,
    max_pi: usize,
) -> Groth16VerifierInput<Fr> {
    let input_constants = get_groth16_consts_from_max_pi(max_pi);
    let verification_key_file: serde_json::Value =
        serde_json::from_str(vk_string.as_str()).unwrap();

    let vk_alpha_1: [String; 3] = deserialize_key!(verification_key_file, "vk_alpha_1");
    let vk_beta_2: [[String; 2]; 3] = deserialize_key!(verification_key_file, "vk_beta_2");
    let vk_gamma_2: [[String; 2]; 3] = deserialize_key!(verification_key_file, "vk_gamma_2");
    let vk_delta_2: [[String; 2]; 3] = deserialize_key!(verification_key_file, "vk_delta_2");

    let alpha_g1: HiLoPoint<Fr> = vec_to_hilo_point(&vk_alpha_1);
    let beta_g2: HiLoPair<Fr> = vec_to_hilo_pair(&vk_beta_2);
    let gamma_g2: HiLoPair<Fr> = vec_to_hilo_pair(&vk_gamma_2);
    let delta_g2: HiLoPair<Fr> = vec_to_hilo_pair(&vk_delta_2);

    let ic: Vec<[String; 3]> = deserialize_key!(verification_key_file, "IC");
    let mut ic_vec: Vec<HiLoPoint<Fr>> =
        ic.into_iter().map(|s| vec_to_hilo_point(&s)).collect_vec();
    ic_vec.resize(
        input_constants.gamma_abc_g1_len,
        (HiLo::default(), HiLo::default()),
    );

    let vk = Groth16VerifierComponentVerificationKey {
        alpha_g1,
        beta_g2,
        gamma_g2,
        delta_g2,
        gamma_abc_g1: ic_vec,
    };

    let proof_file: serde_json::Value = serde_json::from_str(pf_string.as_str()).unwrap();

    // get proof
    let a: [String; 3] = deserialize_key!(proof_file, "pi_a");
    let b: [[String; 2]; 3] = deserialize_key!(proof_file, "pi_b");
    let c: [String; 3] = deserialize_key!(proof_file, "pi_c");

    let a: HiLoPoint<Fr> = vec_to_hilo_point(&a);
    let b: HiLoPair<Fr> = vec_to_hilo_pair(&b);
    let c: HiLoPoint<Fr> = vec_to_hilo_point(&c);

    let pf = Groth16VerifierComponentProof { a, b, c };

    // get public inputs
    let public_file: serde_json::Value = serde_json::from_str(pub_string.as_str()).unwrap();
    let pi: Vec<String> = serde_json::from_value(public_file.clone()).unwrap();
    let len = pi.len();
    let mut pi = pi
        .into_iter()
        .map(|p| fe_from_big(BigUint::from_str(&p).unwrap()))
        .collect_vec();
    pi.resize(input_constants.max_pi, Fr::from(0));

    Groth16VerifierInput {
        vk,
        proof: pf,
        public_inputs: pi,
        num_public_inputs: Fr::from(len as u64 + 1),
    }
}

pub fn get_groth16_output(val: u64) -> Groth16VerifierComponentOutput<Fr> {
    Groth16VerifierComponentOutput {
        success: HiLo::from_hi_lo([Fr::zero(), Fr::from(val)]),
    }
}

lazy_static! {
    static ref GROTH16VERIFY_PARAMS: Groth16VerifierComponentParams =
        Groth16VerifierComponentParams {
            capacity: 3,
            limb_bits: 88,
            num_limbs: 3,
            max_public_inputs: 4,
        };
}

lazy_static! {
    static ref GROTH16VERIFY_PARAMS_CAP2: Groth16VerifierComponentParams =
        Groth16VerifierComponentParams {
            capacity: 6,
            limb_bits: 88,
            num_limbs: 3,
            max_public_inputs: 4,
        };
}

#[cfg(test)]
mod tests {
    use axiom_eth::utils::build_utils::dummy::DummyFrom;

    use super::*;
    use crate::{
        groth16::{native::verify_groth16, unflatten_groth16_input, Groth16VerifierComponent},
        utils::testing::basic_component_outputs_test,
    };
    #[test]
    fn test_groth16_output() {
        let params = GROTH16VERIFY_PARAMS.clone();
        let input = read_and_parse_input(
            "src/groth16/test_data/default.json".to_string(),
            "src/groth16/test_data/default_proof.json".to_string(),
            "src/groth16/test_data/default_public_inputs.json".to_string(),
            params.max_public_inputs,
        );
        let raw_chunks = flatten_groth16_input(input, params.max_public_inputs);
        let chunks = raw_chunks
            .chunks(NUM_FE_PER_CHUNK)
            .map(|x| Groth16VerifierComponentInput {
                packed_bytes: x.to_vec().into(),
            })
            .collect_vec();
        basic_component_outputs_test::<Groth16VerifierComponent<Fr>>(
            20,
            chunks,
            vec![
                get_groth16_output(2),
                get_groth16_output(2),
                get_groth16_output(1),
            ],
            GROTH16VERIFY_PARAMS.clone(),
        );
    }

    #[test]
    fn test_groth16_output_wrong_signature() {
        let params = GROTH16VERIFY_PARAMS.clone();
        let input = read_and_parse_input(
            "src/groth16/test_data/default.json".to_string(),
            "src/groth16/test_data/default_proof.json".to_string(),
            "src/groth16/test_data/default_public_inputs_modified.json".to_string(),
            params.max_public_inputs,
        );
        let raw_chunks = flatten_groth16_input(input, params.max_public_inputs);
        let chunks = raw_chunks
            .chunks(NUM_FE_PER_CHUNK)
            .map(|x| Groth16VerifierComponentInput {
                packed_bytes: x.to_vec().into(),
            })
            .collect_vec();
        basic_component_outputs_test::<Groth16VerifierComponent<Fr>>(
            20,
            chunks,
            vec![
                get_groth16_output(2),
                get_groth16_output(2),
                get_groth16_output(0),
            ],
            GROTH16VERIFY_PARAMS.clone(),
        );
    }

    #[test]
    fn test_groth16_output_more_pi() {
        let mut params = GROTH16VERIFY_PARAMS.clone();
        params.max_public_inputs = 15;
        let constants = get_groth16_consts_from_max_pi(params.max_public_inputs);
        params.capacity = constants.num_chunks;
        let mut outputs = vec![get_groth16_output(2); constants.num_chunks];
        outputs[constants.num_chunks - 1] = get_groth16_output(1);
        let input = read_and_parse_input(
            "src/groth16/test_data/puzzle.json".to_string(),
            "src/groth16/test_data/proof.json".to_string(),
            "src/groth16/test_data/public_inputs.json".to_string(),
            params.max_public_inputs,
        );
        let raw_chunks = flatten_groth16_input(input, params.max_public_inputs);
        let chunks = raw_chunks
            .chunks(NUM_FE_PER_CHUNK)
            .map(|x| Groth16VerifierComponentInput {
                packed_bytes: x.to_vec().into(),
            })
            .collect_vec();
        basic_component_outputs_test::<Groth16VerifierComponent<Fr>>(
            20,
            chunks,
            outputs,
            params.clone(),
        );
    }

    #[test]
    fn test_groth16_dummy_from_input() {
        let params = GROTH16VERIFY_PARAMS_CAP2.clone();
        let chunks = <Vec<Groth16VerifierComponentInput<Fr>> as DummyFrom<
            Groth16VerifierComponentParams,
        >>::dummy_from(params.clone());
        basic_component_outputs_test::<Groth16VerifierComponent<Fr>>(
            20,
            chunks,
            vec![
                get_groth16_output(2),
                get_groth16_output(2),
                get_groth16_output(1),
                get_groth16_output(2),
                get_groth16_output(2),
                get_groth16_output(1),
            ],
            params,
        );
    }

    #[test]
    #[should_panic]
    fn test_groth16_join_output_fail() {
        let input = Groth16VerifierComponentInput {
            packed_bytes: vec![Fr::from(0); NUM_FE_PER_CHUNK].into(),
        };
        basic_component_outputs_test::<Groth16VerifierComponent<Fr>>(
            20,
            vec![input; 3],
            vec![
                get_groth16_output(2),
                get_groth16_output(2),
                get_groth16_output(0),
            ],
            GROTH16VERIFY_PARAMS.clone(),
        );
    }

    #[test]
    fn test_native_verify() {
        let input = read_and_parse_input(
            "src/groth16/test_data/default.json".to_string(),
            "src/groth16/test_data/default_proof.json".to_string(),
            "src/groth16/test_data/default_public_inputs.json".to_string(),
            4,
        );
        let res = verify_groth16(input, 4);
        assert!(res);
    }

    #[test]
    fn test_flatten_unflatten() {
        let input = read_and_parse_input(
            "src/groth16/test_data/default.json".to_string(),
            "src/groth16/test_data/default_proof.json".to_string(),
            "src/groth16/test_data/default_public_inputs.json".to_string(),
            4,
        );
        let raw_chunks = flatten_groth16_input(input.clone(), 4);
        let unflattened = unflatten_groth16_input(raw_chunks, 4);
        assert_eq!(input, unflattened);
    }

    #[test]
    fn test_flatten_unflatten_more_pi() {
        let input = read_and_parse_input(
            "src/groth16/test_data/puzzle.json".to_string(),
            "src/groth16/test_data/proof.json".to_string(),
            "src/groth16/test_data/public_inputs.json".to_string(),
            15,
        );
        let raw_chunks = flatten_groth16_input(input.clone(), 15);
        let unflattened = unflatten_groth16_input(raw_chunks, 15);
        assert_eq!(input, unflattened);
    }
}
