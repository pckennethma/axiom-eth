use axiom_eth::{
    utils::{
        component::circuit::{CoreBuilderOutputParams, CoreBuilderParams},
        encode_h256_to_hilo,
        hilo::HiLo,
    },
    zkevm_hashes::util::eth_types::ToLittleEndian,
    Field,
};
use component_derive::ComponentIO;
use ethers_core::types::{BigEndianHash, H256};
use serde::{Deserialize, Serialize};

use super::{HiLoPair, HiLoPoint};
use crate::{
    ecdsa::utils::decode_hilo_to_h256,
    groth16::NUM_FE_PER_CHUNK,
    utils::flatten::{FixLenVec, InputFlatten},
};

#[derive(Default, Clone, Serialize, Deserialize)]
pub struct Groth16VerifierComponentParams {
    pub capacity: usize,
    pub limb_bits: usize,
    pub num_limbs: usize,
    pub max_public_inputs: usize,
}

impl CoreBuilderParams for Groth16VerifierComponentParams {
    fn get_output_params(&self) -> CoreBuilderOutputParams {
        CoreBuilderOutputParams::new(vec![self.capacity])
    }
}

#[derive(Default, Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Groth16VerifierComponentVerificationKey<T: Copy> {
    pub alpha_g1: HiLoPoint<T>,
    pub beta_g2: HiLoPair<T>,
    pub gamma_g2: HiLoPair<T>,
    pub delta_g2: HiLoPair<T>,
    pub gamma_abc_g1: Vec<HiLoPoint<T>>,
}

impl<T: Copy> Groth16VerifierComponentVerificationKey<T> {
    pub fn unflatten(vec: Vec<T>, gamma_abc_g1_len: usize) -> Self {
        let mut iter = vec.into_iter();
        let alpha_g1_fe: Vec<T> = iter
            .by_ref()
            .take(<HiLoPoint<T> as InputFlatten<T>>::NUM_FE)
            .collect();
        let alpha_g1 = HiLoPoint::unflatten(alpha_g1_fe).unwrap();

        let beta_g2_fe: Vec<T> = iter
            .by_ref()
            .take(<HiLoPair<T> as InputFlatten<T>>::NUM_FE)
            .collect();
        let beta_g2 = HiLoPair::unflatten(beta_g2_fe).unwrap();

        let gamma_g2_fe: Vec<T> = iter
            .by_ref()
            .take(<HiLoPair<T> as InputFlatten<T>>::NUM_FE)
            .collect();
        let gamma_g2 = HiLoPair::unflatten(gamma_g2_fe).unwrap();

        let delta_g2_fe: Vec<T> = iter
            .by_ref()
            .take(<HiLoPair<T> as InputFlatten<T>>::NUM_FE)
            .collect();
        let delta_g2 = HiLoPair::unflatten(delta_g2_fe).unwrap();

        let gamma_abc_g1: Vec<HiLoPoint<T>> = (0..gamma_abc_g1_len)
            .map(|_| {
                let fe: Vec<T> = iter
                    .by_ref()
                    .take(<HiLoPoint<T> as InputFlatten<T>>::NUM_FE)
                    .collect();
                HiLoPoint::unflatten(fe).unwrap()
            })
            .collect();

        Self {
            alpha_g1,
            beta_g2,
            gamma_g2,
            delta_g2,
            gamma_abc_g1,
        }
    }

    pub fn flatten(&self) -> Vec<T> {
        let mut vec: Vec<T> = Vec::new();
        let flattened_alpha_g1: Vec<T> = self.alpha_g1.flatten_vec();
        vec.extend(flattened_alpha_g1);
        let flattened_beta_g2: Vec<T> = self.beta_g2.flatten_vec();
        vec.extend(flattened_beta_g2);
        let flattened_gamma_g2: Vec<T> = self.gamma_g2.flatten_vec();
        vec.extend(flattened_gamma_g2);
        let flattened_delta_g2: Vec<T> = self.delta_g2.flatten_vec();
        vec.extend(flattened_delta_g2);
        for pt in &self.gamma_abc_g1 {
            let flattened_pt: Vec<T> = pt.flatten_vec();
            vec.extend(flattened_pt);
        }
        vec
    }
}

#[derive(Default, Clone, Debug, Serialize, Deserialize, PartialEq, Eq, ComponentIO)]
pub struct Groth16VerifierComponentProof<T: Copy> {
    pub a: HiLoPoint<T>,
    pub b: HiLoPair<T>,
    pub c: HiLoPoint<T>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Groth16VerifierInput<T: Copy> {
    pub vk: Groth16VerifierComponentVerificationKey<T>,
    pub proof: Groth16VerifierComponentProof<T>,
    pub num_public_inputs: T,
    pub public_inputs: Vec<T>, // MAX_PUBLIC_INPUTS
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, ComponentIO, Default)]
pub struct Groth16VerifierComponentInput<T: Copy> {
    pub packed_bytes: FixLenVec<T, NUM_FE_PER_CHUNK>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub struct Groth16NativeInput {
    pub bytes: Vec<H256>,
}

#[derive(Default, Clone, Debug, Serialize, Deserialize, PartialEq, Eq, ComponentIO)]
pub struct Groth16VerifierComponentOutput<T: Copy> {
    pub success: HiLo<T>,
}

impl<F: Field> From<Groth16NativeInput> for Groth16VerifierComponentInput<F> {
    fn from(input: Groth16NativeInput) -> Self {
        let bytes = input
            .bytes
            .iter()
            .map(|x| F::from_bytes_le(&x.into_uint().to_le_bytes()))
            .collect();
        Self {
            packed_bytes: FixLenVec::new(bytes).unwrap(),
        }
    }
}

impl<F: Field> From<Groth16VerifierComponentInput<F>> for Groth16NativeInput {
    fn from(input: Groth16VerifierComponentInput<F>) -> Self {
        let bytes = input
            .packed_bytes
            .vec
            .into_iter()
            .map(|x| {
                let mut bytes = x.to_repr();
                bytes.reverse();
                H256::from_slice(&bytes)
            })
            .collect();
        Self { bytes }
    }
}

impl<F: Field> From<Groth16VerifierComponentOutput<F>> for H256 {
    fn from(value: Groth16VerifierComponentOutput<F>) -> Self {
        decode_hilo_to_h256(value.success)
    }
}

impl<F: Field> From<H256> for Groth16VerifierComponentOutput<F> {
    fn from(value: H256) -> Self {
        Groth16VerifierComponentOutput {
            success: encode_h256_to_hilo(&value),
        }
    }
}
