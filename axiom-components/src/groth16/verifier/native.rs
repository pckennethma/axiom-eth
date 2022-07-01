use std::ops::{Add, Mul, Neg};

use axiom_eth::halo2_base::halo2_proofs::halo2curves::{
    bn256::{multi_miller_loop, Bn256, Fr, G1},
    pairing::{Engine, MillerLoopResult},
};

use super::types::{Proof, VerifyingKey};

pub fn verify_groth16_native(vk: VerifyingKey, proof: Proof, pi: Vec<Fr>, max_pi: usize) -> bool {
    let mut vk = vk.clone();
    vk.gamma_abc_g1.resize(max_pi + 1, vk.gamma_abc_g1[0]);

    let alpha_g1_beta_g2 = Bn256::pairing(&vk.alpha_g1, &vk.beta_g2);

    let mut pi = pi.clone();
    pi.resize(max_pi, Fr::zero());

    let prepared_inputs = {
        let mut g_ic: G1 = vk.gamma_abc_g1[0].into();
        for (i, b) in pi.iter().zip(vk.gamma_abc_g1.iter().skip(1)) {
            g_ic = g_ic.add(b.mul(i));
        }
        g_ic
    };

    let test = multi_miller_loop(&[
        (&proof.a, &proof.b.into()),
        (&prepared_inputs.into(), &vk.gamma_g2.neg().into()),
        (&proof.c, &vk.delta_g2.neg().into()),
    ])
    .final_exponentiation();

    test == alpha_g1_beta_g2
}
