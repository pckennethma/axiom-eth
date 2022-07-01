use axiom_eth::{
    halo2curves::{
        bn256::{Fq2, G1Affine, G2Affine},
        CurveAffine,
    },
    Field,
};
use halo2_ecc::halo2_base::utils::{biguint_to_fe, fe_to_biguint};

use super::{
    biguint_to_hilo,
    types::Groth16VerifierInput,
    verifier::{
        native::verify_groth16_native,
        types::{Proof, VerifyingKey},
    },
    Groth16VerifierComponentProof, Groth16VerifierComponentVerificationKey, HiLoPair, HiLoPoint,
};
use crate::ecdsa::utils::decode_hilo_to_biguint;

pub fn g1_affine_to_hilo_point<F: Field>(point: G1Affine) -> HiLoPoint<F> {
    (
        biguint_to_hilo(fe_to_biguint(&point.x)),
        biguint_to_hilo(fe_to_biguint(&point.y)),
    )
}

pub fn hilo_point_to_g1_affine<F: Field>(point: HiLoPoint<F>) -> G1Affine {
    G1Affine::from_xy(
        biguint_to_fe(&decode_hilo_to_biguint(point.0)),
        biguint_to_fe(&decode_hilo_to_biguint(point.1)),
    )
    .unwrap()
}

pub fn g2_affine_to_hilo_pair<F: Field>(pair: G2Affine) -> HiLoPair<F> {
    let x_c0 = biguint_to_hilo(fe_to_biguint(&pair.x.c0));
    let x_c1 = biguint_to_hilo(fe_to_biguint(&pair.x.c1));
    let y_c0 = biguint_to_hilo(fe_to_biguint(&pair.y.c0));
    let y_c1 = biguint_to_hilo(fe_to_biguint(&pair.y.c1));
    ((x_c0, x_c1), (y_c0, y_c1))
}

pub fn hilo_pair_to_g2_affine<F: Field>(pair: HiLoPair<F>) -> G2Affine {
    G2Affine::from_xy(
        Fq2 {
            c0: biguint_to_fe(&decode_hilo_to_biguint(pair.0 .0)),
            c1: biguint_to_fe(&decode_hilo_to_biguint(pair.0 .1)),
        },
        Fq2 {
            c0: biguint_to_fe(&decode_hilo_to_biguint(pair.1 .0)),
            c1: biguint_to_fe(&decode_hilo_to_biguint(pair.1 .1)),
        },
    )
    .unwrap()
}

impl<F: Field> From<Groth16VerifierComponentVerificationKey<F>> for VerifyingKey {
    fn from(input: Groth16VerifierComponentVerificationKey<F>) -> Self {
        VerifyingKey {
            alpha_g1: hilo_point_to_g1_affine(input.alpha_g1),
            beta_g2: hilo_pair_to_g2_affine(input.beta_g2),
            gamma_g2: hilo_pair_to_g2_affine(input.gamma_g2),
            delta_g2: hilo_pair_to_g2_affine(input.delta_g2),
            gamma_abc_g1: input
                .gamma_abc_g1
                .into_iter()
                .map(|pt| hilo_point_to_g1_affine(pt))
                .collect::<Vec<_>>(),
        }
    }
}

impl<F: Field> From<Groth16VerifierComponentProof<F>> for Proof {
    fn from(input: Groth16VerifierComponentProof<F>) -> Self {
        Proof {
            a: hilo_point_to_g1_affine(input.a),
            b: hilo_pair_to_g2_affine(input.b),
            c: hilo_point_to_g1_affine(input.c),
        }
    }
}

pub fn verify_groth16<F: Field>(input: Groth16VerifierInput<F>, max_pi: usize) -> bool {
    verify_groth16_native(
        input.vk.into(),
        input.proof.into(),
        input
            .public_inputs
            .iter()
            .map(|x| biguint_to_fe(&fe_to_biguint(x)))
            .collect::<Vec<_>>(),
        max_pi,
    )
}
