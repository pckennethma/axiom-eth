use axiom_eth::halo2_base::{
    halo2_proofs::halo2curves::bn256::{G1Affine, G2Affine},
    utils::BigPrimeField,
    AssignedValue, Context,
};
use halo2_ecc::{
    bigint::ProperCrtUint,
    bn254::{Fp2Chip, FpChip},
    ecc::{EcPoint, EccChip},
    fields::vector::FieldVector,
};
use serde::{Deserialize, Serialize};

pub type G2AffineAssigned<F> = EcPoint<F, FieldVector<ProperCrtUint<F>>>;
pub type G1AffineAssigned<F> = EcPoint<F, ProperCrtUint<F>>;

/// A proof in the Groth16 SNARK.
#[derive(Clone, Debug, PartialEq, Copy, Serialize, Deserialize, Eq)]
pub struct Proof {
    /// The `A` element in `G1`.
    pub a: G1Affine,
    /// The `B` element in `G2`.
    pub b: G2Affine,
    /// The `C` element in `G1`.
    pub c: G1Affine,
}

/// A verification key in the Groth16 SNARK.
#[derive(Clone, Debug)]
pub struct ProofAssigned<F: BigPrimeField> {
    /// The `A` element in `G1`.
    pub a: G1AffineAssigned<F>,
    /// The `B` element in `G2`.
    pub b: G2AffineAssigned<F>,
    /// The `C` element in `G1`.
    pub c: G1AffineAssigned<F>,
}

impl Proof {
    pub fn assign<F: BigPrimeField>(
        &self,
        ctx: &mut Context<F>,
        g1_chip: &EccChip<F, FpChip<F>>,
        g2_chip: &EccChip<F, Fp2Chip<F>>,
    ) -> ProofAssigned<F> {
        // let fp_chip = FpChip::<F>::new(&range, params.limb_bits, params.num_limbs);
        // let fp2_chip = Fp2Chip::<F>::new(&fp_chip);
        let a = g1_chip.assign_point(ctx, self.a);
        let b = g2_chip.assign_point(ctx, self.b);
        let c = g1_chip.assign_point(ctx, self.c);

        ProofAssigned { a, b, c }
    }
}

////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////

/// A verification key in the Groth16 SNARK.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default, Eq)]
pub struct VerifyingKey {
    /// The `alpha * G`, where `G` is the generator of `E::G1`.
    pub alpha_g1: G1Affine,
    /// The `alpha * H`, where `H` is the generator of `E::G2`.
    pub beta_g2: G2Affine,
    /// The `gamma * H`, where `H` is the generator of `E::G2`.
    pub gamma_g2: G2Affine,
    /// The `delta * H`, where `H` is the generator of `E::G2`.
    pub delta_g2: G2Affine,
    /// The `gamma^{-1} * (beta * a_i + alpha * b_i + c_i) * H`, where `H` is the generator of `E::G1`.
    pub gamma_abc_g1: Vec<G1Affine>,
}

/// A verification key in the Groth16 SNARK.
#[derive(Clone, Debug)]
pub struct VerifyingKeyAssigned<F: BigPrimeField> {
    /// The `alpha * G`, where `G` is the generator of `E::G1`.
    pub alpha_g1: G1AffineAssigned<F>,
    /// The `alpha * H`, where `H` is the generator of `E::G2`.
    pub beta_g2: G2AffineAssigned<F>,
    /// The `gamma * H`, where `H` is the generator of `E::G2`.
    pub gamma_g2: G2AffineAssigned<F>,
    /// The `delta * H`, where `H` is the generator of `E::G2`.
    pub delta_g2: G2AffineAssigned<F>,
    /// The `gamma^{-1} * (beta * a_i + alpha * b_i + c_i) * H`, where `H` is the generator of `E::G1`.
    pub gamma_abc_g1: Vec<G1AffineAssigned<F>>,

    pub abc_len: AssignedValue<F>,
}

impl VerifyingKey {
    pub fn assign<F: BigPrimeField>(
        &self,
        ctx: &mut Context<F>,
        g1_chip: &EccChip<F, FpChip<F>>,
        g2_chip: &EccChip<F, Fp2Chip<F>>,
        max_len: usize,
    ) -> VerifyingKeyAssigned<F> {
        // let fp_chip = FpChip::<F>::new(&range, params.limb_bits, params.num_limbs);
        // let fp2_chip = Fp2Chip::<F>::new(&fp_chip);
        let alpha_g1 = g1_chip.assign_point(ctx, self.alpha_g1);
        let beta_g2 = g2_chip.assign_point(ctx, self.beta_g2);
        let gamma_g2 = g2_chip.assign_point(ctx, self.gamma_g2);
        let delta_g2 = g2_chip.assign_point(ctx, self.delta_g2);
        let len = self.gamma_abc_g1.len();
        let mut gamma_abc_g1 = self
            .gamma_abc_g1
            .iter()
            .map(|pt| g1_chip.assign_point(ctx, *pt))
            .collect::<Vec<_>>();
        let abc_len = ctx.load_witness(F::from(len as u64));
        gamma_abc_g1.resize(max_len, gamma_abc_g1[0].clone());
        VerifyingKeyAssigned {
            alpha_g1,
            beta_g2,
            gamma_g2,
            delta_g2,
            gamma_abc_g1,
            abc_len,
        }
    }
}
