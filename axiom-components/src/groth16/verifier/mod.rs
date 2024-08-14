pub mod native;
#[cfg(test)]
pub mod test;
pub mod types;

use axiom_eth::{
    halo2_base::{
        gates::{GateInstructions, RangeChip, RangeInstructions},
        halo2_proofs::halo2curves::bn256::G1Affine,
        utils::BigPrimeField,
        AssignedValue, Context,
    },
    utils::circuit_utils::unsafe_lt_mask,
};
use halo2_ecc::{
    bn254::{pairing::PairingChip, Fp12Chip, Fp2Chip, FpChip},
    ecc::EccChip,
    fields::FieldChip,
};
use types::{G1AffineAssigned, ProofAssigned, VerifyingKeyAssigned};

/// Prepare proof inputs for use with [`verify_proof_with_prepared_inputs`], wrt the prepared
/// verification key `vk` and instance public inputs.
pub fn prepare_inputs<F: BigPrimeField>(
    ctx: &mut Context<F>,
    range: &RangeChip<F>,
    g1_chip: &EccChip<F, FpChip<F>>,
    vk: &VerifyingKeyAssigned<F>,
    public_inputs: &[AssignedValue<F>],
) -> G1AffineAssigned<F> {
    assert!((public_inputs.len() + 1) == vk.gamma_abc_g1.len());
    let gate = range.gate();
    range.check_less_than_safe(ctx, vk.abc_len, vk.gamma_abc_g1.len() as u64 + 1);
    // check abc_len != 0
    let len_is_zero = gate.is_zero(ctx, vk.abc_len);
    gate.assert_is_const(ctx, &len_is_zero, &F::ZERO);
    let one = ctx.load_constant(F::ONE);
    let num_pi = gate.sub(ctx, vk.abc_len, one);
    let lt_mask = unsafe_lt_mask(ctx, gate, num_pi, public_inputs.len());
    let mut addends = vec![vk.gamma_abc_g1[0].clone()];
    for (j, (i, b)) in public_inputs
        .iter()
        .zip(vk.gamma_abc_g1.iter().skip(1))
        .enumerate()
    {
        let i_mask = gate.mul(ctx, lt_mask[j], *i);
        let bi = g1_chip.scalar_mult::<G1Affine>(ctx, (*b).clone(), vec![i_mask], 254, 4);
        addends.push(bi);
    }
    g1_chip.sum::<G1Affine>(ctx, addends)
}

/// Verify a Groth16 proof `proof` against the prepared verification key `pvk` and prepared public
/// inputs. This should be preferred over [`verify_proof`] if the instance's public inputs are
/// known in advance.
pub fn verify_proof_with_prepared_inputs<F: BigPrimeField>(
    ctx: &mut Context<F>,
    pairing_chip: &PairingChip<F>,
    g2_chip: &EccChip<F, Fp2Chip<F>>,
    vk: &VerifyingKeyAssigned<F>,
    proof: &ProofAssigned<F>,
    prepared_inputs: &G1AffineAssigned<F>,
) -> AssignedValue<F> {
    let neg_gamma_g2 = g2_chip.negate(ctx, &vk.gamma_g2);
    let neg_delta_g2 = g2_chip.negate(ctx, &vk.delta_g2);
    let qap = pairing_chip.multi_miller_loop(
        ctx,
        vec![
            (&prepared_inputs, &neg_gamma_g2),
            (&proof.c, &neg_delta_g2),
            (&proof.a, &proof.b),
        ],
    );
    let test = pairing_chip.final_exp(ctx, qap);
    let alpha_g1_beta_g2 = pairing_chip.pairing(ctx, &vk.beta_g2, &vk.alpha_g1);
    let fp12_chip = Fp12Chip::new(g2_chip.field_chip().fp_chip());
    // println!("FIRST: {:?}\n", test);
    // println!("FIRST: {:?}\n", alpha_g1_beta_g2);
    fp12_chip.is_equal(ctx, &test, &alpha_g1_beta_g2)
}

/// Verify a Groth16 proof `proof` against the prepared verification key `pvk`,
/// with respect to the instance `public_inputs`.
#[allow(clippy::too_many_arguments)]
pub fn verify_proof<F: BigPrimeField>(
    ctx: &mut Context<F>,
    range: &RangeChip<F>,
    pairing_chip: &PairingChip<F>,
    g1_chip: &EccChip<F, FpChip<F>>,
    g2_chip: &EccChip<F, Fp2Chip<F>>,
    vk: &VerifyingKeyAssigned<F>,
    proof: &ProofAssigned<F>,
    public_inputs: &[AssignedValue<F>],
) -> AssignedValue<F> {
    let prepared_inputs = prepare_inputs(ctx, range, g1_chip, vk, public_inputs);
    verify_proof_with_prepared_inputs(ctx, pairing_chip, g2_chip, vk, proof, &prepared_inputs)
}
