use std::cmp::min;

use axiom_eth::{
    halo2_base::{
        gates::{flex_gate::threads::parallelize_core, RangeChip, RangeInstructions},
        AssignedValue, Context,
    },
    rlc::circuit::builder::RlcCircuitBuilder,
    utils::{
        build_utils::dummy::DummyFrom,
        bytes_be_to_uint,
        component::{types::PoseidonHasher, utils::create_hasher},
        hilo::HiLo,
        uint_to_bytes_be, uint_to_bytes_le,
    },
    Field,
};
use component_derive::Component;
use halo2_ecc::{
    bn254::{pairing::PairingChip, Fp2Chip, FpChip},
    ecc::EccChip,
    halo2_base::{gates::GateInstructions, safe_types::SafeByte, utils::biguint_to_fe},
};
use num_bigint::BigUint;
use serde_json;

use self::{
    test::default_groth16_subquery_input,
    types::{Groth16VerifierComponentInput, Groth16VerifierComponentParams, Groth16VerifierInput},
    utils::*,
    verifier::{
        types::{ProofAssigned, VerifyingKeyAssigned},
        verify_proof,
    },
};
use crate::{
    groth16::types::{
        Groth16VerifierComponentOutput, Groth16VerifierComponentProof,
        Groth16VerifierComponentVerificationKey,
    },
    scaffold::{BasicComponentScaffold, BasicComponentScaffoldIO},
    utils::flatten::InputFlatten,
};

pub mod native;
pub mod test;
pub mod types;
pub mod utils;
pub mod verifier;

pub const NUM_BYTES_PER_FE: usize = 31;
pub const NUM_FE_PER_CHUNK: usize = 13;
pub const NUM_BYTES_PROOF: usize = (4 + 8 + 4) * 16;
pub const MAX_NUM_BYTES_PER_CHUNK: usize = NUM_BYTES_PER_FE * NUM_FE_PER_CHUNK;
pub const NULL_CHUNK_VAL: usize = 2;
pub const NUM_FE_PROOF: usize = (NUM_BYTES_PROOF + NUM_BYTES_PER_FE - 1) / NUM_BYTES_PER_FE;

#[derive(Debug, Clone, Copy)]
pub struct Groth16InputConstants {
    pub max_pi: usize,
    pub gamma_abc_g1_len: usize,
    pub num_fe_hilo_vkey: usize,
    pub num_bytes_vkey: usize,
    pub num_bytes_per_input_without_pi: usize,
    pub num_fe_vkey: usize,
    pub num_fe_per_input_without_pi: usize,
    pub num_fe_per_input: usize,
    pub num_chunks: usize,
    pub max_num_fe_per_input: usize,
    pub max_num_fe_per_input_no_hash: usize,
    pub max_num_bytes_per_input: usize,
    pub num_fe_padding: usize,
}

pub fn get_groth16_consts_from_max_pi(max_pi: usize) -> Groth16InputConstants {
    let gamma_abc_g1_len = max_pi + 1;
    let num_fe_hilo_vkey = 4 + 8 + 8 + 8 + 4 * gamma_abc_g1_len;
    let num_bytes_vkey = num_fe_hilo_vkey * 16 + 1;
    let num_bytes_per_input_without_pi = num_bytes_vkey + NUM_BYTES_PROOF;
    let num_fe_vkey = (num_bytes_vkey + NUM_BYTES_PER_FE - 1) / NUM_BYTES_PER_FE;
    let num_fe_per_input_without_pi = num_fe_vkey + NUM_FE_PROOF;
    let num_fe_per_input = num_fe_per_input_without_pi + max_pi;
    let num_chunks = (num_fe_per_input + NUM_FE_PER_CHUNK - 1) / NUM_FE_PER_CHUNK;
    let max_num_fe_per_input = NUM_FE_PER_CHUNK * num_chunks;
    let max_num_fe_per_input_no_hash = max_num_fe_per_input - 1;
    let max_num_bytes_per_input = NUM_BYTES_PER_FE * max_num_fe_per_input_no_hash;
    let num_fe_padding = max_num_fe_per_input_no_hash - num_fe_per_input;
    Groth16InputConstants {
        max_pi,
        gamma_abc_g1_len,
        num_fe_hilo_vkey,
        num_bytes_vkey,
        num_bytes_per_input_without_pi,
        num_fe_vkey,
        num_fe_per_input_without_pi,
        num_fe_per_input,
        num_chunks,
        max_num_fe_per_input,
        max_num_fe_per_input_no_hash,
        max_num_bytes_per_input,
        num_fe_padding,
    }
}

impl<F: Field> Groth16VerifierComponentProof<AssignedValue<F>> {
    pub fn convert_to_affine(
        &self,
        ctx: &mut Context<F>,
        range: &RangeChip<F>,
        g1_chip: &EccChip<F, FpChip<F>>,
    ) -> ProofAssigned<F> {
        let a = hilo_point_to_affine(ctx, range, g1_chip, self.a);
        let b = hilo_pair_to_affine(ctx, range, g1_chip, self.b);
        let c = hilo_point_to_affine(ctx, range, g1_chip, self.c);

        ProofAssigned { a, b, c }
    }
}

impl<F: Field> Groth16VerifierComponentVerificationKey<AssignedValue<F>> {
    pub fn convert_to_affine(
        &self,
        ctx: &mut Context<F>,
        range: &RangeChip<F>,
        g1_chip: &EccChip<F, FpChip<F>>,
        num_public_inputs: AssignedValue<F>,
        max_len: usize,
    ) -> VerifyingKeyAssigned<F> {
        let alpha_g1 = hilo_point_to_affine(ctx, range, g1_chip, self.alpha_g1);
        let beta_g2 = hilo_pair_to_affine(ctx, range, g1_chip, self.beta_g2);
        let gamma_g2 = hilo_pair_to_affine(ctx, range, g1_chip, self.gamma_g2);
        let delta_g2 = hilo_pair_to_affine(ctx, range, g1_chip, self.delta_g2);
        let mut gamma_abc_g1 = self
            .gamma_abc_g1
            .iter()
            .map(|pt| hilo_point_to_affine(ctx, range, g1_chip, *pt))
            .collect::<Vec<_>>();
        gamma_abc_g1.resize(max_len, gamma_abc_g1[0].clone());
        VerifyingKeyAssigned {
            alpha_g1,
            beta_g2,
            gamma_g2,
            delta_g2,
            gamma_abc_g1,
            abc_len: num_public_inputs,
        }
    }
}

#[derive(Component)]
pub struct Groth16VerifierComponent<F: Field>(std::marker::PhantomData<F>);

impl<F: Field> BasicComponentScaffold<F> for Groth16VerifierComponent<F> {
    type Params = Groth16VerifierComponentParams;
    fn virtual_assign_phase0(
        params: Groth16VerifierComponentParams,
        builder: &mut RlcCircuitBuilder<F>,
        input: Vec<Groth16VerifierComponentInput<F>>,
    ) -> BasicComponentScaffoldIO<F, Self> {
        let range = builder.base.range_chip();
        let input_constants = get_groth16_consts_from_max_pi(params.max_public_inputs);
        assert!(input.len() % input_constants.num_chunks == 0);
        let chunked_input = input.chunks(input_constants.num_chunks).collect::<Vec<_>>();
        let zero = builder.base.main(0).load_constant(F::ZERO);
        let two = builder
            .base
            .main(0)
            .load_constant(F::from(NULL_CHUNK_VAL as u64));

        let null_output = Groth16VerifierComponentOutput {
            success: HiLo::from_hi_lo([zero, two]),
        };
        let mut hasher = create_hasher();
        hasher.initialize_consts(builder.base.main(0), &range.gate);
        let pool = builder.base.pool(0);
        let res = parallelize_core(pool, chunked_input, |ctx, subquery| {
            let assigned_inputs = subquery
                .iter()
                .map(|x| Self::assign_input(ctx, x.clone()))
                .collect::<Vec<_>>();

            let (input, res) =
                join_groth16_input(ctx, &range, &assigned_inputs, &hasher, input_constants);
            let out = handle_single_groth16verify(
                ctx,
                &range,
                input,
                params.limb_bits,
                params.num_limbs,
                params.max_public_inputs,
            )
            .1;
            ctx.constrain_equal(&res, &out.success.lo());
            let last_idx = assigned_inputs.len() - 1;
            let mut outputs = assigned_inputs
                .iter()
                .map(|x| (x.clone(), null_output.clone()))
                .collect::<Vec<_>>();
            outputs[last_idx] = (assigned_inputs[last_idx].clone(), out);
            outputs
        });
        let outputs = res.into_iter().flatten().collect::<Vec<_>>();
        ((), outputs)
    }
}

impl<F: Field> DummyFrom<Groth16VerifierComponentParams> for Vec<Groth16VerifierComponentInput<F>> {
    fn dummy_from(core_params: Groth16VerifierComponentParams) -> Self {
        let capacity = core_params.capacity;
        let constants = get_groth16_consts_from_max_pi(core_params.max_public_inputs);
        assert_eq!(capacity % constants.num_chunks, 0);
        let num_joined_subqueries = capacity / constants.num_chunks;
        let single_input = default_groth16_subquery_input(core_params.max_public_inputs);
        let stringified = serde_json::to_string(&single_input).unwrap();
        let single_input: Vec<Groth16VerifierComponentInput<F>> =
            serde_json::from_str(&stringified).unwrap();
        (0..num_joined_subqueries)
            .flat_map(|_| single_input.clone())
            .collect::<Vec<_>>()
    }
}

pub fn handle_single_groth16verify<F: Field>(
    ctx: &mut Context<F>,
    range: &RangeChip<F>,
    input: Groth16VerifierInput<AssignedValue<F>>,
    limb_bits: usize,
    num_limbs: usize,
    max_public_inputs: usize,
) -> (
    Groth16VerifierInput<AssignedValue<F>>,
    Groth16VerifierComponentOutput<AssignedValue<F>>,
) {
    let fp_chip = FpChip::<F>::new(range, limb_bits, num_limbs);
    let fp2_chip = Fp2Chip::<F>::new(&fp_chip);
    let g1_chip = EccChip::new(&fp_chip);
    let g2_chip = EccChip::new(&fp2_chip);
    let pairing_chip = PairingChip::new(&fp_chip);

    let p = input.proof.convert_to_affine(ctx, range, &g1_chip);
    let vk = input.vk.convert_to_affine(
        ctx,
        range,
        &g1_chip,
        input.num_public_inputs,
        max_public_inputs + 1,
    );

    let success = verify_proof(
        ctx,
        range,
        &pairing_chip,
        &g1_chip,
        &g2_chip,
        &vk,
        &p,
        &input.public_inputs,
    );

    let hi_lo_success = HiLo::from_hi_lo([ctx.load_constant(F::ZERO), success]);

    (
        input,
        Groth16VerifierComponentOutput {
            success: hi_lo_success,
        },
    )
}

pub fn join_groth16_input<F: Field>(
    ctx: &mut Context<F>,
    range: &RangeChip<F>,
    chunks: &[Groth16VerifierComponentInput<AssignedValue<F>>],
    hasher: &PoseidonHasher<F>,
    input_constants: Groth16InputConstants,
) -> (Groth16VerifierInput<AssignedValue<F>>, AssignedValue<F>) {
    assert_eq!(chunks.len(), input_constants.num_chunks);
    let mut verification_result: AssignedValue<F> = ctx.load_constant(F::ZERO);
    let shift = ctx.load_constant(biguint_to_fe(&BigUint::from(2u64).pow(31 * 8)));
    let chunks = chunks
        .iter()
        .enumerate()
        .map(|(idx, x)| {
            let mut bytes = x.packed_bytes.vec.clone();
            // this is the most significat byte in the first bytes32 chunk
            let res = uint_to_bytes_be(ctx, range, &bytes[0], 32)[0];
            bytes[0] = range.gate().sub_mul(ctx, bytes[0], res, shift);
            if idx == input_constants.num_chunks - 1 {
                verification_result = *res;
            } else {
                range
                    .gate()
                    .assert_is_const(ctx, &res, &F::from(NULL_CHUNK_VAL as u64));
            }
            Groth16VerifierComponentInput {
                packed_bytes: bytes.into(),
            }
        })
        .collect::<Vec<_>>();

    let mut bytes: Vec<SafeByte<F>> = vec![];
    let mut byte_chunks = chunks
        .iter()
        .flat_map(|x| x.packed_bytes.vec.clone())
        .collect::<Vec<_>>();
    let hash = byte_chunks.pop().unwrap();
    assert_eq!(
        byte_chunks.len(),
        input_constants.max_num_fe_per_input_no_hash
    );
    let res = hasher.hash_fix_len_array(ctx, &range.gate, &byte_chunks);
    ctx.constrain_equal(&res, &hash);

    let mut pis = byte_chunks
        .split_off(byte_chunks.len() - input_constants.max_pi - input_constants.num_fe_padding);
    let padding = pis.split_off(pis.len() - input_constants.num_fe_padding);
    padding
        .iter()
        .for_each(|x| range.gate.assert_is_const(ctx, x, &F::ZERO));
    let mut idx = 0;
    let mut unpack_bytes = |bytes: &mut Vec<SafeByte<F>>, mut num_bytes: usize| {
        while num_bytes > 0 {
            let num_bytes_fe = min(NUM_BYTES_PER_FE, num_bytes);
            let mut chunk_bytes = uint_to_bytes_le(ctx, range, &byte_chunks[idx], num_bytes_fe);
            bytes.append(&mut chunk_bytes);
            num_bytes -= num_bytes_fe;
            idx += 1;
        }
    };
    unpack_bytes(&mut bytes, input_constants.num_bytes_vkey);
    assert_eq!(bytes.len(), input_constants.num_bytes_vkey);
    let num_inputs = bytes.pop().unwrap();
    unpack_bytes(&mut bytes, NUM_BYTES_PROOF);
    assert_eq!(
        idx,
        input_constants.num_fe_per_input - input_constants.max_pi
    );
    assert_eq!(
        bytes.len(),
        input_constants.num_bytes_per_input_without_pi - 1
    );
    let bytes32_chunks = bytes.chunks(32).collect::<Vec<_>>();
    let unpacked = bytes32_chunks
        .iter()
        .flat_map(|x| pack_bytes_le_to_hilo(ctx, range.gate(), x).flatten())
        .collect::<Vec<_>>();
    let vk_fe = unpacked[..input_constants.num_fe_hilo_vkey].to_vec();
    let proof_fe = unpacked[input_constants.num_fe_hilo_vkey..].to_vec();
    (
        Groth16VerifierInput {
            vk: Groth16VerifierComponentVerificationKey::unflatten(
                vk_fe,
                input_constants.gamma_abc_g1_len,
            ),
            proof: Groth16VerifierComponentProof::unflatten(proof_fe).unwrap(),
            public_inputs: pis,
            num_public_inputs: *num_inputs.as_ref(),
        },
        verification_result,
    )
}

pub fn unflatten_groth16_input<F: Field>(input: Vec<F>, max_pi: usize) -> Groth16VerifierInput<F> {
    let constants = get_groth16_consts_from_max_pi(max_pi);
    let mut input = input
        .chunks(NUM_FE_PER_CHUNK)
        .collect::<Vec<_>>()
        .iter()
        .flat_map(|x| {
            let mut x = x.to_vec();
            let first_fe_bytes = x[0].to_bytes_le();
            x[0] = F::from_bytes_le(&first_fe_bytes[..31]);
            x
        })
        .collect::<Vec<_>>();
    //remove the hash from the flattened input
    input.pop();
    assert_eq!(input.len(), constants.max_num_fe_per_input_no_hash);
    // assert_eq!(hash, compute_poseidon(&input));
    let mut public_inputs =
        input.split_off(input.len() - constants.max_pi - constants.num_fe_padding);
    public_inputs.truncate(public_inputs.len() - constants.num_fe_padding);
    assert_eq!(public_inputs.len(), constants.max_pi);
    let proof_fe = input.split_off(input.len() - NUM_FE_PROOF);
    assert_eq!(proof_fe.len(), NUM_FE_PROOF);
    let vk_fe = input.split_off(input.len() - constants.num_fe_vkey);
    assert_eq!(vk_fe.len(), constants.num_fe_vkey);

    let unpack_bytes = |bytes: Vec<F>, mut num_bytes: usize| -> Vec<u8> {
        let mut idx = 0;
        let mut byte_chunks = vec![];
        while num_bytes > 0 {
            let num_bytes_fe = min(NUM_BYTES_PER_FE, num_bytes);
            let mut chunk_bytes = bytes[idx].to_bytes_le()[..num_bytes_fe].to_vec();
            byte_chunks.append(&mut chunk_bytes);
            num_bytes -= num_bytes_fe;
            idx += 1;
        }
        byte_chunks
    };

    let mut vk_bytes = unpack_bytes(vk_fe.clone(), constants.num_bytes_vkey);
    let num_public_inputs = vk_bytes.pop().unwrap();

    let proof_bytes = unpack_bytes(proof_fe.clone(), NUM_BYTES_PROOF);

    let vk_hilo = vk_bytes
        .chunks(16)
        .collect::<Vec<_>>()
        .iter()
        .map(|x| F::from_u128(u128::from_le_bytes((*x).try_into().unwrap())))
        .collect::<Vec<_>>();

    let proof_hilo = proof_bytes
        .chunks(16)
        .collect::<Vec<_>>()
        .iter()
        .map(|x| F::from_u128(u128::from_le_bytes((*x).try_into().unwrap())))
        .collect::<Vec<_>>();

    let vk =
        Groth16VerifierComponentVerificationKey::unflatten(vk_hilo, constants.gamma_abc_g1_len);
    let proof = Groth16VerifierComponentProof::unflatten(proof_hilo).unwrap();
    Groth16VerifierInput {
        vk,
        proof,
        public_inputs,
        num_public_inputs: F::from(num_public_inputs as u64),
    }
}

pub fn pack_bytes_le_to_hilo<F: Field>(
    ctx: &mut Context<F>,
    gate: &impl GateInstructions<F>,
    bytes: &[SafeByte<F>],
) -> HiLo<AssignedValue<F>> {
    let len = bytes.len();
    assert!(len <= 32);
    let hi = if len > 16 {
        let mut hi_bytes = bytes[0..len - 16].to_vec();
        hi_bytes.reverse();
        bytes_be_to_uint(ctx, gate, &hi_bytes, hi_bytes.len())
    } else {
        ctx.load_zero()
    };
    let lo = {
        let lo_len = if len > 16 { 16 } else { len };
        let mut lo_bytes = bytes[len - lo_len..len].to_vec();
        lo_bytes.reverse();
        bytes_be_to_uint(ctx, gate, &lo_bytes, lo_len)
    };
    HiLo::from_hi_lo([hi, lo])
}
