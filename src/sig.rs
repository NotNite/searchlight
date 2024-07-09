use crate::MAX_INSN_SIZE;
use binaryninja::{
    architecture::Architecture,
    binaryview::{BinaryView, BinaryViewBase, BinaryViewExt},
};
use iced_x86::{FlowControl, OpKind};
use std::fmt::Display;

#[derive(Debug)]
pub struct Signature(pub Vec<Option<u8>>);

impl Display for Signature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let str = self
            .0
            .iter()
            .map(|byte| match byte {
                Some(byte) => format!("{:02X}", byte),
                None => "??".to_string(),
            })
            .collect::<Vec<String>>()
            .join(" ");
        write!(f, "{}", str)
    }
}

pub fn parse(sig: &str) -> anyhow::Result<Signature> {
    let sig = sig.trim().split(" ");
    let mut sig_bytes = Vec::new();
    for byte in sig {
        if byte == "??".to_string() {
            sig_bytes.push(None);
        } else {
            sig_bytes.push(Some(u8::from_str_radix(byte, 16)?));
        }
    }

    Ok(Signature(sig_bytes))
}

pub fn binary(bv: &BinaryView) -> Vec<Option<u8>> {
    let mut bytes = Vec::new();
    let start = bv.start();
    let end = bv.end();

    let per = 0x1000;
    let mut scratch = vec![0u8; per];

    let mut pos = start;
    loop {
        if pos < start || pos >= end {
            break;
        }

        let read = bv.read(&mut scratch, pos);
        if read == 0 {
            pos = bv.next_valid_offset_after(pos);
            continue;
        }

        for i in 0..read {
            bytes.push(Some(scratch[i]));
        }

        if read < per {
            pos = bv.next_valid_offset_after(pos + read as u64);
            for _ in 0..(per - read) {
                bytes.push(None);
            }
        } else {
            pos += per as u64;
        }
    }

    bytes
}

pub fn scan_in_binary(
    binary: &Vec<Option<u8>>,
    bv: &BinaryView,
    sig: &Signature,
    log: bool,
    max: usize,
) -> Vec<u64> {
    let start = bv.start();
    let end = bv.end();
    let sig_len = sig.0.len();

    let mut search = start;
    let mut results = Vec::new();

    loop {
        if search < start || search >= (end - sig_len as u64) {
            break;
        }

        let mut found = true;
        for i in 0..sig_len {
            let bi = binary[(search - start + i as u64) as usize];
            if bi.is_none() {
                found = false;
                break;
            }

            if sig.0[i].is_some() && sig.0[i].unwrap() != bi.unwrap() {
                found = false;
                break;
            }
        }

        if found {
            results.push(search);
            if log {
                log::info!("0x{:X}", search);
            }
            if results.len() >= max {
                break;
            }
        }

        search += 1;
    }

    results
}

pub fn read_u8(bv: &BinaryView, addr: u64) -> u8 {
    let mut value = [0u8; 1];
    bv.read(&mut value, addr);
    return value[0];
}

pub fn instruction_to_sig(bv: &BinaryView, pos: u64) -> Option<Signature> {
    let buf = bv.read_vec(pos, MAX_INSN_SIZE);
    let mut decoder = iced_x86::Decoder::new(
        if let Some(arch) = bv.default_arch() {
            (arch.address_size() * 8) as u32
        } else {
            64
        },
        &buf,
        0,
    );
    decoder.set_ip(pos);

    let instr = decoder.decode();
    let offsets = decoder.get_constant_offsets(&instr);
    if instr.is_invalid() {
        return None;
    }

    let is_branch = matches!(
        instr.flow_control(),
        FlowControl::Call
            | FlowControl::ConditionalBranch
            | FlowControl::IndirectBranch
            | FlowControl::IndirectCall
            | FlowControl::UnconditionalBranch
    );

    let mut pattern = buf
        .iter()
        .map(|byte| Some(*byte))
        .collect::<Vec<Option<u8>>>();

    // https://github.com/unknowntrojan/binja_coolsigmaker/blob/01be2ffd9fde5532656228b9804fcc31c56f447e/src/lib.rs#L381
    if offsets.has_displacement() {
        for x in offsets.displacement_offset()
            ..offsets.displacement_offset() + offsets.displacement_size()
        {
            pattern[x] = None;
        }
    }

    if offsets.has_immediate() {
        let branch_target = instr
            .op_kinds()
            .filter_map(|kind| match kind {
                OpKind::FarBranch16 => Some(instr.far_branch16() as u64 + bv.start() - 0x10000000),
                OpKind::FarBranch32 => Some(instr.far_branch32() as u64 + bv.start() - 0x10000000),
                OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64 => {
                    Some(instr.near_branch_target())
                }
                _ => None,
            })
            .nth(0);

        if is_branch && branch_target.is_some_and(|branch_target| bv.offset_valid(branch_target)) {
            for x in
                offsets.immediate_offset()..offsets.immediate_offset() + offsets.immediate_size()
            {
                pattern[x] = None;
            }
        }
    }

    if offsets.has_immediate2() {
        let branch_target = instr
            .op_kinds()
            .filter_map(|kind| match kind {
                OpKind::FarBranch16 => Some(instr.far_branch16() as u64 + bv.start() - 0x10000000),
                OpKind::FarBranch32 => Some(instr.far_branch32() as u64 + bv.start() - 0x10000000),
                OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64 => {
                    Some(instr.near_branch_target())
                }
                _ => None,
            })
            .nth(0);

        if is_branch && branch_target.is_some_and(|branch_target| bv.offset_valid(branch_target)) {
            for x in
                offsets.immediate_offset2()..offsets.immediate_offset2() + offsets.immediate_size2()
            {
                pattern[x] = None;
            }
        }
    }

    pattern.truncate(instr.len());
    Some(Signature(pattern))
}

pub fn create_for_range(bv: &BinaryView, range: std::ops::Range<u64>) -> Option<Signature> {
    let mut pos = range.start;
    let mut sig = Vec::new();
    while pos < range.end {
        let insn = instruction_to_sig(bv, pos);
        if insn.is_none() {
            return None;
        }
        let mut insn = insn.unwrap();
        pos += insn.0.len() as u64;
        sig.append(&mut insn.0);
    }

    Some(Signature(sig))
}

pub fn create_until_unique(
    bv: &BinaryView,
    binary: &Vec<Option<u8>>,
    offset: u64,
) -> Option<Signature> {
    let mut sig = Vec::new();
    let mut pos = offset;

    loop {
        if pos < bv.start() || pos >= bv.end() {
            return None;
        }

        if (pos - offset) as usize >= crate::MAX_LEN {
            return None;
        }

        let insn = instruction_to_sig(bv, pos);
        if insn.is_none() {
            return None;
        }
        let mut insn = insn.unwrap();
        pos += insn.0.len() as u64;
        sig.append(&mut insn.0);

        let sig = Signature(sig.clone());
        if scan_in_binary(binary, bv, &sig, false, 2).len() == 1 {
            return Some(sig);
        }
    }
}

pub fn get_function_tries(bv: &BinaryView, func: &binaryninja::function::Function) -> Vec<u64> {
    let mut tries = Vec::new();

    // add function start, as long as it doesn't start with E8/E9 (mistaken for call indirection)
    let start = func.start();
    let start_byte = read_u8(bv, start);
    if start_byte != 0xE8 && start_byte != 0xE9 {
        tries.push(start);
    }

    // try all call indirections (call <func>)
    let refs = bv.get_code_refs(start);
    for ref_ in refs.iter() {
        let ref_ = ref_.address;
        let ref_byte = read_u8(bv, ref_);
        if ref_byte == 0xE8 || ref_byte == 0xE9 {
            tries.push(ref_);
        }
    }

    tries
}

pub fn get_address_tries(bv: &BinaryView, addr: u64) -> Vec<u64> {
    let refs = bv.get_code_refs(addr);
    refs.iter().map(|ref_| ref_.address).collect()
}
