use binaryninja::{
    binaryview::{BinaryView, BinaryViewBase, BinaryViewExt},
    types::ConstantReference,
};
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

pub fn read_int32(bv: &BinaryView, addr: u64) -> u32 {
    let mut value = [0u8; 4];
    bv.read(&mut value, addr);
    return u32::from_le_bytes(value);
}

pub fn instruction_to_sig(
    bv: &BinaryView,
    addr: u64,
    inst_length: usize,
    consts: Vec<ConstantReference>,
) -> Signature {
    let mut sig = Vec::new();
    let mut new_delta = 0;

    if consts.is_empty() {
        for i in 0..inst_length {
            sig.push(Some(read_u8(bv, addr + i as u64)));
        }
        return Signature(sig);
    }

    for const_ in consts {
        if const_.pointer {
            new_delta += 4;
        } else {
            let four_bytes = read_int32(bv, addr + inst_length as u64 - (new_delta + 4) as u64);
            if const_.value == four_bytes.into() {
                new_delta += 4;
            } else {
                let one_byte = read_u8(bv, addr + inst_length as u64 - (new_delta + 1) as u64);
                if const_.value == one_byte.into() {
                    new_delta += 1;
                }
            }
        }
    }

    for x in 0..inst_length - new_delta {
        sig.push(Some(read_u8(bv, addr + x as u64)));
    }
    for _ in 0..new_delta {
        sig.push(None);
    }

    Signature(sig)
}

pub fn create_for_range(bv: &BinaryView, range: std::ops::Range<u64>) -> Option<Signature> {
    let func = bv.functions_containing(range.start);
    if func.is_empty() {
        return None;
    }
    let func = func.get(0);

    let mut pos = range.start;
    let mut sig = Vec::new();
    while pos < range.end {
        let consts = func
            .constants_referenced_by(pos, Some(func.arch()))
            .into_iter()
            .collect();

        let inst_length = bv.instruction_len(&func.arch(), pos);
        if inst_length.is_none() {
            return None;
        }
        let inst_length = inst_length.unwrap();
        if inst_length == 0 {
            return None;
        }

        let mut insn = instruction_to_sig(bv, pos, inst_length, consts);
        sig.append(&mut insn.0);

        pos += inst_length as u64;
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

        let func = bv.functions_containing(pos);
        if func.is_empty() {
            return None;
        }
        let func = func.get(0);

        let consts = func
            .constants_referenced_by(pos, Some(func.arch()))
            .into_iter()
            .collect();

        let inst_length = bv.instruction_len(&func.arch(), pos);
        if inst_length.is_none() {
            return None;
        }
        let inst_length = inst_length.unwrap();
        if inst_length == 0 {
            return None;
        }

        let mut insn = instruction_to_sig(bv, pos, inst_length, consts);
        sig.append(&mut insn.0);

        pos += inst_length as u64;

        let sig = Signature(sig.clone());
        if scan_in_binary(binary, bv, &sig, false).len() == 1 {
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
