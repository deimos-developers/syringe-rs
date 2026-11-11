//! Translation of `SyringeEx/tests/RebuildInstructionsTests.cpp`.

#![cfg(test)]

use zydis::{AllOperands, Decoder, Instruction, MachineMode, Mnemonic, StackWidth, ffi};

use crate::syringe_debugger::SyringeDebugger;

fn rebuild(bytes: &[u8], original_addr: u32, new_addr: u32) -> Vec<u8> {
    SyringeDebugger::rebuild_instructions(bytes, original_addr, new_addr, "")
}

fn decode(code: &[u8]) -> Option<Instruction<AllOperands>> {
    let decoder = Decoder::new(MachineMode::LONG_COMPAT_32, StackWidth::_32).ok()?;
    decoder.decode_first::<AllOperands>(code).ok().flatten()
}

fn decode_branch_target(code: &[u8], runtime_addr: u32) -> Option<u32> {
    let instruction = decode(code)?;

    for operand in instruction.visible_operands() {
        if matches!(operand.kind, ffi::DecodedOperandKind::Imm(_)) {
            if let Ok(address) = instruction.calc_absolute_address(runtime_addr as u64, operand) {
                return Some(address as u32);
            }
        }
    }

    None
}

fn decode_mnemonic(code: &[u8]) -> Option<Mnemonic> {
    decode(code).map(|instruction| instruction.mnemonic)
}

#[test]
fn non_relative_copied_verbatim() {
    let bytes = [0x83, 0xC4, 0x08, 0x85, 0xC0];
    let result = rebuild(&bytes, 0x00400000, 0x10000000);

    assert_eq!(result.len(), bytes.len());
    assert_eq!(result, bytes);
}

#[test]
fn short_jnz_relocated() {
    let bytes = [0x75, 0x14];
    let result = rebuild(&bytes, 0x005DBA4E, 0x10000000);

    assert_eq!(result.len(), 6);
    assert_eq!(decode_mnemonic(&result), Some(Mnemonic::JNZ));
    assert_eq!(decode_branch_target(&result, 0x10000000), Some(0x005DBA64));
}

#[test]
fn short_jmp_relocated() {
    let bytes = [0xEB, 0x10];
    let result = rebuild(&bytes, 0x00401000, 0x20000000);

    assert_eq!(result.len(), 5);
    assert_eq!(decode_mnemonic(&result), Some(Mnemonic::JMP));
    assert_eq!(decode_branch_target(&result, 0x20000000), Some(0x00401012));
}

#[test]
fn near_call_relocated() {
    let bytes = [0xE8, 0xFB, 0x0F, 0x00, 0x00];
    let result = rebuild(&bytes, 0x00401000, 0x30000000);

    assert_eq!(result.len(), 5);
    assert_eq!(decode_mnemonic(&result), Some(Mnemonic::CALL));
    assert_eq!(decode_branch_target(&result, 0x30000000), Some(0x00402000));
}

#[test]
fn near_jmp_relocated() {
    let bytes = [0xE9, 0xFB, 0x0F, 0x00, 0x00];
    let result = rebuild(&bytes, 0x00401000, 0x40000000);

    assert_eq!(result.len(), 5);
    assert_eq!(decode_mnemonic(&result), Some(Mnemonic::JMP));
    assert_eq!(decode_branch_target(&result, 0x40000000), Some(0x00402000));
}

#[test]
fn mixed_instructions_with_jnz() {
    let bytes = [0x83, 0xC4, 0x08, 0x85, 0xC0, 0x75, 0x14];
    let result = rebuild(&bytes, 0x005DBA49, 0x10000000);

    assert!(result.len() >= 5);
    assert_eq!(&result[..5], &bytes[..5]);

    let jnz = &result[5..];
    assert_eq!(decode_mnemonic(jnz), Some(Mnemonic::JNZ));
    assert_eq!(decode_branch_target(jnz, 0x10000005), Some(0x005DBA64));
}

#[test]
fn short_jnz_stays_short_when_close() {
    let bytes = [0x75, 0x14];
    let result = rebuild(&bytes, 0x00401000, 0x00401100);

    assert_eq!(decode_mnemonic(&result), Some(Mnemonic::JNZ));
    assert_eq!(decode_branch_target(&result, 0x00401100), Some(0x00401016));
}

#[test]
fn near_jnz_relocated() {
    let bytes = [0x0F, 0x85, 0xFA, 0x0F, 0x00, 0x00];
    let result = rebuild(&bytes, 0x00401000, 0x50000000);

    assert_eq!(result.len(), 6);
    assert_eq!(decode_mnemonic(&result), Some(Mnemonic::JNZ));
    assert_eq!(decode_branch_target(&result, 0x50000000), Some(0x00402000));
}

#[test]
fn multiple_relative_instructions() {
    let bytes = [
        0xE8, 0xFB, 0x0F, 0x00, 0x00, 0x75, 0x08, 0xE9, 0xF4, 0xEF, 0xFF, 0xFF,
    ];
    let result = rebuild(&bytes, 0x00401000, 0x60000000);

    let expected_targets = [0x00402000, 0x0040100F, 0x00400000];
    let expected_mnemonics = [Mnemonic::CALL, Mnemonic::JNZ, Mnemonic::JMP];

    let mut offset = 0;
    for index in 0..3 {
        if offset >= result.len() {
            break;
        }

        let Some(instruction) = decode(&result[offset..]) else {
            panic!("decode failure");
        };

        assert_eq!(instruction.mnemonic, expected_mnemonics[index]);

        for operand in instruction.visible_operands() {
            if matches!(operand.kind, ffi::DecodedOperandKind::Imm(_)) {
                if let Ok(address) =
                    instruction.calc_absolute_address(0x60000000 + offset as u32 as u64, operand)
                {
                    assert_eq!(address as u32, expected_targets[index]);
                }
            }
        }

        offset += instruction.length as usize;
    }
}

#[test]
fn empty_input() {
    let result = rebuild(&[], 0x00400000, 0x10000000);
    assert!(result.is_empty());
}

#[test]
fn single_nop() {
    let bytes = [0x90];
    let result = rebuild(&bytes, 0x00400000, 0x10000000);

    assert_eq!(result.len(), 1);
    assert_eq!(result[0], 0x90);
}

#[test]
fn short_backward_jmp() {
    let bytes = [0xEB, 0xF0];
    let result = rebuild(&bytes, 0x00401010, 0x70000000);

    assert_eq!(decode_mnemonic(&result), Some(Mnemonic::JMP));
    assert_eq!(decode_branch_target(&result, 0x70000000), Some(0x00401002));
}

#[test]
fn various_short_jcc() {
    let jccs = [
        (0x74, Mnemonic::JZ),
        (0x75, Mnemonic::JNZ),
        (0x72, Mnemonic::JB),
        (0x73, Mnemonic::JNB),
        (0x76, Mnemonic::JBE),
        (0x77, Mnemonic::JNBE),
        (0x7C, Mnemonic::JL),
        (0x7D, Mnemonic::JNL),
        (0x7E, Mnemonic::JLE),
        (0x7F, Mnemonic::JNLE),
    ];

    for (opcode, mnemonic) in jccs {
        let bytes = [opcode, 0x20];
        let result = rebuild(&bytes, 0x00401000, 0x20000000);

        assert_eq!(decode_mnemonic(&result), Some(mnemonic));
        assert_eq!(decode_branch_target(&result, 0x20000000), Some(0x00401022));
    }
}

#[test]
fn intra_prologue_je_forward() {
    let bytes = [0x85, 0xC0, 0x74, 0x04, 0x83, 0xC4, 0x08, 0x90, 0x89, 0xE5];
    let result = rebuild(&bytes, 0x00401000, 0x10000000);

    let mut offset = 0;
    let mut je_target = None;
    let mut mov_addr = None;
    let mut index = 0;

    while offset < result.len() {
        let Some(instruction) = decode(&result[offset..]) else {
            break;
        };

        if instruction.mnemonic == Mnemonic::JZ {
            je_target = decode_branch_target(&result[offset..], 0x10000000 + offset as u32);
        }
        if instruction.mnemonic == Mnemonic::MOV && index > 0 {
            mov_addr = Some(0x10000000 + offset as u32);
        }

        offset += instruction.length as usize;
        index += 1;
    }

    assert!(je_target.is_some());
    assert!(mov_addr.is_some());
    assert_eq!(je_target, mov_addr);
    assert_ne!(je_target, Some(0x00401008));
}

#[test]
fn intra_prologue_jmp_backward() {
    let bytes = [0x90, 0x85, 0xC0, 0x83, 0xC4, 0x08, 0xEB, 0xF8];
    let result = rebuild(&bytes, 0x00401000, 0x20000000);

    let mut offset = 0;
    let mut jmp_target = None;

    while offset < result.len() {
        let Some(instruction) = decode(&result[offset..]) else {
            break;
        };

        if instruction.mnemonic == Mnemonic::JMP {
            jmp_target = decode_branch_target(&result[offset..], 0x20000000 + offset as u32);
        }

        offset += instruction.length as usize;
    }

    assert_eq!(jmp_target, Some(0x20000000));
    assert_ne!(jmp_target, Some(0x00401000));
}

#[test]
fn mixed_intra_and_external() {
    let bytes = [
        0xE8, 0xFB, 0x0F, 0x00, 0x00, 0x74, 0x03, 0x83, 0xC4, 0x08, 0x89, 0xE5,
    ];
    let result = rebuild(&bytes, 0x00401000, 0x30000000);

    let mut call_target = None;
    let mut je_target = None;
    let mut mov_addr = None;
    let mut offset = 0;
    let mut index = 0;

    while offset < result.len() {
        let Some(instruction) = decode(&result[offset..]) else {
            break;
        };

        if instruction.mnemonic == Mnemonic::CALL {
            call_target = decode_branch_target(&result[offset..], 0x30000000 + offset as u32);
        } else if instruction.mnemonic == Mnemonic::JZ {
            je_target = decode_branch_target(&result[offset..], 0x30000000 + offset as u32);
        } else if instruction.mnemonic == Mnemonic::MOV && index == 3 {
            mov_addr = Some(0x30000000 + offset as u32);
        }

        offset += instruction.length as usize;
        index += 1;
    }

    assert_eq!(call_target, Some(0x00402000));
    assert!(je_target.is_some());
    assert!(mov_addr.is_some());
    assert_eq!(je_target, mov_addr);
    assert_ne!(je_target, Some(0x0040100A));
}

#[test]
fn loop_external_target() {
    let bytes = [0xE2, 0xFE];
    let result = rebuild(&bytes, 0x00401000, 0x00401010);

    assert_eq!(result.len(), 2);
    assert_eq!(decode_mnemonic(&result), Some(Mnemonic::LOOP));
}

#[test]
fn loop_intra_prologue_does_not_corrupt_offsets() {
    let bytes = [0x90, 0x90, 0xE2, 0xFC, 0x89, 0xE5];
    let result = rebuild(&bytes, 0x00401000, 0x00401010);

    assert_eq!(result.len(), bytes.len());
    assert_eq!(result[result.len() - 2], 0x89);
    assert_eq!(result[result.len() - 1], 0xE5);
}

#[test]
fn jecxz_intra_prologue_not_remapped() {
    let bytes = [0x90, 0xE3, 0xFD, 0x89, 0xE5];
    let result = rebuild(&bytes, 0x00401000, 0x00401010);

    assert_eq!(result.len(), bytes.len());
    assert_eq!(decode_mnemonic(&result[1..]), Some(Mnemonic::JECXZ));
}

#[test]
fn short_jnz_forced_near() {
    let bytes = [0x75, 0x14];
    let result = rebuild(&bytes, 0x00401000, 0x00401100);

    assert_eq!(result.len(), 6);
    assert_eq!(decode_mnemonic(&result), Some(Mnemonic::JNZ));
    assert_eq!(decode_branch_target(&result, 0x00401100), Some(0x00401016));
}

#[test]
fn parses_own_executable_imports() {
    let exe = std::env::current_exe().expect("current exe path");
    let pe = crate::portable_executable::PortableExecutable::new(
        exe.to_str().expect("utf-8 executable path"),
    )
    .expect("parse own executable");

    assert!(!pe.imports().is_empty());
    let total_thunks: usize = pe.imports().iter().map(|import| import.thunks.len()).sum();
    assert!(total_thunks > 0 && total_thunks < 10_000);
}
