use binaryninja::{
    backgroundtask::BackgroundTask,
    binaryview::{BinaryView, BinaryViewBase, BinaryViewExt},
    command::{
        register, register_for_address, register_for_function, register_for_range, AddressCommand,
        Command, FunctionCommand, RangeCommand,
    },
    function::Function,
    interaction::get_text_line_input,
    logger::Logger,
};

mod sig;

pub const MAX_LEN: usize = 128;
pub const MAX_SIGS_AT_ONCE: usize = 10;
pub const MAX_INSN_SIZE: usize = 16;

struct FunctionSigMakerCommand;

impl FunctionCommand for FunctionSigMakerCommand {
    fn action(&self, view: &BinaryView, func: &Function) {
        let tries = sig::get_function_tries(view, func);
        let binary = sig::binary(&view);
        let bv = view.to_owned();
        let start = func.start();
        std::thread::spawn(move || {
            let task = BackgroundTask::new("Creating signature...", false).unwrap();
            log::info!("========== Signatures for function 0x{:x}", start);
            let mut done = 0;

            for try_addr in tries {
                let sig = sig::create_until_unique(&bv, &binary, try_addr);
                if let Some(sig) = sig {
                    log::info!("{}", sig);
                    done += 1;
                }

                if done >= MAX_SIGS_AT_ONCE {
                    break;
                }
            }
            log::info!("==========");
            task.finish();
        });
    }

    fn valid(&self, _: &BinaryView, _: &Function) -> bool {
        true
    }
}

struct AddressSigMakerCommand;

impl AddressCommand for AddressSigMakerCommand {
    fn action(&self, bv: &BinaryView, addr: u64) {
        let tries = sig::get_address_tries(bv, addr);
        let binary = sig::binary(bv);
        let bv = bv.to_owned();
        std::thread::spawn(move || {
            let task = BackgroundTask::new("Creating signature...", false).unwrap();
            log::info!("========== Signatures for address 0x{:x}", addr);
            let mut done = 0;

            for try_addr in tries {
                let sig = sig::create_until_unique(&bv, &binary, try_addr);
                if let Some(sig) = sig {
                    log::info!("{}", sig);
                    done += 1;
                }

                if done >= MAX_SIGS_AT_ONCE {
                    break;
                }
            }
            log::info!("==========");
            task.finish();
        });
    }

    fn valid(&self, view: &BinaryView, addr: u64) -> bool {
        !view.get_code_refs(addr).is_empty()
    }
}

struct RangeSigMakerCommand;

impl RangeCommand for RangeSigMakerCommand {
    fn action(&self, view: &BinaryView, range: std::ops::Range<u64>) {
        let sig = sig::create_for_range(view, range);
        if let Some(sig) = sig {
            log::info!("{}", sig);
        } else {
            log::error!("failed to create signature for range");
        }
    }

    fn valid(&self, view: &BinaryView, range: std::ops::Range<u64>) -> bool {
        range.clone().all(|addr| view.offset_readable(addr))
    }
}

struct SigScannerCommand;

impl Command for SigScannerCommand {
    fn action(&self, view: &BinaryView) {
        let sig = get_text_line_input("Enter signature to scan for", "Signature");
        if sig.is_none() {
            return;
        }
        let sig = sig::parse(sig.unwrap().trim());
        if sig.is_err() {
            log::error!("Failed to parse signature: {:?}", sig.err());
            return;
        }
        let sig = sig.unwrap();

        let bv = view.to_owned();
        let binary = sig::binary(&bv);
        let task = BackgroundTask::new("Scanning for signature...", false).unwrap();
        log::info!("========== Scan results for {}", sig);
        sig::scan_in_binary(&binary, &bv, &sig, true, MAX_SIGS_AT_ONCE);
        log::info!("==========");
        task.finish();
    }

    fn valid(&self, _: &BinaryView) -> bool {
        true
    }
}

#[no_mangle]
#[allow(non_snake_case)]
pub extern "C" fn CorePluginInit() -> bool {
    Logger::new("searchlight").init();

    register_for_function(
        "searchlight\\Create signature for function",
        "Create signature for a given function",
        FunctionSigMakerCommand,
    );

    register_for_address(
        "searchlight\\Create signature for address",
        "Create signature for a static address",
        AddressSigMakerCommand,
    );

    register_for_range(
        "searchlight\\Create signature for range",
        "Create signature for a given range",
        RangeSigMakerCommand,
    );

    register(
        "searchlight\\Scan for signature",
        "Scan for signatures in the binary",
        SigScannerCommand,
    );

    true
}
