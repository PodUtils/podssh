//! The way to a TPM on Windows: the TPM Base Services (TBS, tbs.dll),
//! which share the TPM between programs as Linux's resource manager does:
//! the handles of a context are its own, and go when it closes. podssh
//! loads tbs.dll at run time, which is the probe, as it loads webauthn.dll
//! for a security key: a Windows without it still runs podssh. windows-sys
//! gives the types; no C is compiled.
//!
//! The probe asks TBS which TPM it has (`Tbsi_GetDeviceInfo`): none, or one
//! of version 1.2, is refused in one line that starts "no TPM: ". Each
//! command runs on a thread of its own for [`COMMAND_LIMIT`]; past it, it
//! is cancelled (`Tbsip_Cancel_Commands`), and the context takes no more.

use std::ffi::c_void;
use std::path::Path;
use std::sync::{Arc, OnceLock};

use windows_sys::Win32::Foundation::HMODULE;
use windows_sys::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryExW, LOAD_LIBRARY_SEARCH_SYSTEM32};
use windows_sys::Win32::System::TpmBaseServices::{
    TBS_COMMAND_LOCALITY_ZERO, TBS_COMMAND_PRIORITY_NORMAL, TBS_CONTEXT_PARAMS, TBS_CONTEXT_PARAMS2,
    TBS_CONTEXT_PARAMS2_0, TBS_CONTEXT_VERSION_TWO, TBS_SUCCESS, TPM_DEVICE_INFO, TPM_VERSION_20,
};

use super::flow::Transport;
use super::tbs;
use super::wire::{HEADER, MAX_MESSAGE};
use super::COMMAND_LIMIT;

/// The functions of tbs.dll that podssh calls, as the Windows SDK's tbs.h
/// declares them (and windows-sys after it).
type Symbol = unsafe extern "system" fn() -> isize;
type ContextCreate = unsafe extern "system" fn(*const TBS_CONTEXT_PARAMS, *mut *mut c_void) -> u32;
type SubmitCommand = unsafe extern "system" fn(*const c_void, u32, u32, *const u8, u32, *mut u8, *mut u32) -> u32;
type ContextClose = unsafe extern "system" fn(*const c_void) -> u32;
type CancelCommands = unsafe extern "system" fn(*const c_void) -> u32;
type GetDeviceInfo = unsafe extern "system" fn(u32, *mut c_void) -> u32;

/// `includeTpm20`, the third bit of `TBS_CONTEXT_PARAMS2`'s field (tbs.h):
/// a context of the TPM 2.0.
const INCLUDE_TPM20: u32 = 1 << 2;

/// The functions of tbs.dll. The library stays loaded for the life of the
/// process: a context may outlive any one caller.
struct Api {
    create: ContextCreate,
    submit: SubmitCommand,
    close: ContextClose,
    cancel: CancelCommands,
    info: GetDeviceInfo,
}

/// tbs.dll, loaded once, or why not.
fn api() -> Result<&'static Api, String> {
    static API: OnceLock<Result<Api, String>> = OnceLock::new();
    API.get_or_init(load).as_ref().map_err(Clone::clone)
}

fn load() -> Result<Api, String> {
    let name: Vec<u16> = "tbs.dll".encode_utf16().chain(Some(0)).collect();
    // SAFETY: a name that ends in NUL. Only System32 is searched, so no file
    // of the working directory or of PATH is loaded.
    let module = unsafe { LoadLibraryExW(name.as_ptr(), std::ptr::null_mut(), LOAD_LIBRARY_SEARCH_SYSTEM32) };
    if module.is_null() {
        return Err("no TPM: this Windows has no TPM Base Services (tbs.dll)".into());
    }
    functions(module).ok_or_else(|| "no TPM: tbs.dll lacks a function of the TPM Base Services".into())
}

/// The functions of `module`, or `None` when one is missing.
fn functions(module: HMODULE) -> Option<Api> {
    let symbol = |name: &[u8]| -> Option<Symbol> {
        // SAFETY: a loaded module, and a name that ends in NUL.
        unsafe { GetProcAddress(module, name.as_ptr()) }
    };
    // SAFETY: each pointer is the function of that name in tbs.dll, of the
    // type that tbs.h declares for it.
    unsafe {
        Some(Api {
            create: std::mem::transmute::<Symbol, ContextCreate>(symbol(b"Tbsi_Context_Create\0")?),
            submit: std::mem::transmute::<Symbol, SubmitCommand>(symbol(b"Tbsip_Submit_Command\0")?),
            close: std::mem::transmute::<Symbol, ContextClose>(symbol(b"Tbsip_Context_Close\0")?),
            cancel: std::mem::transmute::<Symbol, CancelCommands>(symbol(b"Tbsip_Cancel_Commands\0")?),
            info: std::mem::transmute::<Symbol, GetDeviceInfo>(symbol(b"Tbsi_GetDeviceInfo\0")?),
        })
    }
}

/// Where the TPM is: Windows' TPM Base Services, of which there is one.
#[derive(Debug, Clone)]
pub(super) struct Place;

impl Place {
    pub fn describe(&self) -> String {
        "Windows' TPM Base Services".into()
    }
}

/// The TPM 2.0 of TBS. A device or a socket named (`-O device=`,
/// `PODSSH_TPM_DEVICE`) is refused: TBS is the one way on Windows.
pub(super) fn find(named: Option<&Path>) -> Result<Place, String> {
    if let Some(path) = named {
        return Err(format!(
            "no TPM: on Windows podssh reaches the TPM through the TPM Base Services, not through {}",
            path.display()
        ));
    }
    let api = api()?;
    let mut info = TPM_DEVICE_INFO::default();
    // SAFETY: a TPM_DEVICE_INFO of this function, and its size.
    let code = unsafe { (api.info)(std::mem::size_of::<TPM_DEVICE_INFO>() as u32, (&raw mut info).cast()) };
    if code != TBS_SUCCESS {
        return Err(tbs::no_tpm(code));
    }
    if info.tpmVersion != TPM_VERSION_20 {
        return Err(format!(
            "no TPM: this host's TPM is not of version 2.0 (TBS says version {}), and podssh's keys need 2.0",
            info.tpmVersion
        ));
    }
    Ok(Place)
}

/// A context of TBS for the TPM 2.0.
pub(super) fn open(_place: &Place) -> Result<Box<dyn Transport>, String> {
    let api = api()?;
    let params = TBS_CONTEXT_PARAMS2 {
        version: TBS_CONTEXT_VERSION_TWO,
        Anonymous: TBS_CONTEXT_PARAMS2_0 { asUINT32: INCLUDE_TPM20 },
    };
    let mut handle: *mut c_void = std::ptr::null_mut();
    // SAFETY: parameters of version two, as their version says, which TBS
    // reads through the pointer of version one; and a place for the handle.
    let code = unsafe { (api.create)((&raw const params).cast::<TBS_CONTEXT_PARAMS>(), &raw mut handle) };
    if code != TBS_SUCCESS || handle.is_null() {
        return Err(tbs::no_tpm(code));
    }
    Ok(Box::new(Tbs { context: Arc::new(Context { handle, api }), broken: false }))
}

/// A context of TBS, closed when the last of its users drops it: the
/// transport, or the thread of a command that has not ended.
struct Context {
    handle: *mut c_void,
    api: &'static Api,
}

// SAFETY: a handle of TBS may be used from any thread; TBS orders the
// commands of a context, and `Tbsip_Cancel_Commands` is meant to be called
// from a thread other than the one that waits.
unsafe impl Send for Context {}
unsafe impl Sync for Context {}

impl Context {
    /// One command, and its whole response.
    fn submit(&self, command: &[u8]) -> Result<Vec<u8>, String> {
        let mut answer = vec![0u8; MAX_MESSAGE];
        let mut length = answer.len() as u32;
        // SAFETY: an open context; the command and the buffer live through
        // the call, and `length` is the buffer's size.
        let code = unsafe {
            (self.api.submit)(
                self.handle,
                TBS_COMMAND_LOCALITY_ZERO,
                TBS_COMMAND_PRIORITY_NORMAL,
                command.as_ptr(),
                command.len() as u32,
                answer.as_mut_ptr(),
                &mut length,
            )
        };
        if code != TBS_SUCCESS {
            return Err(format!("the TPM Base Services did not pass the command: {}", tbs::words(code)));
        }
        let length = length as usize;
        if !(HEADER..=answer.len()).contains(&length) {
            return Err(format!("the TPM's answer has {length} bytes, which no answer has"));
        }
        answer.truncate(length);
        Ok(answer)
    }

    fn cancel(&self) {
        // SAFETY: an open context; a cancel with no command waiting does
        // nothing.
        unsafe { (self.api.cancel)(self.handle) };
    }
}

impl Drop for Context {
    fn drop(&mut self) {
        // SAFETY: the context that Tbsi_Context_Create gave, closed once.
        unsafe { (self.api.close)(self.handle) };
    }
}

/// The transport of a context: each command bounded; after one that did
/// not end, the context takes no more, as its state is not known.
struct Tbs {
    context: Arc<Context>,
    broken: bool,
}

impl Transport for Tbs {
    fn transact(&mut self, command: &[u8]) -> Result<Vec<u8>, String> {
        if self.broken {
            return Err("the TPM's context ended with a command that did not answer".into());
        }
        if command.len() > MAX_MESSAGE {
            return Err(format!("a command of {} bytes, more than a TPM takes", command.len()));
        }
        let (context, cancelling) = (self.context.clone(), self.context.clone());
        let command = command.to_vec();
        let answered =
            tbs::bounded(COMMAND_LIMIT, tbs::GRACE, move || context.submit(&command), move || cancelling.cancel());
        match answered {
            Ok(answer) => answer,
            Err(why) => {
                self.broken = true;
                Err(why)
            }
        }
    }
}
