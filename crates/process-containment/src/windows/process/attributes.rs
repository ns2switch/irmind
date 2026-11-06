#![cfg(windows)]
use super::{Identity, error, pipes::Pipes};
use std::{io, ptr};
use windows_sys::Win32::System::WindowsProgramming::PROCESS_CREATION_CHILD_PROCESS_RESTRICTED;
use windows_sys::Win32::{
    Foundation::HANDLE,
    Security::SECURITY_CAPABILITIES,
    System::Threading::{
        DeleteProcThreadAttributeList, InitializeProcThreadAttributeList,
        LPPROC_THREAD_ATTRIBUTE_LIST, PROC_THREAD_ATTRIBUTE_CHILD_PROCESS_POLICY,
        PROC_THREAD_ATTRIBUTE_HANDLE_LIST, PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
        UpdateProcThreadAttribute,
    },
};
#[repr(align(16))]
#[derive(Clone, Copy)]
struct Block {
    _bytes: [u8; 16],
}
pub(super) struct Attributes {
    storage: Vec<Block>,
    handles: Vec<HANDLE>,
    capabilities: Box<SECURITY_CAPABILITIES>,
    policy: Box<u32>,
}
impl Attributes {
    pub(super) fn new(identity: &Identity, pipes: &Pipes) -> io::Result<Self> {
        let mut size = 0;
        // SAFETY: null list is the documented size query; the output pointer is valid.
        unsafe { InitializeProcThreadAttributeList(ptr::null_mut(), 3, 0, &raw mut size) };
        if size == 0 || size > 65536 {
            return Err(error("attribute-size"));
        }
        let mut storage = vec![Block { _bytes: [0; 16] }; size.div_ceil(16)];
        // SAFETY: aligned initialized allocation contains at least size bytes.
        if unsafe {
            InitializeProcThreadAttributeList(storage.as_mut_ptr().cast(), 3, 0, &raw mut size)
        } == 0
        {
            return Err(error("attribute-initialization"));
        }
        let mut out = Self {
            storage,
            handles: vec![
                pipes.input.raw(),
                pipes.output_write.raw(),
                pipes.error_write.raw(),
            ],
            capabilities: Box::new(SECURITY_CAPABILITIES {
                AppContainerSid: identity.raw(),
                Capabilities: ptr::null_mut(),
                CapabilityCount: 0,
                Reserved: 0,
            }),
            policy: Box::new(PROCESS_CREATION_CHILD_PROCESS_RESTRICTED),
        };
        let handles = out.handles.as_ptr().cast();
        let caps = (&raw const *out.capabilities).cast();
        let policy = (&raw const *out.policy).cast();
        let handle_size = out.handles.len() * std::mem::size_of::<HANDLE>();
        out.update(PROC_THREAD_ATTRIBUTE_HANDLE_LIST, handles, handle_size)?;
        out.update(
            PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
            caps,
            std::mem::size_of::<SECURITY_CAPABILITIES>(),
        )?;
        out.update(
            PROC_THREAD_ATTRIBUTE_CHILD_PROCESS_POLICY,
            policy,
            std::mem::size_of::<u32>(),
        )?;
        Ok(out)
    }
    fn update(
        &mut self,
        attribute: u32,
        value: *const std::ffi::c_void,
        size: usize,
    ) -> io::Result<()> {
        // SAFETY: attribute determines the matching initialized buffer/size supplied only by new; all buffers remain stable and live through process creation.
        if unsafe {
            UpdateProcThreadAttribute(
                self.raw(),
                0,
                attribute as usize,
                value,
                size,
                ptr::null_mut(),
                ptr::null(),
            )
        } == 0
        {
            return Err(error("attribute-update"));
        }
        Ok(())
    }
    pub(super) fn raw(&mut self) -> LPPROC_THREAD_ATTRIBUTE_LIST {
        self.storage.as_mut_ptr().cast()
    }
}
impl Drop for Attributes {
    fn drop(&mut self) {
        // SAFETY: storage contains one successfully initialized attribute list; referenced owned buffers remain live during this call.
        unsafe { DeleteProcThreadAttributeList(self.raw()) };
    }
}
