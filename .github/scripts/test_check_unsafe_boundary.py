#!/usr/bin/env python3
import unittest
from pathlib import Path
from check_unsafe_boundary import inspect,unsafe_offsets

class Boundary(unittest.TestCase):
    def test_keywords_are_rejected_in_every_other_workspace(self):
        for source in ('unsafe { call() }','unsafe fn f() {}','unsafe impl Send for X {}','#[unsafe(no_mangle)] fn f() {}'):
            for path in ('crates/app/src/x.rs','helpers/evtx/src/lib.rs','fuzz/fuzz_targets/x.rs','crates/process-containment/src/linux.rs','crates/native-approval/src/lib.rs','crates/native-approval/src/unreviewed.rs'):
                self.assertTrue(inspect(Path(path),source))
    def test_windows_cfg_is_required_even_inside_the_boundary(self):
        path=Path('crates/process-containment/src/windows/process.rs')
        self.assertTrue(inspect(path,'unsafe { call() }'))
        self.assertFalse(inspect(path,'#![cfg(windows)]\n// SAFETY: checked owned handle\nunsafe { call() }'))
    def test_hello_requires_the_exact_approved_file_and_windows_cfg(self):
        path=Path('crates/native-approval/src/windows_hello.rs')
        self.assertTrue(inspect(path,'#![cfg(unix)]\nunsafe { call() }'))
        self.assertFalse(inspect(path,'#![cfg(windows)]\n// SAFETY: reviewed\nunsafe { call() }'))

    def test_touch_id_requires_the_exact_approved_file_and_macos_cfg(self):
        path=Path('crates/native-approval/src/touch_id.rs')
        self.assertTrue(inspect(path,'#![cfg(windows)]\nunsafe { call() }'))
        self.assertFalse(inspect(path,'#![cfg(target_os = "macos")]\n// SAFETY: reviewed\nunsafe { call() }'))

    def test_comments_strings_and_lifetimes_do_not_hide_real_code(self):
        source='''/* outer unsafe /* nested unsafe */ */
        let x = r###"unsafe { no() }"###;
        let y = "unsafe\\\" unsafe";
        let z = 'x'; fn f<'a>(v: &'a str) { unsafe { actual() } }
        // unsafe ignored
        '''
        self.assertEqual(len(unsafe_offsets(source)),1)
        self.assertFalse(unsafe_offsets('let x = "parameters are unsafe"; #![forbid(unsafe_code)]'))

if __name__=='__main__':unittest.main()
