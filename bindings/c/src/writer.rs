// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

use ::opendal as core;
use std::{ffi::c_void, panic::catch_unwind, panic::AssertUnwindSafe};

use super::*;

/// \brief The result type returned by opendal's writer operation.
/// \note The opendal_writer actually owns a pointer to
/// an opendal::BlockingWriter, which is inside the Rust core code.
#[repr(C)]
pub struct opendal_writer {
    /// The pointer to the opendal::BlockingWriter in the Rust code.
    /// Only touch this on judging whether it is NULL.
    inner: *mut c_void,
}

impl opendal_writer {
    fn deref_mut(&mut self) -> &mut core::BlockingWriter {
        // Safety: the inner should never be null once constructed
        // The use-after-free is undefined behavior
        unsafe { &mut *(self.inner as *mut core::BlockingWriter) }
    }
}

impl opendal_writer {
    pub(crate) fn new(writer: core::BlockingWriter) -> Self {
        Self {
            inner: Box::into_raw(Box::new(writer)) as _,
        }
    }

    /// \brief Write data to the writer.
    #[no_mangle]
    pub unsafe extern "C" fn opendal_writer_write(
        &mut self,
        bytes: &opendal_bytes,
    ) -> opendal_result_writer_write {
        let ret = catch_unwind(AssertUnwindSafe(|| {
            let size = bytes.len;
            // Since the write method will consume the buffer, and the buffer passed 
            // in from outside needs to be released externally, in order to adhere to 
            // the principle of "who allocates, releases," it is necessary to copy the 
            // contents of bytes here.
            let copy_bytes = std::slice::from_raw_parts(bytes.data, bytes.len).to_vec();
            match self.deref_mut().write(copy_bytes) {
                Ok(()) => opendal_result_writer_write {
                    size,
                    error: std::ptr::null_mut(),
                },
                Err(e) => opendal_result_writer_write {
                    size: 0,
                    error: opendal_error::new(
                        core::Error::new(core::ErrorKind::Unexpected, "write failed from writer")
                            .set_source(e),
                    ),
                },
            }
        }));
        match handle_result(ret) {
            Ok(ret) => ret,
            Err(error) => opendal_result_writer_write {
                size: 0,
                error,
            }
        }
    }

    /// \brief Write data to the writer with the offset.
    #[no_mangle]
    pub unsafe extern "C" fn opendal_writer_write_with_offset(
        &mut self,
        offset: u64,
        bytes: &opendal_bytes,
    ) -> opendal_result_writer_write {
        let ret = catch_unwind(AssertUnwindSafe(|| {
            let size = bytes.len;
            // Since the write method will consume the buffer, and the buffer passed 
            // in from outside needs to be released externally, in order to adhere to 
            // the principle of "who allocates, releases," it is necessary to copy the 
            // contents of bytes here.
            let copy_bytes = std::slice::from_raw_parts(bytes.data, bytes.len).to_vec();
            match self.deref_mut().write_with_offset(offset, copy_bytes) {
                Ok(()) => opendal_result_writer_write {
                    size,
                    error: std::ptr::null_mut(),
                },
                Err(e) => opendal_result_writer_write {
                    size: 0,
                    error: opendal_error::new(
                        core::Error::new(core::ErrorKind::Unexpected, "write_with_offset failed from writer")
                            .set_source(e),
                    ),
                },
            }
        }));
        match handle_result(ret) {
            Ok(ret) => ret,
            Err(error) => opendal_result_writer_write {
                size: 0,
                error,
            }
        }
    }


    /// \brief Abort the pending writer.
    #[no_mangle]
    pub unsafe extern "C" fn opendal_writer_abort(&mut self) -> *mut opendal_error {
        let ret = catch_unwind(AssertUnwindSafe(|| {
            match self.deref_mut().abort() {
                Ok(_) => std::ptr::null_mut(),
                Err(e) => opendal_error::new(e),
            }
        }));
        match handle_result(ret) {
            Ok(ret) => ret,
            Err(error) => error, 
        }
    }

    /// \brief close the writer.
    #[no_mangle]
    pub unsafe extern "C" fn opendal_writer_close(&mut self) -> *mut opendal_error {
        let ret = catch_unwind(AssertUnwindSafe(|| {
            match self.deref_mut().close() {
                Ok(_) => std::ptr::null_mut(),
                Err(e) => opendal_error::new(e),
            }
        }));
        match handle_result(ret) {
            Ok(ret) => ret,
            Err(error) => error, 
        }
    }

    /// \brief Frees the heap memory used by the opendal_writer.
    /// \note This function make sure all data have been stored.
    #[no_mangle]
    pub unsafe extern "C" fn opendal_writer_free(ptr: *mut opendal_writer) {
        let ret = catch_unwind(|| {
            if !ptr.is_null() {
                drop(Box::from_raw((*ptr).inner as *mut core::BlockingWriter));
                drop(Box::from_raw(ptr));
            }
        });
        handle_result_without_ret(ret);
    }
}
