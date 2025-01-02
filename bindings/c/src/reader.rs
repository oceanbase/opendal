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

use std::ffi::c_void;
use bytes::Buf;

use ::opendal as core;

use super::*;

/// \brief The result type returned by opendal's reader operation.
///
/// \note The opendal_reader actually owns a pointer to
/// a opendal::BlockingReader, which is inside the Rust core code.
#[repr(C)]
pub struct opendal_reader {
    /// The pointer to the opendal::BlockingReader in the Rust code.
    /// Only touch this on judging whether it is NULL.
    inner: *mut c_void,
}

impl opendal_reader {
    fn deref_mut(&mut self) -> &mut core::BlockingReader {
        // Safety: the inner should never be null once constructed
        // The use-after-free is undefined behavior
        unsafe { &mut *(self.inner as *mut core::BlockingReader) }
    }
}

impl opendal_reader {
    pub(crate) fn new(reader: core::BlockingReader) -> Self {
        Self {
            inner: Box::into_raw(Box::new(reader)) as _,
        }
    }

    /// \brief Read data from the reader.
    #[no_mangle]
    pub unsafe extern "C" fn opendal_reader_read(
        &mut self,
        buf: *mut u8,
        len: usize,
        offset: usize,
    ) -> opendal_result_reader_read {
        if buf.is_null() || len == 0 || offset == 0 {
            return opendal_result_reader_read {
                size: 0,
                error: opendal_error::new(
                    core::Error::new(core::ErrorKind::ConfigInvalid, "invalid args"),
                ),
            };
        }

        let range = (offset as u64)..((offset + len) as u64);
        match self.deref_mut().read(range) {
            Ok(buffer) => {
                let read_len = buffer.len();
                if read_len > len {
                    return opendal_result_reader_read {
                        size: 0,
                        error: opendal_error::new(
                            core::Error::new(
                                core::ErrorKind::Unexpected, 
                                "returned data is larger than expected"
                            ),
                        ),
                    };
                }

                unsafe {
                    std::ptr::copy_nonoverlapping(buffer.chunk().as_ptr(), buf, read_len);
                }
                opendal_result_reader_read {
                    size: read_len,
                    error: std::ptr::null_mut(),
                }
            },
            Err(e) => opendal_result_reader_read {
                size: 0,
                error: opendal_error::new(
                    core::Error::new(core::ErrorKind::Unexpected, "read failed from reader")
                        .set_source(e),
                ),
            },
        }
    }

    /// \brief Frees the heap memory used by the opendal_reader.
    #[no_mangle]
    pub unsafe extern "C" fn opendal_reader_free(ptr: *mut opendal_reader) {
        if !ptr.is_null() {
            drop(Box::from_raw((*ptr).inner as *mut core::BlockingReader));
            drop(Box::from_raw(ptr));
        }
    }
}
