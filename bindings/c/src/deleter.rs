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
use std::ffi::c_void;
use std::os::raw::c_char;

use super::*;

/// TODO
#[repr(C)]
pub struct opendal_deleter {
    /// The pointer to the opendal::BlockingDeleter in the Rust code.
    /// Only touch this on judging whether it is NULL.
    inner: *mut c_void,
}

impl opendal_deleter {
    fn deref_mut(&mut self) -> &mut core::BlockingDeleter {
        // Safety: the inner should never be null once constructed
        // The use-after-free is undefined behavior
        unsafe { &mut *(self.inner as *mut core::BlockingDeleter) }
    }
}

impl opendal_deleter {
    pub(crate) fn new(deleter: core::BlockingDeleter) -> Self {
        Self {
            inner: Box::into_raw(Box::new(deleter)) as _,
        }
    }

    /// 将一个路径插入待删除列表
    #[no_mangle]
    pub unsafe extern "C" fn opendal_deleter_delete(
        &mut self,
        path: *const c_char,
    ) -> *mut opendal_error {
        let path = match c_char_to_str(path) {
            Ok(valid_str) => valid_str,
            Err(e) => {
                return e;
            }
        };

        match self.deref_mut().delete(path) {
            Ok(_) => std::ptr::null_mut(),
            Err(e) => opendal_error::new(e),
        }
    }

    /// 批量删除当前缓存的待删除对象
    #[no_mangle]
    pub unsafe extern "C" fn opendal_deleter_flush(&mut self) -> *mut opendal_error {
        match self.deref_mut().flush() {
            Ok(deleted) => {
                let cur_size = self.deref_mut().cur_size();
                if cur_size == 0 {
                    std::ptr::null_mut()
                } else {
                    opendal_error::new(
                        core::Error::new(
                            core::ErrorKind::Unexpected,
                            &format!(
                                "delete {} objects, but {} remained objects fail to delete",
                                deleted, cur_size
                            ),
                        )
                        .set_temporary(),
                    )
                }
            }
            Err(e) => opendal_error::new(e),
        }
    }

    /// \brief Free the heap-allocated metadata used by opendal_lister
    #[no_mangle]
    pub unsafe extern "C" fn opendal_deleter_free(ptr: *mut opendal_deleter) {
        if !ptr.is_null() {
            drop(Box::from_raw((*ptr).inner as *mut core::BlockingDeleter));
            drop(Box::from_raw(ptr));
        }
    }
}
