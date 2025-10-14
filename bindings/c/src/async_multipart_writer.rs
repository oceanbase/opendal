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

use super::*;
use ::opendal as core;
use crate::common::*;

/// \brief Used to write a multipart file asynchronously.
#[repr(C)]
pub struct opendal_async_multipart_writer {
    inner: *mut c_void,
    tenant_id: u64,
}

impl opendal_async_multipart_writer {
    fn deref_mut(&mut self) -> &mut core::ObMultipartWriter {
        unsafe { &mut *(self.inner as *mut core::ObMultipartWriter) }
    }

    /// doc placeholder
    #[no_mangle]
    pub unsafe extern "C" fn opendal_async_multipart_writer_free(
        ptr: *mut opendal_async_multipart_writer,
    ) {
        obdal_catch_unwind(|| {
            if !ptr.is_null() {
                drop(Box::from_raw((*ptr).inner as *mut core::ObMultipartWriter));
                drop(Box::from_raw(ptr));
            }
        }).map_or_else(|err| {
            tracing::error!("{:?}", err);
        }, |_| ());
    }
}

fn deref_mut_from_inner<'a>(inner: *mut c_void) -> &'a mut core::ObMultipartWriter {
    unsafe { &mut *(inner as *mut core::ObMultipartWriter) }
}

impl opendal_async_multipart_writer {
    pub(crate) fn new(multipart_writer: core::ObMultipartWriter, tenant_id: u64) -> Self {
        Self {
            inner: Box::into_raw(Box::new(multipart_writer)) as _,
            tenant_id,
        }
    }

    /// doc placeholder
    #[no_mangle]
    pub unsafe extern "C" fn opendal_async_multipart_writer_initiate(
        &mut self,
    ) -> *mut opendal_error {
        let tenant_id = self.tenant_id;
        obdal_catch_unwind(|| {
            match obdal_block_on(self.deref_mut().initiate_part(), tenant_id) {
                Ok(_) => std::ptr::null_mut(),
                Err(e) => opendal_error::new(e),
            }
        }).map_or_else(|err| err, |ret| ret)
    }

    /// Noticed that this function will be called in multiple threads from oceanbase.
    /// so we maintain mutex in type::ob_multipart_writer::ObMultipartWriter.
    /// then we can clone the self.inner to avoid rust borrow checker.
    #[no_mangle]
    pub unsafe extern "C" fn opendal_async_multipart_writer_write(
        &mut self,
        bytes: &opendal_bytes,
        part_id: usize,
        callback: OpenDalAsyncCallbackFn,
        ctx: *mut c_void,
    ) {
        let _ = obdal_catch_unwind(|| {
            let _guard = ThreadTenantIdGuard::new(self.tenant_id);

            let inner_clone = self.inner.clone() as usize;
            let size = bytes.len as i64;
            let copy_bytes = std::slice::from_raw_parts(bytes.data, bytes.len).to_vec();
            let ctx_clone = ctx as usize;
            obdal_spawn(async move {
                let write = deref_mut_from_inner(inner_clone as *mut c_void);
                let ret = write.write_with_part_id(copy_bytes, part_id).await;
                match ret {
                    Ok(()) => {
                        tokio::task::spawn_blocking(move || {
                            callback(std::ptr::null_mut(), size, ctx_clone as *mut c_void);
                        });
                    }
                    Err(e) => {
                        tokio::task::spawn_blocking(move || {
                            callback(opendal_error::new(e), size, ctx_clone as *mut c_void);
                        });
                    }
                }
            }, self.tenant_id);
        }).map_err(|e| {
            callback(e, 0, ctx);
        });
    }

    /// doc placeholder
    #[no_mangle]
    pub unsafe extern "C" fn opendal_async_multipart_writer_abort(
        &mut self,
    ) -> *mut opendal_error {
        let tenant_id = self.tenant_id;
        obdal_catch_unwind(|| {
            match obdal_block_on(self.deref_mut().abort(), tenant_id) {
                Ok(_) => std::ptr::null_mut(),
                Err(e) => opendal_error::new(e),
            }
        }).map_or_else(|err| err, |ret| ret)
    }

    /// doc placeholder
    #[no_mangle]
    pub unsafe extern "C" fn opendal_async_multipart_writer_close(
        &mut self,
    ) -> *mut opendal_error {
        let tenant_id = self.tenant_id;
        obdal_catch_unwind(|| {
            match obdal_block_on(self.deref_mut().close(), tenant_id) {
                Ok(_) => std::ptr::null_mut(),
                Err(e) => opendal_error::new(e),
            }
        }).map_or_else(|err| err, |ret| ret)
    }
}
