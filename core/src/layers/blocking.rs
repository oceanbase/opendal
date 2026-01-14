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

use std::sync::Arc;
use std::future::Future;
use std::ffi::CString;

use tokio::runtime::Handle;
use tokio::task_local;

use std::time::Instant;

use crate::raw::*;
use crate::*;

/// Add blocking API support for non-blocking services.
///
/// # Notes
///
/// - Please only enable this layer when the underlying service does not support blocking.
///
/// # Examples
///
/// ## In async context
///
/// BlockingLayer will use current async context's runtime to handle the async calls.
///
/// ```rust,no_run
/// # use opendal::layers::BlockingLayer;
/// # use opendal::services;
/// # use opendal::BlockingOperator;
/// # use opendal::Operator;
/// # use opendal::Result;
///
/// #[tokio::main]
/// async fn main() -> Result<()> {
///     // Create fs backend builder.
///     let mut builder = services::S3::default().bucket("test").region("us-east-1");
///
///     // Build an `BlockingOperator` with blocking layer to start operating the storage.
///     let _: BlockingOperator = Operator::new(builder)?
///         .layer(BlockingLayer::create()?)
///         .finish()
///         .blocking();
///
///     Ok(())
/// }
/// ```
///
/// ## In async context with blocking functions
///
/// If `BlockingLayer` is called in blocking function, please fetch a [`tokio::runtime::EnterGuard`]
/// first. You can use [`Handle::try_current`] first to get the handle and then call [`Handle::enter`].
/// This often happens in the case that async function calls blocking function.
///
/// ```rust,no_run
/// # use opendal::layers::BlockingLayer;
/// # use opendal::services;
/// # use opendal::BlockingOperator;
/// # use opendal::Operator;
/// # use opendal::Result;
///
/// #[tokio::main]
/// async fn main() -> Result<()> {
///     let _ = blocking_fn()?;
///     Ok(())
/// }
///
/// fn blocking_fn() -> Result<BlockingOperator> {
///     // Create fs backend builder.
///     let mut builder = services::S3::default().bucket("test").region("us-east-1");
///
///     let handle = tokio::runtime::Handle::try_current().unwrap();
///     let _guard = handle.enter();
///     // Build an `BlockingOperator` with blocking layer to start operating the storage.
///     let op: BlockingOperator = Operator::new(builder)?
///         .layer(BlockingLayer::create()?)
///         .finish()
///         .blocking();
///     Ok(op)
/// }
/// ```
///
/// ## In blocking context
///
/// In a pure blocking context, we can create a runtime and use it to create the `BlockingLayer`.
///
/// > The following code uses a global statically created runtime as an example, please manage the
/// > runtime on demand.
///
/// ```rust,no_run
/// # use once_cell::sync::Lazy;
/// # use opendal::layers::BlockingLayer;
/// # use opendal::services;
/// # use opendal::BlockingOperator;
/// # use opendal::Operator;
/// # use opendal::Result;
///
/// static RUNTIME: Lazy<tokio::runtime::Runtime> = Lazy::new(|| {
///     tokio::runtime::Builder::new_multi_thread()
///         .enable_all()
///         .build()
///         .unwrap()
/// });
///
/// fn main() -> Result<()> {
///     // Create fs backend builder.
///     let mut builder = services::S3::default().bucket("test").region("us-east-1");
///
///     // Fetch the `EnterGuard` from global runtime.
///     let _guard = RUNTIME.enter();
///     // Build an `BlockingOperator` with blocking layer to start operating the storage.
///     let _: BlockingOperator = Operator::new(builder)?
///         .layer(BlockingLayer::create()?)
///         .finish()
///         .blocking();
///
///     Ok(())
/// }
/// ```
#[derive(Debug, Clone)]
pub struct BlockingLayer {
    handle: Handle,
    tenant_id: u64,
    trace_id: Option<CString>,
}

/// 500 is the default tenant id for oceanbase
pub const DEFAULT_TENANT_ID: u64 = 500;

task_local! {
    /// tls variable for oceanbase malloc
    /// oceanbase malloc will use this to get the tenant id
    pub static TENANT_ID: u64;
    
    /// tls variable for oceanbase trace id
    pub static TRACE_ID: Option<CString>;
}

impl BlockingLayer {
    /// Create a new `BlockingLayer` with the current runtime's handle
    pub fn create(tenant_id: Option<u64>) -> Result<Self> {
        Ok(Self {
            handle: Handle::try_current()
                .map_err(|_| Error::new(ErrorKind::Unexpected, "failed to get current handle"))?,
            tenant_id: tenant_id.unwrap_or(DEFAULT_TENANT_ID),
            trace_id: None,
        })
    }

    /// Set the trace id for the blocking layer
    pub fn with_trace_id(self, trace_id: CString) -> Self {
        Self {
            handle: self.handle,
            tenant_id: self.tenant_id,
            trace_id: Some(trace_id),
        }
    }
}

impl<A: Access> Layer<A> for BlockingLayer {
    type LayeredAccess = BlockingAccessor<A>;

    fn layer(&self, inner: A) -> Self::LayeredAccess {
        BlockingAccessor {
            inner,
            handle: self.handle.clone(),
            tenant_id: self.tenant_id,
            trace_id: self.trace_id.clone(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct BlockingAccessor<A: Access> {
    inner: A,

    handle: Handle,
    tenant_id: u64,
    trace_id: Option<CString>,
}


fn with_scope<F>(f: F, tenant_id: u64, trace_id: Option<CString>) -> impl Future<Output = F::Output>
where F: Future
{
    use crate::layers::retry::get_retry_timeout_from_ob;
    use crate::layers::retry::RETRY_TIMEOUT;
    use crate::layers::retry::TASK_START_TIME;
    let retry_timeout = get_retry_timeout_from_ob();
    let f = RETRY_TIMEOUT.scope(Some(retry_timeout), f);
    let f = TASK_START_TIME.scope(Some(Instant::now()), f);
    let f = TENANT_ID.scope(tenant_id, f);
    let f = TRACE_ID.scope(trace_id, f);
    f
}

impl<A: Access> BlockingAccessor<A> {
    // with a scope of task local variables
    // like tenant_id, retry_timeout, task_start_time
    fn with_scope<F>(&self, f: F) -> impl Future<Output = F::Output>
    where 
        F: Future
    {
        with_scope(f, self.tenant_id, self.trace_id.clone())
    }
}

impl<A: Access> LayeredAccess for BlockingAccessor<A> {
    type Inner = A;
    type Reader = A::Reader;
    type BlockingReader = BlockingWrapper<A::Reader>;
    type Writer = A::Writer;
    type BlockingWriter = BlockingWrapper<A::Writer>;
    type ObMultipartWriter = A::ObMultipartWriter;
    type BlockingObMultipartWriter = BlockingWrapper<A::ObMultipartWriter>;
    type Lister = A::Lister;
    type BlockingLister = BlockingWrapper<A::Lister>;
    type Deleter = A::Deleter;
    type BlockingDeleter = BlockingWrapper<A::Deleter>;

    fn inner(&self) -> &Self::Inner {
        &self.inner
    }

    fn info(&self) -> Arc<AccessorInfo> {
        let mut meta = self.inner.info().as_ref().clone();
        meta.full_capability_mut().blocking = true;
        meta.into()
    }

    async fn create_dir(&self, path: &str, args: OpCreateDir) -> Result<RpCreateDir> {
        self.with_scope(async move {
            self.inner.create_dir(path, args).await
        }).await
    }

    async fn read(&self, path: &str, args: OpRead) -> Result<(RpRead, Self::Reader)> {
        self.with_scope(async move {
            self.inner.read(path, args).await
        }).await
    }

    async fn write(&self, path: &str, args: OpWrite) -> Result<(RpWrite, Self::Writer)> {
        self.with_scope(async move {
            self.inner.write(path, args).await
        }).await
    }

    async fn ob_multipart_write(
        &self,
        path: &str,
        args: OpWrite,
    ) -> Result<(RpWrite, Self::ObMultipartWriter)> {
        self.with_scope(async move {
            self.inner.ob_multipart_write(path, args).await
        }).await
    }

    async fn copy(&self, from: &str, to: &str, args: OpCopy) -> Result<RpCopy> {
        self.with_scope(async move {
            self.inner.copy(from, to, args).await
        }).await
    }

    async fn rename(&self, from: &str, to: &str, args: OpRename) -> Result<RpRename> {
        self.with_scope(async move {
            self.inner.rename(from, to, args).await
        }).await
    }

    async fn stat(&self, path: &str, args: OpStat) -> Result<RpStat> {
        self.with_scope(async move {
            self.inner.stat(path, args).await
        }).await
    }

    async fn put_object_tagging(&self, path: &str, args: OpPutObjTag) -> Result<RpPutObjTag> {
        self.with_scope(async move {
            self.inner.put_object_tagging(path, args).await
        }).await
    }

    async fn get_object_tagging(&self, path: &str) -> Result<RpGetObjTag> {
        self.with_scope(async move {
            self.inner.get_object_tagging(path).await
        }).await
    }

    async fn delete(&self) -> Result<(RpDelete, Self::Deleter)> {
        self.with_scope(async move {
            self.inner.delete().await
        }).await
    }

    async fn list(&self, path: &str, args: OpList) -> Result<(RpList, Self::Lister)> {
        self.with_scope(async move {
            self.inner.list(path, args).await
        }).await
    }

    async fn presign(&self, path: &str, args: OpPresign) -> Result<RpPresign> {
        self.with_scope(async move {
            self.inner.presign(path, args).await
        }).await
    }

    fn blocking_create_dir(&self, path: &str, args: OpCreateDir) -> Result<RpCreateDir> {
        self.handle.block_on(self.with_scope(async move {
            self.inner.create_dir(path, args).await
        }))
    }

    fn blocking_read(&self, path: &str, args: OpRead) -> Result<(RpRead, Self::BlockingReader)> {
        self.handle.block_on(self.with_scope(async move {
            let (rp, reader) = self.inner.read(path, args).await?;
            let blocking_reader =
                Self::BlockingReader::new(self.handle.clone(), reader, self.tenant_id, self.trace_id.clone());
            Ok((rp, blocking_reader))
        }))
    }

    fn blocking_write(&self, path: &str, args: OpWrite) -> Result<(RpWrite, Self::BlockingWriter)> {
        self.handle.block_on(self.with_scope(async move {
            let (rp, writer) = self.inner.write(path, args).await?;
            let blocking_writer =
                Self::BlockingWriter::new(self.handle.clone(), writer, self.tenant_id, self.trace_id.clone());
            Ok((rp, blocking_writer))
        }))
    }

    fn blocking_ob_multipart_write(
        &self,
        path: &str,
        args: OpWrite,
    ) -> Result<(RpWrite, Self::BlockingObMultipartWriter)> {
        self.handle.block_on(self.with_scope(async move {
            let (rp, multipart_writer) = self.inner.ob_multipart_write(path, args).await?;
            let blocking_ob_multipart_writer = Self::BlockingObMultipartWriter::new(
                self.handle.clone(),
                multipart_writer,
                self.tenant_id,
                self.trace_id.clone(),
            );
            Ok((rp, blocking_ob_multipart_writer))
        }))
    }

    fn blocking_copy(&self, from: &str, to: &str, args: OpCopy) -> Result<RpCopy> {
        self.handle.block_on(self.with_scope(async move {
            self.inner.copy(from, to, args).await
        }))
    }

    fn blocking_rename(&self, from: &str, to: &str, args: OpRename) -> Result<RpRename> {
        self.handle.block_on(self.with_scope(async move {
            self.inner.rename(from, to, args).await
        }))
    }

    fn blocking_stat(&self, path: &str, args: OpStat) -> Result<RpStat> {
        self.handle.block_on(self.with_scope(async move {
            self.inner.stat(path, args).await
        }))
    }

    fn blocking_put_object_tagging(&self, path: &str, args: OpPutObjTag) -> Result<RpPutObjTag> {
        self.handle.block_on(self.with_scope(async move {
            self.inner.put_object_tagging(path, args).await
        }))
    }

    fn blocking_get_object_tagging(&self, path: &str) -> Result<RpGetObjTag> {
        self.handle.block_on(self.with_scope(async move {
            self.inner.get_object_tagging(path).await
        }))
    }

    fn blocking_delete(&self) -> Result<(RpDelete, Self::BlockingDeleter)> {
        self.handle.block_on(self.with_scope(async move {
            let (rp, deleter) = self.inner.delete().await?;
            let blocking_deleter =
                Self::BlockingDeleter::new(self.handle.clone(), deleter, self.tenant_id, self.trace_id.clone());
            Ok((rp, blocking_deleter))
        }))
    }

    fn blocking_list(&self, path: &str, args: OpList) -> Result<(RpList, Self::BlockingLister)> {
        self.handle.block_on(self.with_scope(async move {
            let (rp, lister) = self.inner.list(path, args).await?;
            let blocking_lister =
                Self::BlockingLister::new(self.handle.clone(), lister, self.tenant_id, self.trace_id.clone());
            Ok((rp, blocking_lister))
        }))
    }
}

pub struct BlockingWrapper<I> {
    handle: Handle,
    inner: I,
    tenant_id: u64,
    trace_id: Option<CString>,
}

impl<I> BlockingWrapper<I> {
    fn new(handle: Handle, inner: I, tenant_id: u64, trace_id: Option<CString>) -> Self {
        Self {
            handle,
            inner,
            tenant_id,
            trace_id,
        }
    }
}

impl<I: oio::Read + 'static> oio::BlockingRead for BlockingWrapper<I> {
    fn read(&mut self) -> Result<Buffer> {
        self.handle.block_on(with_scope(self.inner.read(), self.tenant_id, self.trace_id.clone()))
    }
}

impl<I: oio::Write + 'static> oio::BlockingWrite for BlockingWrapper<I> {
    fn write(&mut self, bs: Buffer) -> Result<()> {
        self.handle.block_on(with_scope(self.inner.write(bs), self.tenant_id, self.trace_id.clone()))
    }

    fn write_with_offset(&mut self, offset: u64, bs: Buffer) -> Result<()> {
        self.handle.block_on(with_scope(self.inner.write_with_offset(offset, bs), self.tenant_id, self.trace_id.clone()))
    }

    fn close(&mut self) -> Result<()> {
        self.handle.block_on(with_scope(self.inner.close(), self.tenant_id, self.trace_id.clone()))
    }

    fn abort(&mut self) -> Result<()> {
        self.handle.block_on(with_scope(self.inner.abort(), self.tenant_id, self.trace_id.clone()))
    }
}

impl<I: oio::ObMultipartWrite + 'static> oio::BlockingObMultipartWrite for BlockingWrapper<I> {
    fn initiate_part(&mut self) -> Result<()> {
        self.handle.block_on(with_scope(self.inner.initiate_part(), self.tenant_id, self.trace_id.clone()))
    }

    fn write_with_part_id(&mut self, bs: Buffer, part_id: usize) -> Result<oio::MultipartPart> {
        self.handle.block_on(with_scope(self.inner.write_with_part_id(bs, part_id), self.tenant_id, self.trace_id.clone()))
    }

    fn close(&mut self, parts: Vec<oio::MultipartPart>) -> Result<()> {
        self.handle.block_on(with_scope(self.inner.close(parts), self.tenant_id, self.trace_id.clone()))
    }

    fn abort(&mut self) -> Result<()> {
        self.handle.block_on(with_scope(self.inner.abort(), self.tenant_id, self.trace_id.clone()))
    }
}

impl<I: oio::List> oio::BlockingList for BlockingWrapper<I> {
    fn next(&mut self) -> Result<Option<oio::Entry>> {
        self.handle.block_on(with_scope(self.inner.next(), self.tenant_id, self.trace_id.clone()))
    }
}

impl<I: oio::Delete + 'static> oio::BlockingDelete for BlockingWrapper<I> {
    fn delete(&mut self, path: &str, args: OpDelete) -> Result<()> {
        self.handle.block_on(with_scope(async { self.inner.delete(path, args) }, self.tenant_id, self.trace_id.clone()))
    }

    fn flush(&mut self) -> Result<usize> {
        self.handle.block_on(with_scope(self.inner.flush(), self.tenant_id, self.trace_id.clone()))
    }

    fn deleted(&mut self, path: &str, args: OpDelete) -> Result<bool> {
        self.handle.block_on(with_scope(async { self.inner.deleted(path, args) }, self.tenant_id, self.trace_id.clone()))
    }
}

#[cfg(test)]
mod tests {
    use once_cell::sync::Lazy;

    use super::*;
    use crate::types::Result;

    static RUNTIME: Lazy<tokio::runtime::Runtime> = Lazy::new(|| {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap()
    });

    fn create_blocking_layer() -> Result<BlockingLayer> {
        let _guard = RUNTIME.enter();
        BlockingLayer::create(None)
    }

    #[test]
    fn test_blocking_layer_in_blocking_context() {
        // create in a blocking context should fail
        let layer = BlockingLayer::create(None);
        assert!(layer.is_err());

        // create in an async context and drop in a blocking context
        let layer = create_blocking_layer();
        assert!(layer.is_ok())
    }

    #[test]
    fn test_blocking_layer_in_async_context() {
        // create and drop in an async context
        let _guard = RUNTIME.enter();

        let layer = BlockingLayer::create(None);
        assert!(layer.is_ok());
    }
}
