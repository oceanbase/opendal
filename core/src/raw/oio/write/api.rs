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

use std::future::Future;
use std::ops::DerefMut;

use crate::raw::*;
use crate::*;

/// Writer is a type erased [`Write`]
pub type Writer = Box<dyn WriteDyn>;

/// Write is the trait that OpenDAL returns to callers.
pub trait Write: Unpin + Send + Sync {
    /// Write given bytes into writer.
    ///
    /// # Behavior
    ///
    /// - `Ok(())` means all bytes has been written successfully.
    /// - `Err(err)` means error happens and no bytes has been written.
    fn write(&mut self, bs: Buffer) -> impl Future<Output = Result<()>> + MaybeSend;

    /// Adapter function for OB append write, used solely to support services that offer append writing.
    fn write_with_offset(&mut self, offset: u64, bs: Buffer) -> impl Future<Output = Result<()>> + MaybeSend;

    /// Close the writer and make sure all data has been flushed.
    fn close(&mut self) -> impl Future<Output = Result<()>> + MaybeSend;

    /// Abort the pending writer.
    fn abort(&mut self) -> impl Future<Output = Result<()>> + MaybeSend;
}

impl Write for () {
    async fn write(&mut self, _: Buffer) -> Result<()> {
        unimplemented!("write is required to be implemented for oio::Write")
    }

    async fn write_with_offset(&mut self, _: u64, _: Buffer) -> Result<()> {
        Err(Error::new(
            ErrorKind::Unsupported,
            "output write doesn't support write_with_offset",
        ))
    }

    async fn close(&mut self) -> Result<()> {
        Err(Error::new(
            ErrorKind::Unsupported,
            "output writer doesn't support close",
        ))
    }

    async fn abort(&mut self) -> Result<()> {
        Err(Error::new(
            ErrorKind::Unsupported,
            "output writer doesn't support abort",
        ))
    }
}

pub trait WriteDyn: Unpin + Send + Sync {
    fn write_dyn(&mut self, bs: Buffer) -> BoxedFuture<Result<()>>;

    fn write_with_offset_dyn(&mut self, offset: u64, bs: Buffer) -> BoxedFuture<Result<()>>;

    fn close_dyn(&mut self) -> BoxedFuture<Result<()>>;

    fn abort_dyn(&mut self) -> BoxedFuture<Result<()>>;
}

impl<T: Write + ?Sized> WriteDyn for T {
    fn write_dyn(&mut self, bs: Buffer) -> BoxedFuture<Result<()>> {
        Box::pin(self.write(bs))
    }

    fn write_with_offset_dyn(&mut self, offset: u64, bs: Buffer) -> BoxedFuture<Result<()>> {
        Box::pin(self.write_with_offset(offset, bs))
    }

    fn close_dyn(&mut self) -> BoxedFuture<Result<()>> {
        Box::pin(self.close())
    }

    fn abort_dyn(&mut self) -> BoxedFuture<Result<()>> {
        Box::pin(self.abort())
    }
}

impl<T: WriteDyn + ?Sized> Write for Box<T> {
    async fn write(&mut self, bs: Buffer) -> Result<()> {
        self.deref_mut().write_dyn(bs).await
    }

    async fn write_with_offset(&mut self, offset: u64, bs: Buffer) -> Result<()> {
        self.deref_mut().write_with_offset_dyn(offset, bs).await
    }

    async fn close(&mut self) -> Result<()> {
        self.deref_mut().close_dyn().await
    }

    async fn abort(&mut self) -> Result<()> {
        self.deref_mut().abort_dyn().await
    }
}

/// BlockingWriter is a type erased [`BlockingWrite`]
pub type BlockingWriter = Box<dyn BlockingWrite>;

/// BlockingWrite is the trait that OpenDAL returns to callers.
pub trait BlockingWrite: Send + Sync + 'static {
    /// Write whole content at once.
    ///
    /// # Behavior
    ///
    /// - `Ok(n)` means `n` bytes has been written successfully.
    /// - `Err(err)` means error happens and no bytes has been written.
    ///
    /// It's possible that `n < bs.len()`, caller should pass the remaining bytes
    /// repeatedly until all bytes has been written.
    fn write(&mut self, bs: Buffer) -> Result<()>;

    /// Adapter function for OB append write, used solely to support services that offer append writing. 
    fn write_with_offset(&mut self, offset: u64, bs: Buffer) -> Result<()>;

    /// Close the writer and make sure all data has been flushed.
    fn close(&mut self) -> Result<()>;

    /// Abort the pending writer.
    fn abort(&mut self) -> Result<()> {
        Err(Error::new(
            ErrorKind::Unsupported,
            "output writer doesn't support abort",
        ))
    }
}

impl BlockingWrite for () {
    fn write(&mut self, bs: Buffer) -> Result<()> {
        let _ = bs;

        unimplemented!("write is required to be implemented for oio::BlockingWrite")
    }
     fn write_with_offset(&mut self, _: u64, _: Buffer) -> Result<()> {
        Err(Error::new(
            ErrorKind::Unsupported,
            "output writer doesn't support write with offset",
        )) 
     }

    fn close(&mut self) -> Result<()> {
        Err(Error::new(
            ErrorKind::Unsupported,
            "output writer doesn't support close",
        ))
    }
}

/// `Box<dyn BlockingWrite>` won't implement `BlockingWrite` automatically.
///
/// To make BlockingWriter work as expected, we must add this impl.
impl<T: BlockingWrite + ?Sized> BlockingWrite for Box<T> {
    fn write(&mut self, bs: Buffer) -> Result<()> {
        (**self).write(bs)
    }

    fn write_with_offset(&mut self, offset: u64, bs: Buffer) -> Result<()> {
       (**self).write_with_offset(offset, bs) 
    }

    fn close(&mut self) -> Result<()> {
        (**self).close()
    }
}

/// ObMultipartWriter is a type erased [`ObMutipartWrite`]
pub type ObMultipartWriter = Box<dyn ObMultipartWriteDyn>;

/// ObMultipartWrite is the trait that ObDal returns to callers.
pub trait ObMultipartWrite: Unpin + Send + Sync {
    ///
    fn initiate_part(&mut self) -> impl Future<Output = Result<()>> + MaybeSend;
    ///
    fn write_with_part_id(&mut self, bs: Buffer, part_id: usize) -> impl Future<Output = Result<()>> + MaybeSend;
    ///
    fn close(&mut self) -> impl Future<Output = Result<()>> + MaybeSend;
    ///
    fn abort(&mut self) -> impl Future<Output = Result<()>> + MaybeSend;
}

impl ObMultipartWrite for () {
    async fn initiate_part(&mut self) -> Result<()> {
        unimplemented!("initiate part is required to be implemented for oio::ObMutipartWrite")
    }

    async fn write_with_part_id(&mut self, _: Buffer, _: usize) -> Result<()> {
        unimplemented!("write_with_part_id is required to be implemented for oio::ObMutipartWrite")
    }

    async fn close(&mut self) -> Result<()> {
        Err(Error::new(
            ErrorKind::Unsupported,
            "output ObMultipartWriter doesn't support close",
        ))
    }

    async fn abort(&mut self) -> Result<()> {
        Err(Error::new(
            ErrorKind::Unsupported,
            "output ObMultipartWriter doesn't support abort",
        ))
    }
}

pub trait ObMultipartWriteDyn: Unpin + Send + Sync {
    fn initiate_part_dyn(&mut self) -> BoxedFuture<Result<()>>;

    fn write_with_part_id_dyn(&mut self, bs: Buffer, part_id: usize) -> BoxedFuture<Result<()>>;

    fn close_dyn(&mut self) -> BoxedFuture<Result<()>>;

    fn abort_dyn(&mut self) -> BoxedFuture<Result<()>>;
}

impl<T: ObMultipartWrite + ?Sized> ObMultipartWriteDyn for T {
    fn initiate_part_dyn(&mut self) -> BoxedFuture<Result<()>> {
        Box::pin(self.initiate_part())
    }

    fn write_with_part_id_dyn(&mut self, bs: Buffer, part_id: usize) -> BoxedFuture<Result<()>> {
        Box::pin(self.write_with_part_id(bs, part_id))
    }

    fn close_dyn(&mut self) -> BoxedFuture<Result<()>> {
        Box::pin(self.close())
    }

    fn abort_dyn(&mut self) -> BoxedFuture<Result<()>> {
        Box::pin(self.abort())
    }
}

impl<T: ObMultipartWriteDyn + ?Sized> ObMultipartWrite for Box<T> {
    async fn initiate_part(&mut self) -> Result<()> {
        self.deref_mut().initiate_part_dyn().await
    }

    async fn write_with_part_id(&mut self, bs: Buffer, part_id: usize) -> Result<()> {
        self.deref_mut().write_with_part_id_dyn(bs, part_id).await
    }

    async fn close(&mut self) -> Result<()> {
        self.deref_mut().close_dyn().await
    }

    async fn abort(&mut self) -> Result<()> {
        self.deref_mut().abort_dyn().await
    }
}

/// BlockingObMultipartWriter is a type erased [`BlockingObMultipartWrite`]
pub type BlockingObMultipartWriter = Box<dyn BlockingObMultipartWrite>;

/// BlockingObMultipartWrite is the trait that ObDAL returns to Callers.
pub trait BlockingObMultipartWrite: Send + Sync + 'static {
    ///
    fn initiate_part(&mut self) -> Result<()>;
    ///
    fn write_with_part_id(&mut self, bs: Buffer, part_id: usize) -> Result<()>;
    ///
    fn close(&mut self) -> Result<()>;
    ///
    fn abort(&mut self) -> Result<()>;
}

impl BlockingObMultipartWrite for () {
    fn initiate_part(&mut self) -> Result<()> {
        unimplemented!("initiate part is required to be implemented for oio::ObMutipartWrite")
    }

    fn write_with_part_id(&mut self, _: Buffer, _: usize) -> Result<()> {
        unimplemented!("write_with_part_id is required to be implemented for oio::ObMutipartWrite")
    }

    fn close(&mut self) -> Result<()> {
        Err(Error::new(
            ErrorKind::Unsupported,
            "output ObMultipartWriter doesn't support close",
        ))
    }

    fn abort(&mut self) -> Result<()> {
        Err(Error::new(
            ErrorKind::Unsupported,
            "output ObMultipartWriter doesn't support abort",
        ))
    }
}

impl <T: BlockingObMultipartWrite + ?Sized> BlockingObMultipartWrite for Box<T> {
    fn initiate_part(&mut self) -> Result<()> {
        (**self).initiate_part()
    }

    fn write_with_part_id(&mut self, bs: Buffer, part_id: usize) -> Result<()> {
        (**self).write_with_part_id(bs, part_id)
    }

    fn close(&mut self) -> Result<()> {
        (**self).close()
    }

    fn abort(&mut self) -> Result<()> {
        (**self).abort()
    }
}
