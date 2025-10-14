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

use std::fmt::Debug;
use std::fmt::Formatter;
use std::ops::Div;
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;


use log::warn;

use crate::raw::*;
use crate::*;

pub const SMALL_IO_SIZE: u64 = 128 * 1024;       // 128KB
pub const MIDLE_IO_SIZE: u64 = 2 * 1024 * 1024;  // 2MB

pub const UTIL_IO_WARN_THRESHOLD_TIME : Duration = Duration::from_millis(50);        // 50ms
pub const SMALL_IO_WARN_THRESHOLD_TIME : Duration = Duration::from_millis(100);        // 100ms
pub const MIDLE_IO_WARN_THRESHOLD_TIME : Duration = Duration::from_millis(200);        // 200ms
pub const LARGE_IO_WARN_THRESHOLD_TIME : Duration = Duration::from_millis(300);        // 300ms


/// check if the io is slow
pub fn is_slow(cost_time: Duration, io_size: u64) -> bool {
    if io_size == 0 {
        return cost_time > UTIL_IO_WARN_THRESHOLD_TIME;
    } else if io_size <= SMALL_IO_SIZE {
        return cost_time > SMALL_IO_WARN_THRESHOLD_TIME;
    } else if io_size <= MIDLE_IO_SIZE {
        return cost_time > MIDLE_IO_WARN_THRESHOLD_TIME;
    } else {
        return cost_time > LARGE_IO_WARN_THRESHOLD_TIME;
    }
}


/// calc the speed of io, unit is MB/s
pub fn calc_speed(cost_time: Duration, io_size: u64) -> f64 {
    if cost_time.is_zero() {
        return 0.0;
    }

    return (io_size as f64) / cost_time.as_secs_f64() / 1024.0 / 1024.0;
}

/// Add OceanBase Guard
/// Notice: This layer is only used for OceanBase observer
/// it is specifically designed for ob use cases
pub struct ObGuardLayer {
}

impl Default for ObGuardLayer {
    fn default() -> Self {
        Self {
        }
    }
}

impl ObGuardLayer {
    /// Create a new ObGuardLayer instance
    pub fn new() -> Self {
        Self::default()
    }
}

impl<A: Access> Layer<A> for ObGuardLayer {
    type LayeredAccess = ObGuardAccessor<A>;

    fn layer(&self, inner: A) -> Self::LayeredAccess {
        ObGuardAccessor {
            inner: Arc::new(inner),
        }
    }
}

pub struct ObGuardAccessor<A: Access> {
    inner: Arc<A>,
}

impl<A: Access> Debug for ObGuardAccessor<A> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ObGuardAccessor")
            .field("inner", &self.inner)
            .finish_non_exhaustive()
    }
}

impl<A: Access> LayeredAccess for ObGuardAccessor<A> {
    type Inner = A;
    type Reader = ObGuardWrapper<A::Reader>;
    type BlockingReader = ObGuardWrapper<A::BlockingReader>;
    type Writer = ObGuardWrapper<A::Writer>;
    type BlockingWriter = ObGuardWrapper<A::BlockingWriter>;
    type ObMultipartWriter = ObGuardWrapper<A::ObMultipartWriter>;
    type BlockingObMultipartWriter = ObGuardWrapper<A::BlockingObMultipartWriter>;
    type Lister = ObGuardWrapper<A::Lister>;
    type BlockingLister = ObGuardWrapper<A::BlockingLister>;
    type Deleter = ObGuardWrapper<A::Deleter>;
    type BlockingDeleter = ObGuardWrapper<A::BlockingDeleter>;

    fn inner(&self) -> &Self::Inner {
        &self.inner
    }

    /// actually, create_dir is not used in ob observer
    async fn create_dir(&self, path: &str, args: OpCreateDir) -> Result<RpCreateDir> {
        let start_time = Instant::now();
        self.inner.create_dir(path, args)
            .await
            .map_err(|e| e.with_context("cost time(ms)", start_time.elapsed().as_millis()))
    }

    /// this method will create io for read, but not copy data to buffer that ob offered.
    async fn read(&self, path: &str, args: OpRead) -> Result<(RpRead, Self::Reader)> {
        let start_time = Instant::now();
        self.inner.read(path, args.clone())
            .await
            .map(|(rp, r)| (rp, ObGuardWrapper::new(r).with_path(path)))
            .map_err(|e| e.with_context("cost time(ms)", start_time.elapsed().as_millis()))
    }

    /// this method not create io in ob
    async fn write(&self, path: &str, args: OpWrite) -> Result<(RpWrite, Self::Writer)> {
        let start_time = Instant::now();
        self.inner.write(path, args.clone())
            .await
            .map(|(rp, w)| (rp, ObGuardWrapper::new(w).with_path(path)))
            .map_err(|e| e.with_context("cost time(ms)", start_time.elapsed().as_millis()))
    }

    /// this method not create io in ob
    async fn ob_multipart_write(&self, path: &str, args: OpWrite) -> Result<(RpWrite, Self::ObMultipartWriter)> {
        let start_time = Instant::now();
        self.inner.ob_multipart_write(path, args.clone())
            .await
            .map(|(rp, w)| (rp, ObGuardWrapper::new(w).with_path(path)))
            .map_err(|e| e.with_context("cost time(ms)", start_time.elapsed().as_millis()))
    }

    async fn stat(&self, path: &str, args: OpStat) -> Result<RpStat> {
        let start_time = Instant::now();
        let rp = self.inner.stat(path, args.clone())
            .await
            .map_err(|e| e.with_context("cost time(ms)", start_time.elapsed().as_millis()))?;

        let cost_time = start_time.elapsed();
        if is_slow(cost_time, 0) {
            warn!("stat: {} is slow, cost: {:?}, speed: {:.2} MB/s", path, cost_time, 0);
        }
        Ok(rp)
    }

    /// this method not create io in ob
    async fn delete(&self) -> Result<(RpDelete, Self::Deleter)> {
        let start_time = Instant::now();
        self.inner.delete()
            .await
            .map(|(rp, r)| (rp, ObGuardWrapper::new(r)))
            .map_err(|e| e.with_context("cost time(ms)", start_time.elapsed().as_millis()))
    }

    /// this method not used in ob observer
    async fn copy(&self, from: &str, to: &str, args: OpCopy) -> Result<RpCopy> {
        let start_time = Instant::now();
        self.inner.copy(from, to, args.clone())
            .await
            .map_err(|e| e.with_context("cost time(ms)", start_time.elapsed().as_millis()))
    }

    /// this method not used in ob observer
    async fn rename(&self, from: &str, to: &str, args: OpRename) -> Result<RpRename> {
        let start_time = Instant::now();
        self.inner.rename(from, to, args.clone())
            .await
            .map_err(|e| e.with_context("cost time(ms)", start_time.elapsed().as_millis()))
    }

    async fn list(&self, path: &str, args: OpList) -> Result<(RpList, Self::Lister)> {
        let start_time = Instant::now();
        let rp = self.inner.list(path, args.clone())
            .await
            .map(|(rp, r)| (rp, ObGuardWrapper::new(r).with_path(path)))
            .map_err(|e| e.with_context("cost time(ms)", start_time.elapsed().as_millis()))?;

        let cost_time = start_time.elapsed();
        if is_slow(cost_time, 0) {
            warn!("list: {} is slow, cost: {:?}, speed: {:.2} MB/s", path, cost_time, 0);
        }
        Ok(rp)
    }

    /// this method not used in ob observer
    fn blocking_create_dir(&self, _path: &str, _args: OpCreateDir) -> Result<RpCreateDir> {
        Err(Error::new(
            ErrorKind::Unsupported,
            "operation is not supported",
        ))
    }

    /// this method not create io in ob
    fn blocking_read(&self, _path: &str, _args: OpRead) -> Result<(RpRead, Self::BlockingReader)> {
        Err(Error::new(
            ErrorKind::Unsupported,
            "operation is not supported",
        ))
    }


    fn blocking_write(&self, _path: &str, _args: OpWrite) -> Result<(RpWrite, Self::BlockingWriter)> {
        Err(Error::new(
            ErrorKind::Unsupported,
            "operation is not supported",
        ))
    }

    fn blocking_ob_multipart_write(&self, _path: &str, _args: OpWrite) -> Result<(RpWrite, Self::BlockingObMultipartWriter)> {
        Err(Error::new(
            ErrorKind::Unsupported,
            "operation is not supported",
        ))
    }

    fn blocking_delete(&self) -> Result<(RpDelete, Self::BlockingDeleter)> {
        Err(Error::new(
            ErrorKind::Unsupported,
            "operation is not supported",
        ))
    }

    fn blocking_stat(&self, _path: &str, _args: OpStat) -> Result<RpStat> {
        Err(Error::new(
            ErrorKind::Unsupported,
            "operation is not supported",
        ))
    }

    fn blocking_put_object_tagging(&self, _path: &str, _args: OpPutObjTag) -> Result<RpPutObjTag> {
        Err(Error::new(
            ErrorKind::Unsupported,
            "operation is not supported",
        ))
    }

    fn blocking_get_object_tagging(&self, _path: &str) -> Result<RpGetObjTag> {
        Err(Error::new(
            ErrorKind::Unsupported,
            "operation is not supported",
        ))
    }

    fn blocking_copy(&self, _from: &str, _to: &str, _args: OpCopy) -> Result<RpCopy> {
        Err(Error::new(
            ErrorKind::Unsupported,
            "operation is not supported",
        ))
    }

    fn blocking_rename(&self, _from: &str, _to: &str, _args: OpRename) -> Result<RpRename> {
        Err(Error::new(
            ErrorKind::Unsupported,
            "operation is not supported",
        ))
    }

    fn blocking_list(&self, _path: &str, _args: OpList) -> Result<(RpList, Self::BlockingLister)> {
        Err(Error::new(
            ErrorKind::Unsupported,
            "operation is not supported",
        ))
    }
}

pub struct ObGuardWrapper<R> {
    inner: R,
    io_size: u64,
    path: String,
}

impl<R> ObGuardWrapper<R> {
    fn new(inner: R) -> Self {
        Self {
            inner: inner,
            io_size: 0,
            path: String::new(),
        }
    }

    fn with_path(self, path: &str) -> Self {
        Self {
            inner: self.inner,
            io_size: self.io_size,
            path: path.to_string(),
        }
    }
}

impl<R: oio::Read> oio::Read for ObGuardWrapper<R> {
    /// This method doesn't necessarily incur IO, 
    /// and we don't know from the fact that all of the services ob used 
    /// implement it using HttpBody, so we won't do latency statistics here
    async fn read(&mut self) -> Result<Buffer> {
        let start_time = Instant::now();
        self.inner.read().await
            .map_err(|e| e.with_context("cost time(ms)", start_time.elapsed().as_millis()))
    }
}

impl<R: oio::BlockingRead> oio::BlockingRead for ObGuardWrapper<R> {
    fn read(&mut self) -> Result<Buffer> {
        Err(Error::new(
            ErrorKind::Unsupported,
            "operation is not supported",
        ))
    }
}

impl<R: oio::Write> oio::Write for ObGuardWrapper<R> {
    /// in ob, only put will use this method, but not io will be created
    /// the real io will be created in close method
    async fn write(&mut self, bs: Buffer) -> Result<()> {
        let start_time = Instant::now();
        let io_size = bs.len() as u64;
        let rp = self.inner.write(bs.clone()).await
            .map_err(|e| e.with_context("cost time(ms)", start_time.elapsed().as_millis()))?;

        self.io_size += io_size;
        Ok(rp)
    }

    /// in ob, append writer will use this method
    /// the io will be created in this method
    async fn write_with_offset(&mut self, offset: u64, bs: Buffer) -> Result<()> {
        let start_time = Instant::now();
        let io_size = bs.len() as u64;
        let rp = self.inner.write_with_offset(offset, bs.clone()).await
            .map_err(|e| e.with_context("cost time(ms)", start_time.elapsed().as_millis()))?;

        let cost_time = start_time.elapsed();
        if is_slow(cost_time, io_size) {
            warn!("writer write_with_offset {}: is slow, io_size: {}, cost: {:?}, speed: {:.2} MB/s", self.path, io_size, cost_time, calc_speed(cost_time, io_size));
        }
        Ok(rp)
    }

    async fn abort(&mut self) -> Result<()> {
        let start_time = Instant::now();
        let rp = self.inner.abort().await
            .map_err(|e| e.with_context("cost time(ms)", start_time.elapsed().as_millis()))?;

        let cost_time = start_time.elapsed();
        if is_slow(cost_time, 0) {
            warn!("writer abort {}: is slow, cost: {:?}, speed: {:.2} MB/s", self.path, cost_time, 0);
        }
        Ok(rp)
    }

    /// in ob, only put will create io in this method
    async fn close(&mut self) -> Result<()> {
        let start_time = Instant::now();
        let rp = self.inner.close().await
            .map_err(|e| e.with_context("cost time(ms)", start_time.elapsed().as_millis()))?;

        let cost_time = start_time.elapsed();
        if is_slow(cost_time, self.io_size) {
            warn!("writer close {}: is slow, io_size: {}, cost: {:?}, speed: {:.2} MB/s", self.path, self.io_size, cost_time, calc_speed(cost_time, self.io_size));
        }
        Ok(rp)
    }
}

impl<R: oio::BlockingWrite> oio::BlockingWrite for ObGuardWrapper<R> {
    fn write(&mut self, _bs: Buffer) -> Result<()> {
        Err(Error::new(
            ErrorKind::Unsupported,
            "operation is not supported",
        ))
    }

    fn write_with_offset(&mut self, _offset: u64, _bs: Buffer) -> Result<()> {
        Err(Error::new(
            ErrorKind::Unsupported,
            "operation is not supported",
        ))
    }

    fn close(&mut self) -> Result<()> {
        Err(Error::new(
            ErrorKind::Unsupported,
            "operation is not supported",
        ))
    }
}

impl<R: oio::ObMultipartWrite + Clone> Clone for ObGuardWrapper<R> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            io_size: self.io_size,
            path: self.path.clone(),
        }
    }
}

impl<R: oio::ObMultipartWrite + Clone> oio::ObMultipartWrite for ObGuardWrapper<R> {
    async fn initiate_part(&mut self) -> Result<()> {
        let start_time = Instant::now();
        let rp = self.inner.initiate_part().await
            .map_err(|e| e.with_context("cost time(ms)", start_time.elapsed().as_millis()))?;

        let cost_time = start_time.elapsed();
        if is_slow(cost_time, 0) {
            warn!("multipart writer initiate_part: is slow, cost: {:?}, speed: {:.2} MB/s", cost_time, 0);
        }
        Ok(rp)
    }

    async fn write_with_part_id(&mut self, bs: Buffer, part_id: usize) -> Result<oio::MultipartPart> {
        let start_time = Instant::now();
        let io_size = bs.len() as u64;
        let rp = self.inner.write_with_part_id(bs, part_id)
            .await
            .map_err(|e| e.with_context("cost time(ms)", start_time.elapsed().as_millis()))?;

        let cost_time = start_time.elapsed();
        if is_slow(cost_time, io_size) {
            warn!("multipart writer write_with_part_id {}: is slow, part_id: {}, io_size: {}, cost: {:?}, speed: {:.2} MB/s", self.path, part_id, io_size, cost_time, calc_speed(cost_time, io_size));
        }
        Ok(rp)
    }

    async fn close(&mut self, parts: Vec<oio::MultipartPart>) -> Result<()> {
        let start_time = Instant::now();
        let rp = self.inner.close(parts.clone()).await
            .map_err(|e| e.with_context("cost time(ms)", start_time.elapsed().as_millis()))?;

        let cost_time = start_time.elapsed();
        if is_slow(cost_time, 0) {
            warn!("multipart writer close {}: is slow, cost: {:?}, speed: {:.2} MB/s", self.path, cost_time, 0);
        }
        Ok(rp)
    }

    async fn abort(&mut self) -> Result<()> {
        let start_time = Instant::now();
        let rp = self.inner.abort().await
            .map_err(|e| e.with_context("cost time(ms)", start_time.elapsed().as_millis()))?;

        let cost_time = start_time.elapsed();
        if is_slow(cost_time, 0) {
            warn!("multipart writer abort {}: is slow, cost: {:?}, speed: {:.2} MB/s", self.path, cost_time, 0);
        }
        Ok(rp)
    }
}

impl<R: oio::BlockingObMultipartWrite> oio::BlockingObMultipartWrite for ObGuardWrapper<R> {
    fn initiate_part(&mut self) -> Result<()> {
        Err(Error::new(
            ErrorKind::Unsupported,
            "operation is not supported",
        ))
    }


    fn write_with_part_id(&mut self, _bs: Buffer, _part_id: usize) -> Result<oio::MultipartPart> {
        Err(Error::new(
            ErrorKind::Unsupported,
            "operation is not supported",
        ))
    }


    fn close(&mut self, _parts: Vec<oio::MultipartPart>) -> Result<()> {
        Err(Error::new(
            ErrorKind::Unsupported,
            "operation is not supported",
        ))
    }

    fn abort(&mut self) -> Result<()> {
        Err(Error::new(
            ErrorKind::Unsupported,
            "operation is not supported",
        ))
    }
}

impl<P: oio::List> oio::List for ObGuardWrapper<P> {
    /// this method may create io in ob
    async fn next(&mut self) -> Result<Option<oio::Entry>> {
        let start_time = Instant::now();
        let rp = self.inner.next().await
            .map_err(|e| e.with_context("cost time(ms)", start_time.elapsed().as_millis()))?;

        let cost_time = start_time.elapsed();
        if is_slow(cost_time, 0) {
            warn!("list next {}: is slow, cost: {:?}, speed: {:.2} MB/s", self.path, cost_time, 0);
        }
        Ok(rp)
    }
}

impl<P: oio::BlockingList> oio::BlockingList for ObGuardWrapper<P> {
    fn next(&mut self) -> Result<Option<oio::Entry>> {
        Err(Error::new(
            ErrorKind::Unsupported,
            "operation is not supported",
        ))
    }
}

impl<P: oio::Delete> oio::Delete for ObGuardWrapper<P> {
    /// in some backend, like s3、oss、azblob, support batch delete, so this method not create io in ob
    /// but like gcs, only support one shot delete, so this method create io in ob
    fn delete(&mut self, path: &str, args: OpDelete) -> Result<()> {
        let start_time = Instant::now();
        let rp = self.inner.delete(path, args.clone())
            .map_err(|e| e.with_context("cost time(ms)", start_time.elapsed().as_millis()))?;

        let cost_time = start_time.elapsed();
        if is_slow(cost_time, 0) {
            warn!("deleter delete {}: is slow, cost: {:?}, speed: {:.2} MB/s", path, cost_time, 0);
        }
        Ok(rp)
    }

    /// As opposed to the `delete` method, this method create io in ob when backend support batch delete
    async fn flush(&mut self) -> Result<usize> {
        let start_time = Instant::now();
        let rp = self.inner.flush().await
            .map_err(|e| e.with_context("cost time(ms)", start_time.elapsed().as_millis()))?;

        let cost_time = start_time.elapsed();
        if is_slow(cost_time, 0) {
            warn!("deleter flush: is slow, cost: {:?}, speed: {:.2} MB/s", cost_time, 0);
        }
        Ok(rp)
    }

    /// this method not create io in ob
    fn deleted(&mut self, path: &str, args: OpDelete) -> Result<bool> {
        let start_time = Instant::now();
        self.inner.deleted(path, args.clone())
            .map_err(|e| e.with_context("cost time(ms)", start_time.elapsed().as_millis()))
    }
}

impl<P: oio::BlockingDelete> oio::BlockingDelete for ObGuardWrapper<P> {
    fn delete(&mut self, _path: &str, _args: OpDelete) -> Result<()> {
        Err(Error::new(
            ErrorKind::Unsupported,
            "operation is not supported",
        ))
    }

    fn flush(&mut self) -> Result<usize> {
        Err(Error::new(
            ErrorKind::Unsupported,
            "operation is not supported",
        ))
    }
}