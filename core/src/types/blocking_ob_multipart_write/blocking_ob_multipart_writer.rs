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

use bytes::Buf;
use std::sync::Mutex;

use crate::raw::*;
use crate::*;

///
pub struct BlockingObMultipartWriter {
    /// Keep a reference to write context in writer.
    _ctx: Arc<ObMultipartWriteContext>,
    inner: ObMultipartWriteGenerator<oio::BlockingObMultipartWriter>,
    parts: Arc<Mutex<Vec<oio::MultipartPart>>>,
}


impl BlockingObMultipartWriter {
    ///
    pub(crate) fn new(ctx: ObMultipartWriteContext) -> Result<Self> {
        let ctx = Arc::new(ctx);
        let inner = ObMultipartWriteGenerator::blocking_create(ctx.clone())?;

        Ok(Self { _ctx: ctx, inner, parts: Arc::new(Mutex::new(Vec::new())) })
    }

    ///
    pub fn initiate_part(&mut self) -> Result<()> {
        self.inner.initiate_part()
    }

    ///
    pub fn write_with_part_id(
        &mut self,
        bs: impl Into<Buffer>,
        part_id: usize,
    ) -> Result<()> {
        let bs = bs.into();
        let part = self.inner.write_with_part_id(bs.clone(), part_id)?;
        {
            let mut guard = self.parts.lock().unwrap();
            guard.push(part);
        }

        Ok(())
    }

    ///
    pub fn write_from(&mut self, bs: impl Buf, part_id: usize) -> Result<()> {
        let mut bs = bs;
        let bs = Buffer::from(bs.copy_to_bytes(bs.remaining()));
        self.write_with_part_id(bs, part_id)
    }

    ///
    pub fn abort(&mut self) -> Result<()> {
        self.inner.abort()
    }

    ///
    pub fn close(&mut self) -> Result<()> {
        let parts = self.parts.lock().unwrap();
        self.inner.close(parts.clone())
    }
}
