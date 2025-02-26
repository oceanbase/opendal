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

use oio::ObMultipartWrite;
use crate::raw::*;
use crate::*;

pub struct ObMultipartWriteContext {
    acc: Accessor,
    path: String,
    args: OpWrite,
    #[allow(dead_code)]
    options: OpWriter,
}

impl ObMultipartWriteContext {
    #[inline]
    pub fn new(acc: Accessor, path: String, args: OpWrite, options: OpWriter) -> Self {
        Self {
            acc,
            path,
            args,
            options,
        }
    }

    #[inline]
    pub fn accessor(&self) -> &Accessor {
        &self.acc
    }

    #[inline]
    pub fn path(&self) -> &str {
        &self.path
    }

    #[inline]
    pub fn args(&self) -> &OpWrite {
        &self.args
    }

    #[inline]
    #[allow(dead_code)]
    pub fn options(&self) -> &OpWriter {
        &self.options
    }
}

pub struct ObMultipartWriteGenerator<W> {
    w: W,
}

impl ObMultipartWriteGenerator<oio::ObMultipartWriter> {
    pub async fn create(ctx: Arc<ObMultipartWriteContext>) -> Result<Self> {
        let (_, w) = ctx.accessor().ob_multipart_write(ctx.path(), ctx.args().clone()).await?;
        Ok(Self {
            w
        })
    }

    #[cfg(test)]
    #[allow(dead_code)]
    fn new(w: oio::ObMultipartWriter) -> Self {
        Self {
            w
        }
    }
}

impl ObMultipartWriteGenerator<oio::ObMultipartWriter> {
    pub async fn initiate_part(&mut self) -> Result<()> {
        self.w.initiate_part().await
    }

    pub async fn write_with_part_id(&mut self, bs: Buffer, part_id: usize) -> Result<usize> {
        let size = bs.len();
        self.w.write_with_part_id(bs, part_id).await?;
        return Ok(size)
    }

    pub async fn close(&mut self) -> Result<()> {
        self.w.close().await
    }

    pub async fn abort(&mut self) -> Result<()> {
        self.w.abort().await
    }
}

impl ObMultipartWriteGenerator<oio::BlockingObMultipartWriter> {
    pub fn blocking_create(ctx: Arc<ObMultipartWriteContext>) -> Result<Self> {
        let (_, w) = ctx.acc.blocking_ob_multipart_write(ctx.path(), ctx.args().clone())?;
        Ok(Self {
            w
        })
    }
}

impl ObMultipartWriteGenerator<oio::BlockingObMultipartWriter> {
    pub fn initiate_part(&mut self) -> Result<()> {
        self.w.initiate_part()
    }

    pub fn write_with_part_id(&mut self, bs: Buffer, part_id: usize) -> Result<usize> {
        let size = bs.len();
        self.w.write_with_part_id(bs, part_id)?;
        Ok(size)
    }

    pub fn close(&mut self) -> Result<()> {
        self.w.close()
    }

    pub fn abort(&mut self) -> Result<()> {
        self.w.abort()
    }
}


