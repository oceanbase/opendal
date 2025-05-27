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

use http::StatusCode;
use uuid::Uuid;

use super::core::AzblobCore;
use super::error::parse_error;
use crate::raw::*;
use crate::*;

pub struct AzblobMultipartWriter {
    core: Arc<AzblobCore>,
    op: OpWrite,
    path: String,
}

impl AzblobMultipartWriter {
    pub fn new(core: Arc<AzblobCore>, op: OpWrite, path: String) -> Self {
        Self {
            core,
            op,
            path,
        }
    }
}

impl oio::MultipartWrite for AzblobMultipartWriter {
    async fn write_once(&self, size: u64, body: Buffer) -> Result<()> {
        let mut req: http::Request<Buffer> = self.core.azblob_put_blob_request(&self.path, Some(size), &self.op, body)?;
        self.core.sign(&mut req).await?;
        let resp = self.core.send(req).await?;
        let status = resp.status();
        match status {
            StatusCode::CREATED | StatusCode::OK => Ok(()),
            _ => Err(parse_error(resp)),
        }
    }


    async fn initiate_part(&self) -> Result<String> {
        Ok("fake_upload_id".to_string())
    }

    async fn write_part(&self, _upload_id: &str, part_number: usize, size: u64, body: Buffer) -> Result<oio::MultipartPart> {
        let block_id = Uuid::new_v4();
        let resp = self
            .core
            .azblob_put_block(&self.path, block_id, Some(size), &self.op, body)
            .await?;

        let status = resp.status();
        match status {
            StatusCode::CREATED | StatusCode::OK => Ok(oio::MultipartPart {
                part_number: part_number,
                etag: String::new(),
                checksum: None,
                block_id: Some(block_id)
            }),
            _ => Err(parse_error(resp)),
        }
    }

    async fn complete_part(&self, _upload_id: &str, parts: &[oio::MultipartPart]) -> Result<()> {
        let mut parts: Vec<_> = parts
            .iter()
            .collect();
        parts.sort_by(|lth, rth| lth.part_number.cmp(&rth.part_number));
        let block_ids = parts
            .iter()
            .map(|p| p.block_id.unwrap())
            .collect();

        let resp = self
            .core
            .azblob_complete_put_block_list(&self.path, block_ids, &self.op)
            .await?;

        let status = resp.status();
        match status {
            StatusCode::CREATED | StatusCode::OK => Ok(()),
            _ => Err(parse_error(resp)),
        }
    }

    async fn abort_part(&self, _upload_id: &str) -> Result<()> {
        Ok(())
    }
}
