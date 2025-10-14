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

#![warn(missing_docs)]
// This crate is the C binding for the OpenDAL project.
// So it's type node can't meet camel case.
#![allow(non_camel_case_types)]
// This crate is the C binding for the OpenDAL project.
// Nearly all the functions exposed to C FFI are unsafe.
#![allow(clippy::missing_safety_doc)]

//! The Apache OpenDAL C binding.
//!
//! The OpenDAL C binding allows users to utilize the OpenDAL's amazing storage accessing capability
//! in the C programming language.
//!
//! For examples, you may see the examples subdirectory

mod common;
pub use common::c_char_to_str;
pub use common::handle_result;
pub use common::handle_result_without_ret;
pub use common::dump_panic;

mod error;
pub use error::opendal_code;
pub use error::opendal_error;

mod lister;
pub use lister::opendal_lister;

mod deleter;
pub use deleter::opendal_deleter;

mod metadata;
pub use metadata::opendal_metadata;

mod operator;
pub use operator::opendal_operator;
mod async_operator;
pub use async_operator::opendal_async_operator;

mod async_multipart_writer;
pub use async_multipart_writer::opendal_async_multipart_writer;

mod operator_info;

mod result;
pub use result::opendal_result_exists;
pub use result::opendal_result_is_exist;
pub use result::opendal_result_list;
pub use result::opendal_result_lister_next;
pub use result::opendal_result_operator_deleter;
pub use result::opendal_result_operator_new;
pub use result::opendal_result_operator_reader;
pub use result::opendal_result_operator_writer;
pub use result::opendal_result_read;
pub use result::opendal_result_reader_read;
pub use result::opendal_result_stat;
pub use result::opendal_result_writer_write;
pub use result::opendal_result_get_object_tagging;
pub use result::opendal_result_object_tagging_get;
pub use result::opendal_result_operator_multipart_writer;

mod types;
pub use types::opendal_bytes;
pub use types::opendal_operator_options;
pub use types::opendal_object_tagging;

mod entry;
pub use entry::opendal_entry;

mod reader;
pub use reader::opendal_reader;

mod writer;
pub use writer::opendal_writer;

mod multipart_writer;
pub use multipart_writer::opendal_multipart_writer;
