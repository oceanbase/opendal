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

use clap::Parser;
use futures::TryStreamExt;
use opendal::Operator;
use opendal::Result;
use opendal::Scheme;
use std::collections::HashMap;
use std::str::FromStr;

#[derive(Debug, Parser)]
#[command(
    about = "List test example with runtime parameters",
    version,
    disable_help_subcommand = true
)]
struct Config {
    #[arg(long = "schema", alias = "scheme")]
    scheme: Option<String>,

    #[arg(long)]
    region: Option<String>,

    #[arg(long)]
    endpoint: Option<String>,

    #[arg(long)]
    bucket: Option<String>,

    #[arg(long)]
    ak: Option<String>,

    #[arg(long)]
    sk: Option<String>,

    #[arg(long)]
    root: Option<String>,

    #[arg(
        long = "list-dir",
        alias = "list_dir",
        default_value = "multi-version-list"
    )]
    list_dir: String,

    #[arg(
        long,
        num_args = 0..=1,
        default_missing_value = "true",
        default_value = "false",
        value_parser = clap::value_parser!(bool)
    )]
    recursive: bool,

    #[arg(long = "max-key", alias = "max_key")]
    max_key: Option<usize>,

    #[arg(long)]
    limit: Option<usize>,
}

async fn list(op: &Operator, cfg: &Config) -> Result<()> {
    let mut lister_builder = op.lister_with(&cfg.list_dir).recursive(cfg.recursive);
    if let Some(v) = cfg.max_key {
        lister_builder = lister_builder.limit(v);
    }
    let mut lister: opendal::Lister = lister_builder.await?;
    let mut listed: usize = 0;

    while let Some(entry) = lister.try_next().await? {
        println!("[Lister entry] {:?}", entry);
        listed += 1;
        if cfg.limit.is_some_and(|v| listed >= v) {
            println!("reach limit {}, stop listing", listed);
            break;
        }
    }

    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let cfg = Config::parse();

    let op = if let Some(scheme_str) = cfg.scheme.as_ref() {
        let scheme = Scheme::from_str(scheme_str).map_err(|_| {
            opendal::Error::new(
                opendal::ErrorKind::ConfigInvalid,
                format!("invalid schema/scheme: {scheme_str}"),
            )
        })?;

        let mut map = HashMap::new();
        if let Some(v) = cfg.region.as_ref() {
            map.insert("region".to_string(), v.to_string());
        }
        if let Some(v) = cfg.endpoint.as_ref() {
            map.insert("endpoint".to_string(), v.to_string());
        }
        if let Some(v) = cfg.bucket.as_ref() {
            map.insert("bucket".to_string(), v.to_string());
        }
        if let Some(v) = cfg.ak.as_ref() {
            map.insert("access_key_id".to_string(), v.to_string());
        }
        if let Some(v) = cfg.sk.as_ref() {
            map.insert("secret_access_key".to_string(), v.to_string());
        }
        if let Some(v) = cfg.root.as_ref() {
            map.insert("root".to_string(), v.to_string());
        }
        Operator::via_iter(scheme, map)?
    } else {
        use opendal::raw::tests::init_test_service;
        init_test_service()?.expect("OPENDAL_TEST must be set when --schema/--scheme is absent")
    };

    println!("service {:?} has been initialized", op.info());

    let ret = list(&op, &cfg).await;
    println!("ret = {:?}", ret);
    if let Err(err) = ret {
        println!("err = {}", err);
    }
    Ok(())
}
