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


use opendal::Operator;
use opendal::Result;

async fn prepare(op: Operator) -> Result<()> {
  let bytes = vec![0; 10];

  for i in 0..2000 {
    op.write(&format!("multi-version-list/test_{}", i), bytes.clone()).await?;
  }

  let mut deleter = op.deleter().await?;

  for i in 0..2000 {
    deleter.delete(format!("multi-version-list/test_{}", i)).await?;
  }
  let ret = deleter.flush().await?;

  assert_eq!(ret, 2000);

  Ok(())
}


async fn list(op: Operator) -> Result<()> {
  let entries = op.list("multi-version-list").await?;
  assert_eq!(entries.len(), 0);

  Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
  use opendal::raw::tests::init_test_service;
  let op = init_test_service()?.expect("OPENDAL_TEST must be set");

  println!("service {:?} has been initialized", op.info());
  // let ret = prepare(op).await;
  let ret = list(op).await;
  println!("ret = {:?}", ret);
  if let Err(err) = ret {
    println!("err = {}", err);
  }
  Ok(())
}
