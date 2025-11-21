/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

#include "obdal_test.h"

// The test cases in this file are used to test the worm feature.

TEST_F(ObDalTest, test_write_with_worm_check)
{
  std::string path = base_path_ + "test_write_with_worm_check";
  const int64_t data_size = 1024;
  char data[data_size];
  ASSERT_TRUE(generate_random_bytes(data, data_size));
  opendal_bytes bytes = {
    .data = (uint8_t*)data,
    .len = data_size,
  };
  ObDalAsyncContext context;
  opendal_async_operator_write_with_worm_check(async_op_, path.c_str(), &bytes, obdal_async_callback, &context);
  context.wait();
  ASSERT_EQ(context.error_, nullptr);
  ASSERT_EQ(context.length_, data_size);

  context.reset();
  opendal_async_operator_write_with_worm_check(async_op_, path.c_str(), &bytes, obdal_async_callback, &context);
  context.wait();
  dump_error(context.error_);
  ASSERT_EQ(context.error_, nullptr);
  ASSERT_EQ(context.length_, data_size);

  ASSERT_TRUE(generate_random_bytes(data, data_size));
  opendal_bytes bytes2 = {
    .data = (uint8_t*)data,
    .len = data_size,
  };
  context.reset();
  opendal_async_operator_write_with_worm_check(async_op_, path.c_str(), &bytes2, obdal_async_callback, &context);
  context.wait();
  dump_error(context.error_);
  ASSERT_NE(context.error_, nullptr);
  ASSERT_EQ(context.error_->code, OPENDAL_OVERWRITE_CONTENT_MISMATCH);


  opendal_error *error = opendal_operator_delete(op_, path.c_str());
  ASSERT_NE(error, nullptr);
  ASSERT_EQ(error->code, OPENDAL_FILE_IMMUTABLE);
  opendal_error_free(error);
}

int main(int argc, char **argv) 
{
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}