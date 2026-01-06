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
#include <mutex>
#include <condition_variable>

std::string ObDalTest::base_path_ = "";

TEST_F(ObDalTest, test_rw)
{
  std::string path = base_path_ + "test_rw";
  opendal_bytes data = {
    .data = (uint8_t*)"this_string_length_is_24",
    .len = 24,
  };
  ObDalAsyncContext context;

  opendal_async_operator_write(async_op_, path.c_str(), &data, obdal_async_callback, &context);
  {
    std::unique_lock<std::mutex> lock(context.mutex_);
    context.cv_.wait(lock, [&context] { return context.completed_; });
  }
  dump_error(context.error_);
  ASSERT_EQ(context.error_, nullptr);
  ASSERT_EQ(context.length_, 24);

  // test async read with network disruption
  {
    DisruptNetwork disrupt_network;
    context.reset();
    uint8_t buf[100] = { 0 };
    opendal_async_operator_read(async_op_, path.c_str(), buf, 6, 5, obdal_async_callback, &context);
    context.wait();
    dump_error(context.error_);
    ASSERT_TRUE(context.error_ != nullptr);
    ASSERT_EQ(context.error_->code, OPENDAL_TIMED_OUT);
  }

  // test async read with limit network disruption
  {
    std::thread t([&]() {
      DisruptNetwork disrupt_network;
      sleep(get_retry_timeout() / 2 / 1000);
    });
    sleep(1);
    context.reset();
    uint8_t buf[100] = { 0 };
    opendal_async_operator_read(async_op_, path.c_str(), buf, 6, 5, obdal_async_callback, &context);
    context.wait();
    dump_error(context.error_);
    ASSERT_TRUE(context.error_ == nullptr);
    t.join();
  }
  
  // test sync read with network disruption
  {
    DisruptNetwork disrupt_network;
    opendal_result_operator_reader result_reader = opendal_operator_reader(op_, path.c_str());
    ASSERT_EQ(result_reader.error, nullptr);
    opendal_reader *reader = result_reader.reader;
    ASSERT_TRUE(reader != nullptr);

    uint8_t buf[100] = { 0 };
    opendal_result_reader_read result_reader_read = opendal_reader_read(reader, buf, 6, 5);
    dump_error(result_reader_read.error);
    ASSERT_TRUE(result_reader_read.error != nullptr);
    ASSERT_EQ(result_reader_read.error->code, OPENDAL_TIMED_OUT);
    ASSERT_EQ(result_reader_read.size, 0);

    opendal_reader_free(reader);
  }
}

int main(int argc, char **argv)
{
  // Parse custom schema arg and load envs accordingly, then forward remaining args to gtest
  parse_service_arg(argc, argv);
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}