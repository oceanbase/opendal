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

#ifndef OBDAL_TEST_H_
#define OBDAL_TEST_H_

#include "common.hpp"
#include "opendal.h"
#include "assert.h"
#include <gtest/gtest.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <vector>
#include <mutex>
#include <condition_variable>
#include <thread>

class ObDalTest : public ::testing::Test 
{
public:
  ObDalTest()
    : op_(nullptr),
      async_op_(nullptr),
      ob_span_(nullptr),
      type_(MAX_TYPE)
  {
  }
protected:
  void SetUp() override
  {
    
    ObSpan *ob_span = ob_new_span(1, "test-trace");
    ASSERT_NE(nullptr, ob_span);
    ob_span_ = ob_span;

    opendal_operator_options *options = opendal_operator_options_new();
    opendal_operator_config *config = opendal_operator_config_new();
    TestConfig &cfg = test_config_instance();
    ASSERT_EQ(true, cfg.is_valid());
    ASSERT_EQ(true, cfg.build_config(config));
    type_ = cfg.storage_type_;
    const char *scheme = get_storage_type_name(type_);

    opendal_result_operator_new result = opendal_operator_new2(scheme, config);
    dump_error(result.error);
    ASSERT_EQ(nullptr, result.error);
    op_ = result.op;
    ASSERT_NE(nullptr, op_);

    opendal_error *error = opendal_async_operator_new(scheme, config, &async_op_);
    dump_error(error);
    ASSERT_EQ(nullptr, error);

    opendal_operator_options_free(options);
    opendal_operator_config_free(config);
  }

  void TearDown() override 
  {
    if (op_ != nullptr) {
      opendal_operator_free(op_); 
    }
    if (async_op_ != nullptr) {
      opendal_async_operator_free(async_op_);
    }
    if (ob_span_ != nullptr) {
      ob_drop_span(ob_span_);
    }
  }
  static void SetUpTestCase() 
  {
    // Load configuration from environment variables based on selected schema.
    // Prefer new prefixed envs, fallback to legacy if needed.
    TestConfig &cfg = test_config_instance();
    load_test_config_from_env(cfg);
    ASSERT_TRUE(cfg.is_valid());
    opendal_error *error = opendal_init_env(reinterpret_cast<void *>(my_alloc), 
                                            reinterpret_cast<void *>(my_free),
                                            reinterpret_cast<void *>(ob_log_handler),
                                            6,  // LevelFilter::TRACE,
                                            32, // work thread count 
                                            32, // max blocking thread count
                                            10, // block thread keep alive time (unit s)
                                            32, // max client count
                                            30,
                                            10); // max idle time of client (unit s)
    opendal_register_retry_timeout_fn(reinterpret_cast<void *>(get_retry_timeout_ms));
    ASSERT_EQ(error, nullptr);
    base_path_ = "obdal_test_" + get_formatted_time() + "/";
  }

  static void TearDownTestCase()
  {
    opendal_fin_env();
  }
protected:
  static std::string base_path_;
  const opendal_operator *op_;
  opendal_async_operator *async_op_;
  ObSpan *ob_span_;
  StorageType type_;
};

class ObDalAsyncContext {
public:
  void wait()
  {
    std::unique_lock<std::mutex> lock(mutex_);
    cv_.wait(lock, [this] { return completed_; });
  }
  void reset()
  {
    completed_ = false;
    free_error(error_);
    length_ = 0;
    callback_count_ = 0;
  }
public:
  bool completed_ = false;
  opendal_error *error_ = nullptr;
  int64_t length_ = 0;
  std::mutex mutex_;
  std::condition_variable cv_;
  int64_t callback_count_ = 0;
};
  
void obdal_async_callback(opendal_error *error, const int64_t length, void *ctx)
{
  ObDalAsyncContext *context = static_cast<ObDalAsyncContext *>(ctx);
  {
    std::unique_lock<std::mutex> lock(context->mutex_);
    context->length_ = length;
    context->error_ = error;
    context->completed_ = true;
    context->callback_count_++;
    if (error != nullptr) {
      dump_error(error);
    }
    assert(context->callback_count_ == 1);
  }
  context->cv_.notify_all();
}

#endif