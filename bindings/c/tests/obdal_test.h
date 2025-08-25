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
    base_path_ = "obdal_test_" + get_formatted_time() + "/";
  }
protected:
  void SetUp() override
  {
    
    ObSpan *ob_span = ob_new_span(1, "test-trace");
    ASSERT_NE(nullptr, ob_span);
    ob_span_ = ob_span;

    opendal_operator_options *options = opendal_operator_options_new();
    type_ = get_storage_type(scheme);
    ASSERT_NE(MAX_TYPE, type_);
    if (type_ == S3) {
      opendal_operator_options_set(options, "bucket", bucket);
      opendal_operator_options_set(options, "endpoint", endpoint);
      opendal_operator_options_set(options, "region", region);
      opendal_operator_options_set(options, "access_key_id", access_key_id);
      opendal_operator_options_set(options, "secret_access_key", secret_access_key);
      opendal_operator_options_set(options, "disable_config_load", "true");
      opendal_operator_options_set(options, "disable_ec2_metadata", "true");
      opendal_operator_options_set(options, "enable_virtual_host_style", "true");
      opendal_operator_options_set(options, "checksum_algorithm", "crc32");
    } else if (type_ == OSS) {
      opendal_operator_options_set(options, "bucket", bucket);
      opendal_operator_options_set(options, "endpoint", endpoint);
      opendal_operator_options_set(options, "access_key_id", access_key_id);
      opendal_operator_options_set(options, "access_key_secret", secret_access_key);
      opendal_operator_options_set(options, "checksum_algorithm", "md5");
    } else if (type_ == AZBLOB) {
      opendal_operator_options_set(options, "container", bucket);
      opendal_operator_options_set(options, "endpoint", endpoint);
      opendal_operator_options_set(options, "account_name", access_key_id);
      opendal_operator_options_set(options, "account_key", secret_access_key);
      opendal_operator_options_set(options, "checksum_algorithm", "md5");
    }
    opendal_operator_options_set(options, "tenant_id", "1003");
    opendal_operator_options_set(options, "timeout", "5");

    // Given A new OpenDAL Blocking Operator
    opendal_result_operator_new result = opendal_operator_new(scheme, options);
    dump_error(result.error);
    ASSERT_EQ(nullptr, result.error);

    op_ = result.op;
    ASSERT_NE(nullptr, op_);

    opendal_error *error = opendal_async_operator_new(scheme, options, &async_op_);
    dump_error(error);
    ASSERT_EQ(nullptr, error);

    opendal_operator_options_free(options);
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
    opendal_register_retry_timeout_fn(reinterpret_cast<void *>(get_retry_timeout));
    ASSERT_EQ(error, nullptr);
  }

  static void TearDownTestCase()
  {
    opendal_fin_env();
  }
protected:
  std::string base_path_;
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
      assert(context->callback_count_ == 1);
    }
    context->cv_.notify_all();
  }

#endif