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

class ObDalTest : public ::testing::Test 
{
public:
  ObDalTest() 
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
    opendal_operator_options_set(options, "bucket", bucket);
    opendal_operator_options_set(options, "endpoint", endpoint);
    opendal_operator_options_set(options, "region", region);
    opendal_operator_options_set(options, "access_key_id", access_key_id);
    opendal_operator_options_set(options, "secret_access_key", secret_access_key);
    opendal_operator_options_set(options, "disable_config_load", "true");
    opendal_operator_options_set(options, "disable_ec2_metadata", "true");
    opendal_operator_options_set(options, "enable_virtual_host_style", "true");

    // Given A new OpenDAL Blocking Operator
    opendal_result_operator_new result = opendal_operator_new(scheme, options);
    ASSERT_EQ(nullptr, result.error);

    op_ = result.op;
    ASSERT_NE(nullptr, op_);

    opendal_operator_options_free(options);
  }

  void TearDown() override 
  {
    opendal_operator_free(op_); 
    ob_drop_span(ob_span_);
  }
  static void SetUpTestCase() 
  {
    opendal_error *error = opendal_init_env(reinterpret_cast<void *>(my_alloc), 
                                            reinterpret_cast<void *>(my_free),
                                            reinterpret_cast<void *>(ob_log_handler));
    ASSERT_EQ(error, nullptr);
  }

  static void TearDownTestCase()
  {
  }
protected:
  std::string base_path_;
  const opendal_operator *op_;
  ObSpan *ob_span_;
};

#endif