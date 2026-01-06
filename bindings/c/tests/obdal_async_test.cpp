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
#include <mutex>
#include <string>

std::string ObDalTest::base_path_ = "";

TEST_F(ObDalTest, test_rw)
{
  std::string path = base_path_ + "test_rw";
  opendal_bytes data = {
    .data = (uint8_t*)"this_string_length_is_24",
    .len = 24,
  };
  ObDalAsyncContext context;

  /* Write this into path "/testpath" */
  opendal_async_operator_write(async_op_, path.c_str(), &data, obdal_async_callback, &context);
  context.wait();
  dump_error(context.error_);
  ASSERT_EQ(context.error_, nullptr);

  /* We can read it out, make sure the data is the same */
  opendal_result_operator_reader result_reader = opendal_operator_reader(op_, path.c_str());
  ASSERT_EQ(result_reader.error, nullptr);
  // The reader is in result.reader
  opendal_reader *reader = result_reader.reader;
  ASSERT_TRUE(reader != nullptr);

  ObDalAsyncContext context2;
  uint8_t buf[100] = { 0 };
  opendal_async_operator_read(async_op_, path.c_str(), buf, 6, 5, obdal_async_callback, &context2);
  context2.wait();
  dump_error(context2.error_);
  ASSERT_EQ(context2.error_, nullptr);
  ASSERT_EQ(context2.length_, 6);

  /* Lets print it out */
  for (int i = 0; i < 6; ++i) {
    ASSERT_TRUE(buf[i] == data.data[i + 5]);
  }
  opendal_reader_free(reader);
}

TEST_F(ObDalTest, test_write_with_if_match)
{
  std::string path = base_path_ + "obdal_async_test_write_with_if_match";
  opendal_bytes data = {
    .data = (uint8_t*)"this_string_length_is_24",
    .len = 24,
  };
  ObDalAsyncContext context;
  opendal_async_operator_write_with_if_match(async_op_, path.c_str(), &data, obdal_async_callback, &context);
  context.wait();
  dump_error(context.error_);
  ASSERT_EQ(nullptr, context.error_);
  ASSERT_EQ(context.length_, 24);

  context.reset();
  opendal_bytes data2 = {
    .data = (uint8_t*)"this_string_length_Is_24",
    .len = 24,
  };
  opendal_async_operator_write_with_if_match(async_op_, path.c_str(), &data2, obdal_async_callback, &context);
  context.wait();
  dump_error(context.error_);
  ASSERT_NE(nullptr, context.error_);
  ASSERT_EQ(context.error_->code, OPENDAL_CONDITION_NOT_MATCH);
  ASSERT_EQ(context.length_, 0);

  context.reset();
  opendal_async_operator_write_with_if_match(async_op_, path.c_str(), &data, obdal_async_callback, &context);
  context.wait();
  dump_error(context.error_);
  ASSERT_EQ(nullptr, context.error_);
  ASSERT_EQ(context.length_, 24);


  context.reset();
  opendal_bytes data3 = {
    .data = (uint8_t*)"this_string",
    .len = 11,
  };
  opendal_async_operator_write_with_if_match(async_op_, path.c_str(), &data3, obdal_async_callback, &context);
  context.wait();
  dump_error(context.error_);
  ASSERT_NE(nullptr, context.error_);
  ASSERT_EQ(context.error_->code, OPENDAL_CONDITION_NOT_MATCH);
  ASSERT_EQ(context.length_, 0);
}

TEST_F(ObDalTest, test_parallel_read)
{
  std::string path = base_path_ + "test_parallel_read";
  const int64_t data_size = 24;
  opendal_bytes data = {
    .data = (uint8_t*)"this_string_length_is_24",
    .len = data_size,
  };

  ObDalAsyncContext context;
  opendal_async_operator_write(async_op_, path.c_str(), &data, obdal_async_callback, &context);
  context.wait();
  dump_error(context.error_);
  ASSERT_EQ(nullptr, context.error_);
  ASSERT_EQ(context.length_, data_size);

  int parallel_cnt = 100;
  std::vector<ObDalAsyncContext> contexts(parallel_cnt);
  std::vector<std::tuple<char *, int64_t, int64_t>> read_buf(parallel_cnt);
  for (int step = 0; step < parallel_cnt; step++) {
    int64_t offset = rand_int(0, data_size - 1);
    int64_t len = rand_int(1, data_size - offset);
    char *buf = static_cast<char *>(malloc(len));
    read_buf[step] = std::make_tuple(buf, len, offset);
    opendal_async_operator_read(async_op_, path.c_str(), (uint8_t *) buf, len, offset, obdal_async_callback, &contexts[step]);
  }
  for (int step = 0; step < parallel_cnt; step++) {
    contexts[step].wait();
  }

  for (int step = 0; step < parallel_cnt; step++) {
    dump_error(contexts[step].error_);
    ASSERT_EQ(nullptr, contexts[step].error_);
    ASSERT_EQ(contexts[step].length_, std::get<1>(read_buf[step]));
    ASSERT_EQ(0, strncmp(std::get<0>(read_buf[step]), 
                                    (char *)data.data + std::get<2>(read_buf[step]), 
                                     std::get<1>(read_buf[step])));
    free(std::get<0>(read_buf[step]));
  }
}

TEST_F(ObDalTest, test_ob_multipart)
{
  std::string path = base_path_ + "ob_multipart_file";
  opendal_async_multipart_writer *writer = nullptr;
  opendal_error *error = opendal_async_operator_multipart_writer(async_op_, path.c_str(), &writer);
  ASSERT_FALSE(error);
  ASSERT_TRUE(writer);
  error = opendal_async_multipart_writer_initiate(writer);
  ASSERT_FALSE(error);

  // generate write content
  const int64_t data_size = 48 * 1024 * 1024LL;
  char *data_str = static_cast<char *>(malloc(data_size));
  ASSERT_TRUE(data_str);
  ASSERT_TRUE(generate_random_bytes(data_str, data_size));

  const int64_t range_count = 8;
  std::vector<int64_t> borders;
  std::vector<std::tuple<int64_t, int64_t, int64_t>> ranges;
  ASSERT_TRUE(divide_interval_evenly(0, data_size - 1, range_count, ranges));
  shuffle_vec(ranges);


  std::vector<ObDalAsyncContext> contexts(range_count);
  for (int64_t step = 0; step < range_count; step++) {
    opendal_bytes data = {
      .data = (uint8_t *) (data_str + std::get<0>(ranges[step])),
      .len = (uintptr_t) (std::get<1>(ranges[step]) - std::get<0>(ranges[step])),
    };
    opendal_async_multipart_writer_write(writer, &data, std::get<2>(ranges[step]), obdal_async_callback, &contexts[step]);
  }

  for (int step = 0; step < range_count; step++) {
    {
      std::unique_lock<std::mutex> lock(contexts[step].mutex_);
      contexts[step].cv_.wait(lock, [&contexts, step] { return contexts[step].completed_; });
    }
    dump_error(contexts[step].error_);
    ASSERT_EQ(nullptr, contexts[step].error_);
    ASSERT_EQ(contexts[step].length_, std::get<1>(ranges[step]) - std::get<0>(ranges[step]));
  }

  error = opendal_async_multipart_writer_close(writer);
  dump_error(error);
  ASSERT_EQ(nullptr, error);

  opendal_result_operator_reader result_operator_reader = opendal_operator_reader(op_, path.c_str());
  ASSERT_FALSE(result_operator_reader.error);
  opendal_reader *reader = result_operator_reader.reader;
  ASSERT_TRUE(reader);
  char *read_buf = static_cast<char *>(malloc(data_size));
  ASSERT_TRUE(read_buf);
  opendal_result_reader_read result_reader_read = opendal_reader_read(reader, (uint8_t *) read_buf, data_size, 0/*offset*/);
  dump_error(result_reader_read.error);
  ASSERT_EQ(nullptr, result_reader_read.error);
  ASSERT_EQ(result_reader_read.size, data_size);
  ASSERT_EQ(0, strncmp(data_str, read_buf, data_size));

  opendal_reader_free(reader);
  free(read_buf);
  opendal_async_multipart_writer_free(writer);
  free(data_str);

  {
    opendal_async_multipart_writer *writer = nullptr;
    opendal_error *error = opendal_async_operator_multipart_writer(async_op_, path.c_str(), &writer);
    ASSERT_FALSE(error);
    ASSERT_TRUE(writer);

    error = opendal_async_multipart_writer_initiate(writer);
    ASSERT_FALSE(error);

    error = opendal_async_multipart_writer_abort(writer);
    ASSERT_FALSE(error);

    opendal_async_multipart_writer_free(writer);
    writer = nullptr;
  }

  {
    opendal_async_multipart_writer *writer = nullptr;
    opendal_error *error = opendal_async_operator_multipart_writer(async_op_, path.c_str(), &writer);
    ASSERT_FALSE(error);
    ASSERT_TRUE(writer);

    error = opendal_async_multipart_writer_initiate(writer);
    ASSERT_FALSE(error);

    opendal_async_multipart_writer_free(writer);
    writer = nullptr;
  }
}

int main(int argc, char **argv) 
{
  parse_service_arg(argc, argv);
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}