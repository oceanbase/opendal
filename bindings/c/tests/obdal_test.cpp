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

TEST_F(ObDalTest, test_rw)
{
  std::string path = base_path_ + "test_rw";
  opendal_bytes data = {
    .data = (uint8_t*)"this_string_length_is_24",
    .len = 24,
  };

  /* Write this into path "/testpath" */
  opendal_error *error = opendal_operator_write(op_, path.c_str(), &data);
  dump_error(error);
  ASSERT_EQ(error, nullptr);

  /* We can read it out, make sure the data is the same */
  opendal_result_operator_reader result_reader = opendal_operator_reader(op_, path.c_str());
  ASSERT_EQ(result_reader.error, nullptr);
  // The reader is in result.reader
  opendal_reader *reader = result_reader.reader;
  ASSERT_TRUE(reader != nullptr);

  uint8_t buf[100] = { 0 };
  opendal_result_reader_read result_reader_read = opendal_reader_read(reader, buf, 6, 5);
  ASSERT_TRUE(result_reader_read.error == nullptr);
  ASSERT_TRUE(result_reader_read.size == 6);

  /* Lets print it out */
  for (int i = 0; i < 6; ++i) {
    ASSERT_TRUE(buf[i] == data.data[i + 5]);
  }
  opendal_reader_free(reader);
}

TEST_F(ObDalTest, test_nohead_read)
{
  std::string path = base_path_ + "test_nohead_read";
  opendal_bytes data =  {
    .data = (uint8_t *)"123456789",
    .len = 9,
  };
  opendal_error *error = opendal_operator_write(op_, path.c_str(), &data);
  ASSERT_TRUE(error == nullptr);
  opendal_result_operator_reader result_reader = opendal_operator_reader(op_, path.c_str());
  ASSERT_TRUE(result_reader.error == nullptr);
  opendal_reader *reader = result_reader.reader;
  ASSERT_TRUE(reader != nullptr);

  uint8_t buf[100] = { 0 };
  opendal_result_reader_read result_reader_read = opendal_reader_read(reader, buf, 100, 5);
  ASSERT_TRUE(result_reader_read.error == nullptr);
  ASSERT_TRUE(result_reader_read.size == 4);

  /* Lets print it out */
  for (int i = 0; i < 4; ++i) {
    ASSERT_TRUE(buf[i] == data.data[i + 5]);
  }

  result_reader_read = opendal_reader_read(reader, buf, 100, 9);
  dump_error(result_reader_read.error);
  ASSERT_NE(result_reader_read.error, nullptr);
  free_error(result_reader_read.error);
  ASSERT_EQ(result_reader_read.size, 0);

  opendal_reader_free(reader);
  opendal_bytes_free(&data);
}

TEST_F(ObDalTest, test_tagging)
{
  std::string path = base_path_ + "test_tagging";
  opendal_bytes data = {
    .data = (uint8_t*)"this_string_length_is_24",
    .len = 24,
  };
  /* Write this into path "/testpath" */
  opendal_error *error = opendal_operator_write(op_, path.c_str(), &data);
  ASSERT_TRUE(error == nullptr);

  // test when tagging is not exist
  {
    opendal_result_get_object_tagging result = opendal_operator_get_object_tagging(op_, path.c_str());
    ASSERT_TRUE(result.error == nullptr);
    ASSERT_TRUE(result.tagging != nullptr);

    opendal_result_object_tagging_get result2 = opendal_object_tagging_get(result.tagging, "key");
    ASSERT_TRUE(result2.error == nullptr);
    ASSERT_TRUE(result2.value.len == 0);

    opendal_object_tagging_free(result.tagging);
    opendal_bytes_free(&result2.value);
  }

  // test put_object_tagging
  {
    opendal_object_tagging *tagging = opendal_object_tagging_new();
    ASSERT_TRUE(tagging != nullptr);
    opendal_object_tagging_set(tagging, "key", "value");
    opendal_object_tagging_set(tagging, "key2", "value2");
    opendal_error *error = opendal_operator_put_object_tagging(op_, path.c_str(), tagging);
    dump_error(error);
    ASSERT_TRUE(error == nullptr);

    opendal_object_tagging_free(tagging);
  }

  // test get_object_tagging
  {
    opendal_result_get_object_tagging result = opendal_operator_get_object_tagging(op_, path.c_str());
    ASSERT_TRUE(result.error == nullptr);
    ASSERT_TRUE(result.tagging != nullptr);

    opendal_result_object_tagging_get result2 = opendal_object_tagging_get(result.tagging, "key");
    ASSERT_TRUE(result2.error == nullptr);
    ASSERT_TRUE(strcmp(result2.value, "value") == 0);

    opendal_result_object_tagging_get result3 = opendal_object_tagging_get(result.tagging, "key2");
    ASSERT_TRUE(result3.error == nullptr);
    ASSERT_TRUE(strcmp(result3.value, "value2") == 0);

    opendal_bytes_free(&result2.value);
    opendal_bytes_free(&result3.value);
    opendal_object_tagging_free(result.tagging);
  }
}

TEST_F(ObDalTest, test_list)
{
  std::string path = base_path_ + "test_list/";
  opendal_bytes data = {
    .data = (uint8_t*)"this_string_length_is_24",
    .len = 24,
  };
          
  opendal_error *error = opendal_operator_write(op_, (path + "a").c_str(), &data);
  ASSERT_TRUE(error == nullptr);
  error = opendal_operator_write(op_, (path + "b").c_str(), &data);
  ASSERT_TRUE(error == nullptr);
  error = opendal_operator_write(op_, (path + "c/b").c_str(), &data);
  ASSERT_TRUE(error == nullptr);
  {
    // recursive = true
    opendal_result_list l = opendal_operator_list(op_, path.c_str(), 1, true/*recursive*/, (path + "a").c_str());
    ASSERT_TRUE(l.error == nullptr);
    ASSERT_TRUE(l.lister != nullptr);
    opendal_lister *lister = l.lister;

    opendal_entry *entry = nullptr;

    // first should be testpath/b
    opendal_result_lister_next r_lister_next = opendal_lister_next(lister);
    ASSERT_TRUE(r_lister_next.error == nullptr);
    ASSERT_TRUE(r_lister_next.entry != nullptr);
    entry = r_lister_next.entry;
    char *entry_path = opendal_entry_path(entry); 
    ASSERT_TRUE(0 == strcmp((path + "b").c_str(), entry_path));
    my_free(entry_path);
    // check file length
    opendal_metadata *meta = opendal_entry_metadata(entry);
    ASSERT_TRUE(meta != nullptr);
    ASSERT_TRUE(data.len == opendal_metadata_content_length(meta));
    opendal_metadata_free(meta);
    opendal_entry_free(entry);
    entry = nullptr;

    // second should be testpath/c/d
    r_lister_next = opendal_lister_next(lister);
    ASSERT_TRUE(r_lister_next.error == nullptr);
    ASSERT_TRUE(r_lister_next.entry != nullptr);
    entry = r_lister_next.entry;
    entry_path = opendal_entry_path(entry);
    ASSERT_TRUE(0 == strcmp((path + "c/b").c_str(), entry_path));
    my_free(entry_path);
    opendal_entry_free(entry);
    entry = nullptr;

    // end
    r_lister_next = opendal_lister_next(lister);
    ASSERT_TRUE(r_lister_next.error == nullptr);
    ASSERT_TRUE(r_lister_next.entry == nullptr);
    opendal_lister_free(lister);
  }

  {
    // recursive = false
    // The order in which the list is returned is not fixed and depends on the page.
    // If a page can fit all entries, folders will be returned first, and if not, files will be returned
    // therefore, when limit = 10, the order of entry is as follows:
    // c/
    // a
    // b
    opendal_result_list l = opendal_operator_list(op_, path.c_str(), 10, false/*recursive*/, "");
    ASSERT_TRUE(l.error == nullptr);
    ASSERT_TRUE(l.lister != nullptr);
    opendal_lister *lister = l.lister;
    opendal_entry *entry = nullptr;

    // first should be testpath/c/, because common prefix is handled first
    opendal_result_lister_next r_lister_next = opendal_lister_next(lister);
    ASSERT_TRUE(r_lister_next.error == nullptr);
    ASSERT_TRUE(r_lister_next.entry != nullptr);
    entry = r_lister_next.entry;
    char *entry_path = opendal_entry_path(entry);
    ASSERT_TRUE(0 == strcmp((path + "c/").c_str(), entry_path));
    my_free(entry_path);
    opendal_entry_free(entry);
    entry = nullptr;

    // second should be testpath/b
    r_lister_next = opendal_lister_next(lister);
    ASSERT_TRUE(r_lister_next.error == nullptr);
    ASSERT_TRUE(r_lister_next.entry != nullptr);
    entry = r_lister_next.entry;
    entry_path = opendal_entry_path(entry);
    ASSERT_TRUE(0 == strcmp((path + "a").c_str(), entry_path));
    my_free(entry_path);
    opendal_entry_free(entry);
    entry = nullptr;

    r_lister_next = opendal_lister_next(lister);
    ASSERT_TRUE(r_lister_next.error == nullptr);
    ASSERT_TRUE(r_lister_next.entry != nullptr);
    entry = r_lister_next.entry;
    entry_path = opendal_entry_path(entry);
    ASSERT_TRUE(0 == strcmp((path + "b").c_str(), entry_path));
    my_free(entry_path);
    opendal_entry_free(entry);
    entry = nullptr;

    // end
    r_lister_next = opendal_lister_next(lister);
    ASSERT_TRUE(r_lister_next.error == nullptr);
    ASSERT_TRUE(r_lister_next.entry == nullptr);
    opendal_lister_free(lister);
  }

  {
    // therefore, when limit = 1, the order of entry is as follows:
    // a
    // b
    // c/
    opendal_result_list l = opendal_operator_list(op_, path.c_str(), 1, false/*recursive*/, "");
    ASSERT_TRUE(l.error == nullptr);
    ASSERT_TRUE(l.lister != nullptr);
    opendal_lister *lister = l.lister;
    opendal_entry *entry = nullptr;

    // first should be testpath/c/, because common prefix is handled first
    opendal_result_lister_next r_lister_next = opendal_lister_next(lister);
    ASSERT_TRUE(r_lister_next.error == nullptr);
    ASSERT_TRUE(r_lister_next.entry != nullptr);
    entry = r_lister_next.entry;
    char *entry_path = opendal_entry_path(entry);
    std::cout << "entry_path:" << entry_path << std::endl;
    ASSERT_TRUE(0 == strcmp((path + "a").c_str(), entry_path));
    my_free(entry_path);
    opendal_entry_free(entry);
    entry = nullptr;

    // second should be testpath/b
    r_lister_next = opendal_lister_next(lister);
    ASSERT_TRUE(r_lister_next.error == nullptr);
    ASSERT_TRUE(r_lister_next.entry != nullptr);
    entry = r_lister_next.entry;
    entry_path = opendal_entry_path(entry);
    ASSERT_TRUE(0 == strcmp((path + "b").c_str(), entry_path));
    my_free(entry_path);
    opendal_entry_free(entry);
    entry = nullptr;

    // third shoudl be testpath/c/
    r_lister_next = opendal_lister_next(lister);
    ASSERT_TRUE(r_lister_next.error == nullptr);
    ASSERT_TRUE(r_lister_next.entry != nullptr);
    entry = r_lister_next.entry;
    entry_path = opendal_entry_path(entry);
    ASSERT_TRUE(0 == strcmp((path + "c/").c_str(), entry_path));
    my_free(entry_path);
    opendal_entry_free(entry);
    entry = nullptr;

    // end
    r_lister_next = opendal_lister_next(lister);
    ASSERT_TRUE(r_lister_next.error == nullptr);
    ASSERT_TRUE(r_lister_next.entry == nullptr);
    opendal_lister_free(lister);
  }
}

TEST_F(ObDalTest, test_wrong_endpoint)
{
  std::string test_wrong_endpoint = "aa." + std::string(endpoint);
  opendal_operator_options *options = opendal_operator_options_new();

  if (strcmp(scheme, "s3") == 0) {
      opendal_operator_options_set(options, "bucket", bucket);
      opendal_operator_options_set(options, "endpoint", test_wrong_endpoint.c_str());
      opendal_operator_options_set(options, "region", region);
      opendal_operator_options_set(options, "access_key_id", access_key_id);
      opendal_operator_options_set(options, "secret_access_key", secret_access_key);
      opendal_operator_options_set(options, "disable_config_load", "true");
      opendal_operator_options_set(options, "disable_ec2_metadata", "true");
      opendal_operator_options_set(options, "enable_virtual_host_style", "true");
    } else if (strcmp(scheme, "oss") == 0) {
      opendal_operator_options_set(options, "bucket", bucket);
      opendal_operator_options_set(options, "endpoint", test_wrong_endpoint.c_str());
      opendal_operator_options_set(options, "access_key_id", access_key_id);
      opendal_operator_options_set(options, "access_key_secret", secret_access_key);
    }

  opendal_result_operator_new tmp_result = opendal_operator_new(scheme, options);
  dump_error(tmp_result.error);
  ASSERT_TRUE(tmp_result.error == nullptr);
  opendal_operator_options_free(options);
  opendal_operator *op = tmp_result.op;
  ASSERT_TRUE(op);

  std::string path = base_path_ + "test_wrong_endpoint";
  opendal_bytes data = {
    .data = (uint8_t*)"this_string_length_is_24",
    .len = 24,
  };
  opendal_error *error =  opendal_operator_write(op, path.c_str(), &data);
  ASSERT_TRUE(error != nullptr);
  dump_error(error);
  ASSERT_TRUE(error->code == OPENDAL_INVALID_OBJECT_STORAGE_ENDPOINT);
  free_error(error);

  opendal_writer *writer = nullptr;
  opendal_result_operator_writer result = opendal_operator_writer(op, path.c_str());
  ASSERT_TRUE(result.error == nullptr);
  writer = result.writer;
  opendal_result_writer_write result2 = opendal_writer_write(writer, &data);
  ASSERT_TRUE(result2.error == nullptr);
  opendal_error *error2 = opendal_writer_close(writer);
  ASSERT_TRUE(error2 != nullptr);
  ASSERT_TRUE(error2->code == OPENDAL_INVALID_OBJECT_STORAGE_ENDPOINT);
  free_error(error2);
  opendal_writer_free(writer);
  opendal_operator_free(op);
}

TEST_F(ObDalTest, test_batch_delete)
{
  // This case not support for gcs
  std::string path = base_path_ + "test_batch_delete/";
  opendal_bytes data = {
    .data = (uint8_t*)"this_string_length_is_24",
    .len = 24,
  };

  // First, write some file
  opendal_error *error = opendal_operator_write(op_, (path + "a").c_str(), &data);
  ASSERT_TRUE(error == nullptr);
  error = opendal_operator_write(op_, (path + "b").c_str(), &data);
  ASSERT_TRUE(error == nullptr);
  error = opendal_operator_write(op_, (path + "c/d").c_str(), &data);
  ASSERT_TRUE(error == nullptr);
  opendal_result_exists result_exists = opendal_operator_exists(op_, (path + "a").c_str());
  ASSERT_TRUE(result_exists.error == nullptr);
  ASSERT_TRUE(result_exists.exists == true);

  opendal_result_operator_deleter result_deleter = opendal_operator_deleter(op_);
  ASSERT_TRUE(result_deleter.error == nullptr);
  ASSERT_TRUE(result_deleter.deleter != nullptr);
  opendal_deleter *deleter = result_deleter.deleter;

  // Second, add some files to the deleter
  error = opendal_deleter_delete(deleter, (path + "a").c_str());
  ASSERT_TRUE(error == nullptr);
  error = opendal_deleter_delete(deleter, (path + "b").c_str());
  ASSERT_TRUE(error == nullptr);
  error = opendal_deleter_delete(deleter, (path + "c/d").c_str());
  ASSERT_TRUE(error == nullptr);
  error = opendal_deleter_delete(deleter, (path + "fake-object").c_str());
  ASSERT_TRUE(error == nullptr);

  // Third, flush the deleter.
  // Notice that the no-exist file should be deleted successfully.
  opendal_result_deleter_flush result = opendal_deleter_flush(deleter);
  dump_error(result.error);
  ASSERT_TRUE(result.error == nullptr);
  ASSERT_EQ(result.deleted, 4);

  result = opendal_deleter_flush(deleter);
  dump_error(result.error);
  ASSERT_EQ(result.error, nullptr);
  ASSERT_EQ(result.deleted, 0);

  opendal_result_deleter_deleted result_deleted = opendal_deleter_deleted(deleter, (path + "a").c_str());
  dump_error(result_deleted.error);
  ASSERT_EQ(nullptr, result_deleted.error);
  ASSERT_TRUE(result_deleted.deleted);
  result_deleted = opendal_deleter_deleted(deleter, (path + "b").c_str());
  ASSERT_EQ(nullptr, result_deleted.error);
  ASSERT_TRUE(result_deleted.deleted);
  result_deleted = opendal_deleter_deleted(deleter, (path + "c/d").c_str());
  ASSERT_EQ(nullptr, result_deleted.error);
  ASSERT_TRUE(result_deleted.deleted);
  result_deleted = opendal_deleter_deleted(deleter, (path + "fake-object").c_str());
  ASSERT_EQ(nullptr, result_deleted.error);
  ASSERT_TRUE(result_deleted.deleted);

  opendal_deleter_free(deleter);

  result_exists = opendal_operator_exists(op_, (path + "a").c_str());
  ASSERT_TRUE(result_exists.error == nullptr);
  ASSERT_TRUE(result_exists.exists == false);
}

TEST_F(ObDalTest, test_list_directories)
{
  int file_cnt = 10;
  std::string path = base_path_ + "test_list_directories/";

  // write file first, common prefix is path
  // 0/0
  // 1/1
  // 2/2
  // 3/3
  // 4/4
  // 0/5
  // 1/6
  // 2/7
  // 3/8
  // 4/9
  // 10
  for (int i = 0; i < file_cnt; i++) {
    std::string file_path = "";
    if (i < 5) {
      file_path = path + std::to_string(i) + "/" + std::to_string(i);
    } else {
      file_path = path + std::to_string(i - 5) + "/" + std::to_string(i);
    }

    std::string file_content = "file content of file " + std::to_string(i);
    opendal_bytes data = {
      .data = (uint8_t*) file_content.c_str(),
      .len = file_content.size(),
    };
    ASSERT_EQ(nullptr, opendal_operator_write(op_, file_path.c_str(), &data));
  }

  std::string file_path = path + std::to_string(10);
  std::string file_content = "file content of file " + std::to_string(10);
  opendal_bytes data = {
    .data = (uint8_t*) file_content.c_str(),
    .len = file_content.size(),
  };
  ASSERT_EQ(nullptr, opendal_operator_write(op_, file_path.c_str(), &data));

  // we list all file and directories in path, notice that recursive is false.
  // so the answer must be:
  // 0/
  // 1/
  // 2/
  // 3/
  // 4/
  // 10
  // Then we filtered out the file, the answer contains only the directories
  std::vector<std::string> directories;
  opendal_result_list result = opendal_operator_list(op_, path.c_str(), 1000, false/*recursive*/, "");
  ASSERT_EQ(nullptr, result.error);
  opendal_lister *lister = result.lister;
  ASSERT_TRUE(lister);
  opendal_result_lister_next result2 = opendal_lister_next(lister);
  ASSERT_EQ(nullptr, result2.error);
  opendal_entry *entry = result2.entry;
  while (entry != nullptr) {
    // std::cout << "#[entry path]: " << opendal_entry_path(entry) << std::endl;
    // std::cout << "#[entry name]: " << opendal_entry_name(entry) << std::endl;
    char *entry_name_buf = opendal_entry_name(entry);
    std::string entry_name(entry_name_buf);
    my_free(entry_name_buf);
    ASSERT_TRUE(entry_name.size() > 0);
    if (entry_name.back() == '/') {
      directories.push_back(entry_name);
    }
    opendal_entry_free(entry);
    opendal_result_lister_next result = opendal_lister_next(lister);
    ASSERT_EQ(nullptr, result.error);
    entry = result.entry;
  }

  ASSERT_EQ(directories, std::vector<std::string>({
    "0/",
    "1/",
    "2/",
    "3/",
    "4/",
  }));

  if (entry != nullptr) {
    opendal_entry_free(entry);
  }
  if (lister != nullptr) {
    opendal_lister_free(lister);
  }
}

// This case is use to test multipart writing by Writer.
TEST_F(ObDalTest, test_multipart)
{
  {
    std::string path = base_path_ + "multipart_file";
    opendal_result_operator_writer result_operator_writer = opendal_operator_writer(op_, path.c_str());
    ASSERT_FALSE(result_operator_writer.error);
    opendal_writer *writer = result_operator_writer.writer;
    ASSERT_TRUE(writer);

    // generate write content
    const int64_t data_size = 10 * 1024 * 1024LL;
    char *data_str = static_cast<char *>(malloc(data_size));
    ASSERT_TRUE(data_str != nullptr);
    ASSERT_TRUE(generate_random_bytes(data_str, data_size));
    opendal_bytes data = {
      .data = (uint8_t *) data_str,
      .len = data_size,
    };

    opendal_result_writer_write result_writer_write = opendal_writer_write(writer, &data);
    ASSERT_FALSE(result_writer_write.error);
    ASSERT_EQ(result_writer_write.size, data_size);
    opendal_error *error = opendal_writer_close(writer);
    ASSERT_FALSE(error);
    opendal_writer_free(writer);

    opendal_result_operator_reader result_operator_reader = opendal_operator_reader(op_, path.c_str());
    ASSERT_FALSE(result_operator_reader.error);
    opendal_reader *reader = result_operator_reader.reader;
    ASSERT_TRUE(reader);
    char *read_buf = static_cast<char *>(malloc(data_size));
    ASSERT_TRUE(read_buf);
    opendal_result_reader_read result_reader_read = opendal_reader_read(reader, (uint8_t *) read_buf, data_size, 0/*offset*/);
    ASSERT_FALSE(result_reader_read.error);
    ASSERT_EQ(result_reader_read.size, data_size);
    ASSERT_EQ(0, strncmp(data_str, read_buf, data_size));
    free(read_buf);
    free(data_str);
    opendal_reader_free(reader);
  }
  {
    std::string path = base_path_ + "test_multipart2";
    opendal_result_operator_writer r_writer = opendal_operator_writer(op_, path.c_str());
    ASSERT_TRUE(r_writer.error == nullptr);
    ASSERT_TRUE(r_writer.writer != nullptr);
    opendal_writer *writer = r_writer.writer;

    const int64_t data_size = 10 * 1024 * 1024LL;   // 10KB
    uint8_t *data_str = static_cast<uint8_t *>(malloc(data_size));
    ASSERT_TRUE(data_str != nullptr);
    memset(data_str, 'a', data_size);

    opendal_bytes data = {
        .data = data_str,
        .len = data_size,
    };
    opendal_result_writer_write r_writer_write = opendal_writer_write(writer, &data);
    ASSERT_TRUE(r_writer_write.error == nullptr);
    r_writer_write = opendal_writer_write(writer, &data);
    ASSERT_TRUE(r_writer_write.error == nullptr);

    // abort
    opendal_error *error = opendal_writer_abort(writer);
    ASSERT_TRUE(error == nullptr);

    // If the length does not exceed the buffer length, this operation does not return an error; 
    // if it does exceed, an error is returned.
    r_writer_write = opendal_writer_write(writer, &data);
    ASSERT_TRUE(r_writer_write.error);
    dump_error(r_writer_write.error);

    error = opendal_writer_close(writer);
    ASSERT_TRUE(error);
    free_error(error);

    free_error(r_writer_write.error);
    free(data_str);
    opendal_writer_free(writer);
  }
}

// This case is use to test multipart writing by ObMultipartWriter
TEST_F(ObDalTest, test_ob_multipart)
{
  std::string path = base_path_ + "ob_multipart_file";
  opendal_result_operator_multipart_writer result = opendal_operator_multipart_writer(op_, path.c_str());
  ASSERT_FALSE(result.error);
  opendal_multipart_writer *writer = result.multipart_writer;
  ASSERT_TRUE(writer);
  opendal_error *error = opendal_multipart_writer_initiate(writer);
  ASSERT_FALSE(error);

  // generate write content
  const int64_t data_size = 24 * 1024 * 1024LL;
  char *data_str = static_cast<char *>(malloc(data_size));
  ASSERT_TRUE(data_str);
  ASSERT_TRUE(generate_random_bytes(data_str, data_size));

  const int64_t range_count = 4;
  std::vector<int64_t> borders;
  std::vector<std::tuple<int64_t, int64_t, int64_t>> ranges;
  ASSERT_TRUE(divide_interval_evenly(0, data_size - 1, range_count, ranges));
  shuffle_vec(ranges);

  for (int64_t step = 0; step < range_count; step++) {
    opendal_bytes data = {
      .data = (uint8_t *) (data_str + std::get<0>(ranges[step])),
      .len = (uintptr_t) (std::get<1>(ranges[step]) - std::get<0>(ranges[step])),
    };

    opendal_result_writer_write result = opendal_multipart_writer_write(writer, &data, std::get<2>(ranges[step]));
    dump_error(result.error);
    ASSERT_EQ(nullptr, result.error);
    ASSERT_EQ(result.size, data.len);
  }

  error = opendal_multipart_writer_close(writer);
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
  opendal_multipart_writer_free(writer);
  free(data_str);
}

TEST_F(ObDalTest, test_append_writer)
{
  if (strcmp(scheme, "oss") != 0) {
    return;
  }
  std::string path = base_path_ + "append_file";
  opendal_result_operator_writer result = opendal_operator_append_writer(op_, path.c_str());
  ASSERT_FALSE(result.error);
  opendal_writer *writer = result.writer;
  ASSERT_TRUE(writer);

  // generate write content
  const int64_t data_size = 24 * 1024 * 1024LL;
  char *data_str = static_cast<char *>(malloc(data_size));
  ASSERT_TRUE(data_str);
  ASSERT_TRUE(generate_random_bytes(data_str, data_size));

  std::vector<std::tuple<int64_t, int64_t, int64_t>> ranges;
  const int64_t range_count = 4;
  ASSERT_TRUE(divide_interval_evenly(0, data_size - 1, range_count, ranges));

  for (int step = 0; step < range_count; step++) {
    opendal_bytes data = {
      .data = (uint8_t *) (data_str + std::get<0>(ranges[step])),
      .len = (uintptr_t) (std::get<1>(ranges[step]) - std::get<0>(ranges[step])),
    };

    opendal_result_writer_write result = opendal_writer_write_with_offset(writer, std::get<0>(ranges[step]), &data);
    dump_error(result.error);
    ASSERT_EQ(nullptr, result.error);
    ASSERT_EQ(result.size, data.len);
  }

  {
    // test oss append offset not equal to length
    opendal_bytes data = {
      .data = (uint8_t *) data_str,
      .len = (uintptr_t) 1,
    };
    opendal_result_writer_write result = opendal_writer_write_with_offset(writer, 0, &data);
    dump_error(result.error);
    ASSERT_TRUE(result.error != nullptr);
    ASSERT_EQ(result.error->code, OPENDAL_PWRITE_OFFSET_NOT_MATCH);
    free_error(result.error);
  }

  opendal_error *error = opendal_writer_close(writer);
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
  opendal_writer_free(writer);
  free(data_str);
}

TEST_F(ObDalTest, test_catch_panic)
{
  opendal_error *error = opendal_panic_test();
  ASSERT_TRUE(error);
  dump_error(error);
  free_error(error);

  // TODO: op、writer 等相关函数空指针防御
  // opendal_result_stat result = opendal_operator_stat(nullptr, "test");
  // ASSERT_TRUE(result.error);
  // dump_error(result.error);
  // free_error(result.error);

  // opendal_result_writer_write result2 = opendal_writer_write(nullptr, nullptr);
  // ASSERT_TRUE(result2.error);
  // dump_error(result2.error);
  // free_error(result2.error);
}

int main(int argc, char **argv) 
{
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}