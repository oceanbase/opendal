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

#include "assert.h"
#include "opendal.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>

void *my_alloc(size_t size, size_t align) {
    // printf("my_alloc %zu %zu\n", size, align);
    return malloc(size);
}

void my_free(void *ptr) {
    // printf("my_free\n");
    free(ptr);
}

opendal_operator *init_operator()
{
    /* Initialize a operator for "memory" backend, with no options */
    opendal_operator_options *options = opendal_operator_options_new();
    opendal_operator_options_set(options, "bucket", "xxx");
    opendal_operator_options_set(options, "endpoint", "xxx");
    opendal_operator_options_set(options, "region", "xxx");
    opendal_operator_options_set(options, "access_key_id", "xxx");
    opendal_operator_options_set(options, "secret_access_key", "xxx");
    opendal_operator_options_set(options, "disable_config_load", "true");
    opendal_operator_options_set(options, "disable_ec2_metadata", "true");
    opendal_result_operator_new result = opendal_operator_new("s3", options);
    assert(result.op != nullptr);
    assert(result.error == nullptr);

    opendal_operator_options_free(options);
    return result.op;
}

void test_multipart(const opendal_operator *op)
{
    std::cout << "======================================= Begin test_multipart =======================================" << std::endl;
    assert(op != nullptr);
    const char *path = "testpath";
    opendal_result_operator_writer r_writer = opendal_operator_writer(op, path);
    assert(r_writer.error == nullptr);
    assert(r_writer.writer != nullptr);
    opendal_writer *writer = r_writer.writer;
    
    const int64_t data_size = 10 * 1024 * 1024LL;   // 10MB
    uint8_t *data_str = static_cast<uint8_t *>(malloc(data_size));
    assert(data_str != nullptr);
    memset(data_str, 'a', data_size);

    opendal_bytes data = {
        .data = data_str,
        .len = data_size,
    };
    opendal_result_writer_write r_writer_write = opendal_writer_write(writer, &data);
    assert(r_writer_write.error == nullptr);
    r_writer_write = opendal_writer_write(writer, &data);
    assert(r_writer_write.error == nullptr);
    
    // abort
    assert(nullptr == opendal_writer_abort(writer));
    
    // should fail
    r_writer_write = opendal_writer_write(writer, &data);
    assert(r_writer_write.error != nullptr);
    std::cout << r_writer_write.error->code << std::endl;
    std::cout << (const char *)(r_writer_write.error->message.data) << std::endl;
    std::cout << "======================================= Finish test_multipart =======================================" << std::endl;
}

void test_rw(const opendal_operator *op)
{
    std::cout << "======================================= Begin test_rw =======================================" << std::endl;
    assert(op != nullptr);
    opendal_bytes data = {
        .data = (uint8_t*)"this_string_length_is_24",
        .len = 24,
    };

    /* Write this into path "/testpath" */
    opendal_error *error = opendal_operator_write(op, "/testpath", &data);
    assert(error == nullptr);

    /* We can read it out, make sure the data is the same */
    opendal_result_operator_reader result_reader = opendal_operator_reader(op, "/testpath");
    assert(result_reader.error == nullptr);
    // The reader is in result.reader
    opendal_reader *reader = result_reader.reader;
    assert(reader != nullptr);

    uint8_t buf[100] = { 0 };
    opendal_result_reader_read result_reader_read = opendal_reader_read(reader, buf, 6, 5);
    assert(result_reader_read.error == nullptr);
    assert(result_reader_read.size == 6);

    /* Lets print it out */
    printf("read result:");
    for (int i = 0; i < 6; ++i) {
        printf("%c", buf[i]);
        assert(buf[i] == data.data[i + 5]);
    }
    printf("\n");
    std::cout << "======================================= Finish test_rw =======================================" << std::endl;
}

void test_tagging(const opendal_operator *op) 
{
    std::cout << "======================================= Begin test_tagging =======================================" << std::endl;
    assert(op != nullptr);
    opendal_bytes data = {
        .data = (uint8_t*)"this_string_length_is_24",
        .len = 24,
    };
    /* Write this into path "/testpath" */
    opendal_error *error = opendal_operator_write(op, "/testpath", &data);
    assert(error == nullptr);

    // test when tagging is not exist
    {
        opendal_result_get_object_tagging result = opendal_operator_get_object_tagging(op, "/testpath");
        assert(result.error == nullptr);
        assert(result.tagging != nullptr);

        opendal_result_object_tagging_get result2 = opendal_object_tagging_get(result.tagging, "key");
        assert(result2.error == nullptr);
        assert(result2.value.len == 0);

        opendal_object_tagging_free(result.tagging);
        opendal_bytes_free(&result2.value);
    }

    // test put_object_tagging
    {
        opendal_object_tagging *tagging = opendal_object_tagging_new();
        assert(tagging != nullptr);
        opendal_object_tagging_set(tagging, "key", "value");
        opendal_object_tagging_set(tagging, "key2", "value2");
        opendal_error *error = opendal_operator_put_object_tagging(op, "/testpath", tagging);
        assert(error == nullptr);
        
        opendal_object_tagging_free(tagging);
    }

    // test get_object_tagging
    {
        opendal_result_get_object_tagging result = opendal_operator_get_object_tagging(op, "/testpath");
        assert(result.error == nullptr);
        assert(result.tagging != nullptr);
        // 

        opendal_result_object_tagging_get result2 = opendal_object_tagging_get(result.tagging, "key");
        assert(result2.error == nullptr);
        assert(std::strcmp((char *)result2.value.data, "value") == 0);

        opendal_result_object_tagging_get result3 = opendal_object_tagging_get(result.tagging, "key2");
        assert(result3.error == nullptr);
        assert(std::strcmp((char *)result3.value.data, "value2") == 0);

        opendal_bytes_free(&result2.value);
        opendal_bytes_free(&result3.value);
        opendal_object_tagging_free(result.tagging);
    }
    
    std::cout << "======================================= Finish test_tagging =======================================" << std::endl;
}

void test_list(const opendal_operator *op)
{
    std::cout << "======================================= Begin test_list =======================================" << std::endl;
    assert(op != nullptr);
    opendal_bytes data = {
        .data = (uint8_t*)"this_string_length_is_24",
        .len = 24,
    };
            
    opendal_error *error = opendal_operator_write(op, "testpath/a", &data);
    assert(error == nullptr);
    error = opendal_operator_write(op, "testpath/b", &data);
    assert(error == nullptr);
    error = opendal_operator_write(op, "testpath/c/d", &data);
    assert(error == nullptr);

    {
        // recursive = true
        opendal_result_list l = opendal_operator_list(op, "testpath/", 1000, true/*recursive*/, "testpath/a");
        assert(l.error == nullptr);
        assert(l.lister != nullptr);
        opendal_lister *lister = l.lister;

        opendal_entry *entry = nullptr;

        // first should be testpath/b
        opendal_result_lister_next r_lister_next = opendal_lister_next(lister);
        assert(r_lister_next.error == nullptr);
        assert((entry = r_lister_next.entry) != nullptr);
        assert(0 == strcmp("testpath/b", opendal_entry_path(entry)));
        // check file length
        opendal_metadata *meta = opendal_entry_metadata(entry);
        assert(meta != nullptr);
        assert(data.len == opendal_metadata_content_length(meta));
        opendal_metadata_free(meta);
        opendal_entry_free(entry);
        entry = nullptr;

        // second should be testpath/c/d
        r_lister_next = opendal_lister_next(lister);
        assert(r_lister_next.error == nullptr);
        assert((entry = r_lister_next.entry) != nullptr);
        assert(0 == strcmp("testpath/c/d", opendal_entry_path(entry)));
        opendal_entry_free(entry);
        entry = nullptr;

        // end
        r_lister_next = opendal_lister_next(lister);
        assert(r_lister_next.error == nullptr);
        assert(r_lister_next.entry == nullptr);
        opendal_lister_free(lister);
    }

    {
        // recursive = false
        opendal_result_list l = opendal_operator_list(op, "testpath/", 1000, false/*recursive*/, "testpath/a");
        assert(l.error == nullptr);
        assert(l.lister != nullptr);
        opendal_lister *lister = l.lister;

        opendal_entry *entry = nullptr;

        // first should be testpath/c/, because common prefix is handled first
        opendal_result_lister_next r_lister_next = opendal_lister_next(lister);
        assert(r_lister_next.error == nullptr);
        assert((entry = r_lister_next.entry) != nullptr);
        assert(0 == strcmp("testpath/c/", opendal_entry_path(entry)));
        opendal_entry_free(entry);
        entry = nullptr;

        // second should be testpath/b
        r_lister_next = opendal_lister_next(lister);
        assert(r_lister_next.error == nullptr);
        assert((entry = r_lister_next.entry) != nullptr);
        assert(0 == strcmp("testpath/b", opendal_entry_path(entry)));
        opendal_entry_free(entry);
        entry = nullptr;

        // end
        r_lister_next = opendal_lister_next(lister);
        assert(r_lister_next.error == nullptr);
        assert(r_lister_next.entry == nullptr);
        opendal_lister_free(lister);
    }

    std::cout << "======================================= Finish test_list =======================================" << std::endl;
}

int main()
{
    opendal_error *error = init_obdal_env(nullptr, nullptr);
    assert(error != nullptr);
    printf("%s\n", error->message.data);

    error = init_obdal_env(reinterpret_cast<void *>(my_alloc), reinterpret_cast<void *>(my_free));
    assert(error == nullptr);
    ObSpan *ob_span = ob_new_span(1, "test-trace");
    assert(ob_span != nullptr);

    opendal_operator *op = init_operator();

    test_multipart(op);
    test_rw(op);
    test_tagging(op);
    test_list(op);

    /* the operator_ptr is also heap allocated */
    opendal_operator_free(op);
    ob_drop_span(ob_span);

    return 0;
}
