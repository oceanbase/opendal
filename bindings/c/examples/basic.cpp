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
#include "stdio.h"

int main()
{
    opendal_error *error = init_obdal_env();
    assert(error == nullptr);
    ObSpan *ob_span = ob_new_span(1, "test-trace");
    assert(ob_span != nullptr);
    
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
    assert(result.op != NULL);
    assert(result.error == NULL);

    opendal_operator* op = result.op;

    /* Prepare some data to be written */
    opendal_bytes data = {
        .data = (uint8_t*)"this_string_length_is_24",
        .len = 24,
    };

    /* Write this into path "/testpath" */
    error = opendal_operator_write(op, "/testpath", &data);
    assert(error == NULL);

    /* We can read it out, make sure the data is the same */
    opendal_result_read r = opendal_operator_read(op, "/testpath");
    opendal_bytes read_bytes = r.data;
    assert(r.error == NULL);
    assert(read_bytes.len == 24);

    /* Lets print it out */
    for (int i = 0; i < 24; ++i) {
        printf("%c", read_bytes.data[i]);
    }
    printf("\n");

    /* the opendal_bytes read is heap allocated, please free it */
    opendal_bytes_free(&read_bytes);

    /* the operator_ptr is also heap allocated */
    opendal_operator_free(op);
    ob_drop_span(ob_span);

    return 0;
}
