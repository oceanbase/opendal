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


#ifndef _OPENDAL_H
#define _OPENDAL_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/**
 * \brief The error code for all opendal APIs in C binding.
 * \todo The error handling is not complete, the error with error message will be
 * added in the future.
 */
typedef enum opendal_code {
  /**
   * returning it back. For example, s3 returns an internal service error.
   */
  OPENDAL_UNEXPECTED,
  /**
   * Underlying service doesn't support this operation.
   */
  OPENDAL_UNSUPPORTED,
  /**
   * The config for backend is invalid.
   */
  OPENDAL_CONFIG_INVALID,
  /**
   * The given path is not found.
   */
  OPENDAL_NOT_FOUND,
  /**
   * The given path doesn't have enough permission for this operation
   */
  OPENDAL_PERMISSION_DENIED,
  /**
   * The given path is a directory.
   */
  OPENDAL_IS_A_DIRECTORY,
  /**
   * The given path is not a directory.
   */
  OPENDAL_NOT_A_DIRECTORY,
  /**
   * The given path already exists thus we failed to the specified operation on it.
   */
  OPENDAL_ALREADY_EXISTS,
  /**
   * Requests that sent to this path is over the limit, please slow down.
   */
  OPENDAL_RATE_LIMITED,
  /**
   * The given file paths are same.
   */
  OPENDAL_IS_SAME_FILE,
  /**
   * The condition of this operation is not match.
   */
  OPENDAL_CONDITION_NOT_MATCH,
  /**
   * The range of the content is not satisfied.
   */
  OPENDAL_RANGE_NOT_SATISFIED,
  /**
   * The region name or The bucket name is invalid
   */
  OPENDAL_INVALID_OBJECT_STORAGE_ENDPOINT,
  /**
   * This error is retured when the uploaded checksum does not match the checksum
   * calculated from the data accepted by the server.
   */
  OPENDAL_CHECKSUM_ERROR,
  /**
   * OpenDal returns this error to indicate that the region is not correct.
   */
  OPENDAL_REGION_MISMATCH,
  /**
   * The operation is timed out.
   */
  OPENDAL_TIMED_OUT,
  /**
   * checksum type is not supported
   */
  OPENDAL_CHECKSUM_UNSUPPORTED,
  /**
   * oss append write offset not equal to length
   */
  OPENDAL_PWRITE_OFFSET_NOT_MATCH,
  /**
   * object locked by worm
   */
  OPENDAL_FILE_IMMUTABLE,
  OPENDAL_OVERWRITE_CONTENT_MISMATCH,
} opendal_code;

/**
 * \brief opendal_bytes carries raw-bytes with its length
 *
 * The opendal_bytes type is a C-compatible substitute for Vec type
 * in Rust, it has to be manually freed. You have to call opendal_bytes_free()
 * to free the heap memory to avoid memory leak.
 *
 * @see opendal_bytes_free
 */
typedef struct opendal_bytes {
  /**
   * Pointing to the byte array on heap
   */
  uint8_t *data;
  /**
   * The length of the byte array
   */
  uintptr_t len;
  /**
   * The capacity of the byte array
   */
  uintptr_t capacity;
} opendal_bytes;

/**
 * \brief The opendal error type for C binding, containing an error code and corresponding error
 * message.
 *
 * The normal operations returns a pointer to the opendal_error, and the **nullptr normally
 * represents no error has taken placed**. If any error has taken place, the caller should check
 * the error code and print the error message.
 *
 * The error code is represented in opendal_code, which is an enum on different type of errors.
 * The error messages is represented in opendal_bytes, which is a non-null terminated byte array.
 *
 * \note 1. The error message is on heap, so the error needs to be freed by the caller, by calling
 *       opendal_error_free. 2. The error message is not null terminated, so the caller should
 *       never use "%s" to print the error message.
 *
 * @see opendal_code
 * @see opendal_bytes
 * @see opendal_error_free
 */
typedef struct opendal_error {
  enum opendal_code code;
  struct opendal_bytes message;
  bool is_temporary;
} opendal_error;

/**
 * \brief opendal_entry is the entry under a path, which is listed from the opendal_lister
 *
 * For examples, please see the comment section of opendal_operator_list()
 * @see opendal_operator_list()
 * @see opendal_entry_path()
 * @see opendal_entry_name()
 */
typedef struct opendal_entry {
  /**
   * The pointer to the opendal::Entry in the Rust code.
   * Only touch this on judging whether it is NULL.
   */
  void *inner;
} opendal_entry;

/**
 * \brief The result type returned by opendal_lister_next().
 * The list entry is the list result of the list operation, the error field is the error code and error message.
 * If the operation succeeds, the error should be NULL.
 *
 * \note Please notice if the lister reaches the end, both the list_entry and error will be NULL.
 */
typedef struct opendal_result_lister_next {
  /**
   * The next object name
   */
  struct opendal_entry *entry;
  /**
   * The error, if ok, it is null
   */
  struct opendal_error *error;
} opendal_result_lister_next;

/**
 * \brief BlockingLister is designed to list entries at given path in a blocking
 * manner.
 *
 * Users can construct Lister by `blocking_list` or `blocking_scan`(currently not supported in C binding)
 *
 * For examples, please see the comment section of opendal_operator_list()
 * @see opendal_operator_list()
 */
typedef struct opendal_lister {
  /**
   * The pointer to the opendal::BlockingLister in the Rust code.
   * Only touch this on judging whether it is NULL.
   */
  void *inner;
} opendal_lister;

/**
 * \brief The result type returned by opendal's deleter operation.
 *
 * \note The opendal_deleter actually owns a pointer to
 * a opendal::BlockingDeleter, which is inside the Rust core code.
 */
typedef struct opendal_deleter {
  /**
   * The pointer to the opendal::BlockingDeleter in the Rust code.
   * Only touch this on judging whether it is NULL.
   */
  void *inner;
} opendal_deleter;

/**
 *
 */
typedef struct opendal_result_deleter_deleted {
  /**
   *
   */
  bool deleted;
  /**
   *
   */
  struct opendal_error *error;
} opendal_result_deleter_deleted;

/**
 *
 */
typedef struct opendal_result_deleter_flush {
  uintptr_t deleted;
  struct opendal_error *error;
} opendal_result_deleter_flush;

/**
 * \brief Carries all metadata associated with a **path**.
 *
 * The metadata of the "thing" under a path. Please **only** use the opendal_metadata
 * with our provided API, e.g. opendal_metadata_content_length().
 *
 * \note The metadata is also heap-allocated, please call opendal_metadata_free() on this
 * to free the heap memory.
 *
 * @see opendal_metadata_free
 */
typedef struct opendal_metadata {
  /**
   * The pointer to the opendal::Metadata in the Rust code.
   * Only touch this on judging whether it is NULL.
   */
  void *inner;
} opendal_metadata;

/**
 * \brief Used to access almost all OpenDAL APIs. It represents an
 * operator that provides the unified interfaces provided by OpenDAL.
 *
 * @see opendal_operator_new This function construct the operator
 * @see opendal_operator_free This function frees the heap memory of the operator
 *
 * \note The opendal_operator actually owns a pointer to
 * an opendal::BlockingOperator, which is inside the Rust core code.
 *
 * \remark You may use the field `ptr` to check whether this is a NULL
 * operator.
 */
typedef struct opendal_operator {
  /**
   * The pointer to the opendal::BlockingOperator in the Rust code.
   * Only touch this on judging whether it is NULL.
   */
  void *inner;
  uint64_t tenant_id;
} opendal_operator;

/**
 * \brief The result type returned by opendal_operator_new() operation.
 *
 * If the init logic is successful, the `op` field will be set to a valid
 * pointer, and the `error` field will be set to null. If the init logic fails, the
 * `op` field will be set to null, and the `error` field will be set to a
 * valid pointer with error code and error message.
 *
 * @see opendal_operator_new()
 * @see opendal_operator
 * @see opendal_error
 */
typedef struct opendal_result_operator_new {
  /**
   * The pointer for operator.
   */
  struct opendal_operator *op;
  /**
   * The error pointer for error.
   */
  struct opendal_error *error;
} opendal_result_operator_new;

/**
 * \brief The configuration for the initialization of opendal_operator.
 *
 * \note This is also a heap-allocated struct, please free it after you use it
 *
 * @see opendal_operator_new has an example of using opendal_operator_options
 * @see opendal_operator_options_new This function construct the operator
 * @see opendal_operator_options_free This function frees the heap memory of the operator
 * @see opendal_operator_options_set This function allow you to set the options
 */
typedef struct opendal_operator_options {
  /**
   * The pointer to the HashMap<String, String> in the Rust code.
   * Only touch this on judging whether it is NULL.
   */
  void *inner;
} opendal_operator_options;

/**
 * \brief C++ ABI compatible operator configuration structure
 *
 * This structure is designed to avoid HashMap creation overhead.
 * C++ code can directly populate this struct and pass it to Rust.
 *
 * @see opendal_operator_new2 for blocking operator
 * @see opendal_async_operator_new for async operator
 * @see opendal_operator_config_new to allocate a new config
 * @see opendal_operator_config_free to free the config
 */
typedef struct opendal_operator_config {
  /**
   * Bucket name (S3/OSS) or container name (AzBlob)
   */
  const char *bucket;
  /**
   * Service endpoint
   */
  const char *endpoint;
  /**
   * Access Key ID (S3/OSS) or Account Name (AzBlob)
   */
  const char *access_key_id;
  /**
   * Secret Access Key (S3) / Access Key Secret (OSS) / Account Key (AzBlob)
   */
  const char *secret_access_key;
  /**
   * Timeout in seconds
   */
  uint64_t timeout;
  /**
   * Session Token
   */
  const char *session_token;
  /**
   * Tenant ID
   */
  uint64_t tenant_id;
  /**
   * Checksum algorithm (e.g., "md5", "crc32c", "crc32")
   */
  const char *checksum_algorithm;
  /**
   * Trace Id, thread local in oceanbase, long lifecycle
   */
  const char *trace_id;
  /**
   * AWS Region (S3 only)
   */
  const char *region;
  /**
   * Disable config loading from environment (S3 only)
   */
  bool disable_config_load;
  /**
   * Disable EC2 metadata (S3 only)
   */
  bool disable_ec2_metadata;
  /**
   * Enable virtual host style (S3 only)
   */
  bool enable_virtual_host_style;
  /**
   * Maximum retry times
   */
  uint64_t retry_max_times;
} opendal_operator_config;

/**
 * \brief The result type returned by opendal's read operation.
 *
 * The result type of read operation in opendal C binding, it contains
 * the data that the read operation returns and an NULL error.
 * If the read operation failed, the `data` fields should be a nullptr
 * and the error is not NULL.
 */
typedef struct opendal_result_read {
  /**
   * The byte array with length returned by read operations
   */
  struct opendal_bytes data;
  /**
   * The error, if ok, it is null
   */
  struct opendal_error *error;
} opendal_result_read;

/**
 * \brief The result type returned by opendal's reader operation.
 *
 * \note The opendal_reader actually owns a pointer to
 * a opendal::BlockingReader, which is inside the Rust core code.
 */
typedef struct opendal_reader {
  /**
   * The pointer to the opendal::BlockingReader in the Rust code.
   * Only touch this on judging whether it is NULL.
   */
  void *inner;
  uint64_t tenant_id;
} opendal_reader;

/**
 * \brief The result type returned by opendal_operator_reader().
 * The result type for opendal_operator_reader(), the field `reader` contains the reader
 * of the path, which is an iterator of the objects under the path. the field `code` represents
 * whether the stat operation is successful.
 */
typedef struct opendal_result_operator_reader {
  /**
   * The pointer for opendal_reader
   */
  struct opendal_reader *reader;
  /**
   * The error, if ok, it is null
   */
  struct opendal_error *error;
} opendal_result_operator_reader;

/**
 * \brief The result type returned by opendal's writer operation.
 * \note The opendal_writer actually owns a pointer to
 * an opendal::BlockingWriter, which is inside the Rust core code.
 */
typedef struct opendal_writer {
  /**
   * The pointer to the opendal::BlockingWriter in the Rust code.
   * Only touch this on judging whether it is NULL.
   */
  void *inner;
  uint64_t tenant_id;
} opendal_writer;

/**
 * \brief The result type returned by opendal_operator_writer().
 * The result type for opendal_operator_writer(), the field `writer` contains the writer
 * of the path, which is an iterator of the objects under the path. the field `code` represents
 */
typedef struct opendal_result_operator_writer {
  /**
   * The pointer for opendal_writer
   */
  struct opendal_writer *writer;
  /**
   * The error, if ok, it is null
   */
  struct opendal_error *error;
} opendal_result_operator_writer;

/**
 * \brief The result type returned by opendal's ob_multipart_writer operation.
 * \note The opendal_multipart_writer actually owns a pointer to
 * an opendal::BlockingObMultipartWriter, which is inside the Rust core code.
 */
typedef struct opendal_multipart_writer {
  /**
   * The pointer to the opendal::BlockingObMultipartWriter in the Rust code.
   * Only touch this on judging whether it is NULL.
   */
  void *inner;
  uint64_t tenant_id;
} opendal_multipart_writer;

/**
 * \brief The result type returned by opendal_operator_multipart_writer().
 * The result type for opendal_operator_multipart_writer(), the field `multipart_writer` contains the writer
 * of the path, which is an iterator of the objects under the path.
 */
typedef struct opendal_result_operator_multipart_writer {
  /**
   * The pointer for opendal_multipart_writer
   */
  struct opendal_multipart_writer *multipart_writer;
  /**
   * The error, if ok, it is null
   */
  struct opendal_error *error;
} opendal_result_operator_multipart_writer;

/**
 * \brief opendal_object_tagging is a C-compatible substitute for HashMap<String, String> in Rust
 */
typedef struct opendal_object_tagging {
  void *inner;
} opendal_object_tagging;

/**
 * \brief The result type returned by opendal_operator_get_object_tagging().
 *
 * The result type for opendal_operator_get_object_tagging(), the field `tagging`
 * contains the object tagging, and the field `error` contains the
 * corresponding error. If successful, the `error` field is null.
 */
typedef struct opendal_result_get_object_tagging {
  /**
   * The pointer for object tagging, if ok, it is not null
   */
  struct opendal_object_tagging *tagging;
  /**
   * The error, if ok, it is null
   */
  struct opendal_error *error;
} opendal_result_get_object_tagging;

/**
 * \brief The result type returned by opendal_operator_is_exist().
 *
 * The result type for opendal_operator_is_exist(), the field `is_exist`
 * contains whether the path exists, and the field `error` contains the
 * corresponding error. If successful, the `error` field is null.
 *
 * \note If the opendal_operator_is_exist() fails, the `is_exist` field
 * will be set to false.
 */
typedef struct opendal_result_is_exist {
  /**
   * Whether the path exists
   */
  bool is_exist;
  /**
   * The error, if ok, it is null
   */
  struct opendal_error *error;
} opendal_result_is_exist;

/**
 * \brief The result type returned by opendal_operator_exists().
 *
 * The result type for opendal_operator_exists(), the field `exists`
 * contains whether the path exists, and the field `error` contains the
 * corresponding error. If successful, the `error` field is null.
 *
 * \note If the opendal_operator_exists() fails, the `exists` field
 * will be set to false.
 */
typedef struct opendal_result_exists {
  /**
   * Whether the path exists
   */
  bool exists;
  /**
   * The error, if ok, it is null
   */
  struct opendal_error *error;
} opendal_result_exists;

/**
 * \brief The result type returned by opendal_operator_stat().
 *
 * The result type for opendal_operator_stat(), the field `meta` contains the metadata
 * of the path, the field `error` represents whether the stat operation is successful.
 * If successful, the `error` field is null.
 */
typedef struct opendal_result_stat {
  /**
   * The metadata output of the stat
   */
  struct opendal_metadata *meta;
  /**
   * The error, if ok, it is null
   */
  struct opendal_error *error;
} opendal_result_stat;

/**
 * \brief The result type returned by opendal_operator_list().
 *
 * The result type for opendal_operator_list(), the field `lister` contains the lister
 * of the path, which is an iterator of the objects under the path. the field `error` represents
 * whether the stat operation is successful. If successful, the `error` field is null.
 */
typedef struct opendal_result_list {
  /**
   * The lister, used for further listing operations
   */
  struct opendal_lister *lister;
  /**
   * The error, if ok, it is null
   */
  struct opendal_error *error;
} opendal_result_list;

/**
 * \brief The result type returned by opendal_operator_deleter().
 */
typedef struct opendal_result_operator_deleter {
  /**
   * The pointer for opendal_writer
   */
  struct opendal_deleter *deleter;
  /**
   * The error, if ok, it is null
   */
  struct opendal_error *error;
} opendal_result_operator_deleter;

/**
 * 异步操作 operator
 */
typedef struct opendal_async_operator {
  void *inner;
  uint64_t tenant_id;
  const char *trace_id;
} opendal_async_operator;

typedef void (*OpenDalAsyncCallbackFn)(struct opendal_error*, int64_t bytes, void *ctx);

/**
 * \brief Used to write a multipart file asynchronously.
 */
typedef struct opendal_async_multipart_writer {
  void *inner;
  uint64_t tenant_id;
  const char *trace_id;
} opendal_async_multipart_writer;

/**
 * \brief Metadata for **operator**, users can use this metadata to get information
 * of operator.
 */
typedef struct opendal_operator_info {
  /**
   * The pointer to the opendal::OperatorInfo in the Rust code.
   * Only touch this on judging whether it is NULL.
   */
  void *inner;
} opendal_operator_info;

/**
 * \brief Capability is used to describe what operations are supported
 * by current Operator.
 */
typedef struct opendal_capability {
  /**
   * If operator supports stat.
   */
  bool stat;
  /**
   * If operator supports stat with if match.
   */
  bool stat_with_if_match;
  /**
   * If operator supports stat with if none match.
   */
  bool stat_with_if_none_match;
  /**
   * If operator supports read.
   */
  bool read;
  /**
   * If operator supports read with if match.
   */
  bool read_with_if_match;
  /**
   * If operator supports read with if none match.
   */
  bool read_with_if_none_match;
  /**
   * if operator supports read with override cache control.
   */
  bool read_with_override_cache_control;
  /**
   * if operator supports read with override content disposition.
   */
  bool read_with_override_content_disposition;
  /**
   * if operator supports read with override content type.
   */
  bool read_with_override_content_type;
  /**
   * If operator supports write.
   */
  bool write;
  /**
   * If operator supports write can be called in multi times.
   */
  bool write_can_multi;
  /**
   * If operator supports write with empty content.
   */
  bool write_can_empty;
  /**
   * If operator supports write by append.
   */
  bool write_can_append;
  /**
   * If operator supports write with content type.
   */
  bool write_with_content_type;
  /**
   * If operator supports write with content disposition.
   */
  bool write_with_content_disposition;
  /**
   * If operator supports write with cache control.
   */
  bool write_with_cache_control;
  /**
   * write_multi_max_size is the max size that services support in write_multi.
   *
   * For example, AWS S3 supports 5GiB as max in write_multi.
   *
   * If it is not set, this will be zero
   */
  uintptr_t write_multi_max_size;
  /**
   * write_multi_min_size is the min size that services support in write_multi.
   *
   * For example, AWS S3 requires at least 5MiB in write_multi expect the last one.
   *
   * If it is not set, this will be zero
   */
  uintptr_t write_multi_min_size;
  /**
   * write_total_max_size is the max size that services support in write_total.
   *
   * For example, Cloudflare D1 supports 1MB as max in write_total.
   *
   * If it is not set, this will be zero
   */
  uintptr_t write_total_max_size;
  /**
   * If operator supports create dir.
   */
  bool create_dir;
  /**
   * If operator supports delete.
   */
  bool delete_;
  /**
   * If operator supports copy.
   */
  bool copy;
  /**
   * If operator supports rename.
   */
  bool rename;
  /**
   * If operator supports list.
   */
  bool list;
  /**
   * If backend supports list with limit.
   */
  bool list_with_limit;
  /**
   * If backend supports list with start after.
   */
  bool list_with_start_after;
  /**
   * If backend supports list without delimiter.
   */
  bool list_with_recursive;
  /**
   * If operator supports presign.
   */
  bool presign;
  /**
   * If operator supports presign read.
   */
  bool presign_read;
  /**
   * If operator supports presign stat.
   */
  bool presign_stat;
  /**
   * If operator supports presign write.
   */
  bool presign_write;
  /**
   * If operator supports shared.
   */
  bool shared;
  /**
   * If operator supports blocking.
   */
  bool blocking;
} opendal_capability;

/**
 * \brief The result type returned by opendal_object_tagging_get().
 */
typedef struct opendal_result_object_tagging_get {
  /**
   * The byte array indicated
   */
  struct opendal_bytes value;
  /**
   * TODO
   */
  struct opendal_error *error;
} opendal_result_object_tagging_get;

typedef struct ObSpan {
  void *span;
} ObSpan;

/**
 * \brief The is the result type returned by opendal_reader_read().
 * The result type contains a size field, which is the size of the data read,
 * which is zero on error. The error field is the error code and error message.
 */
typedef struct opendal_result_reader_read {
  /**
   * The read size if succeed.
   */
  uintptr_t size;
  /**
   * The error, if ok, it is null
   */
  struct opendal_error *error;
} opendal_result_reader_read;

/**
 * \brief The result type returned by opendal_writer_write().
 * The result type contains a size field, which is the size of the data written,
 * which is zero on error. The error field is the error code and error message.
 */
typedef struct opendal_result_writer_write {
  /**
   * The write size if succeed.
   */
  uintptr_t size;
  /**
   * The error, if ok, it is null
   */
  struct opendal_error *error;
} opendal_result_writer_write;

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

uint64_t opendal_get_tenant_id(void);

/**
 * return the c_char pointer of the trace_id, may be null
 * ownership remains with the TRACE_ID
 */
const char *opendal_get_trace_id(void);

void opendal_register_retry_timeout_fn(void *retry_timeout_ms_fn);

/**
 * \brief init opendal environment
 *
 * Task to initialize the environment include:
 * - init global allocator and releaser
 * - init global runtime
 * - init global http client
 * - init global log handler
 *
 * @param alloc: the function to allocate memory
 * @param free: the function to release memory
 * @param loghandler: the function to handle log message
 * @param thread_cnt: the thread count of global runtime
 * @param pool_max_idle_per_host: the max idle connection per host
 * @param pool_max_idle_time_s: the max idle time for a connection
 * @param connect_timeout_s: the connect timeout for a connection
 */
struct opendal_error *opendal_init_env(void *alloc,
                                       void *free,
                                       void *loghandler,
                                       uint32_t log_level,
                                       uintptr_t work_thread_cnt,
                                       uintptr_t block_thread_max_cnt,
                                       uint64_t block_thread_keep_alive_time_s,
                                       uintptr_t pool_max_idle_per_host,
                                       uint64_t pool_max_idle_time_s,
                                       uint64_t connect_timeout_s);

/**
 * \brief fin opendal environment
 *
 * Task to finalize the environment include:
 * - drop global runtime
 * - drop global http client
 */
void opendal_fin_env(void);

/**
 * \brief calc md5
 * please free the memory after using it
 */
char *opendal_calc_md5(const uint8_t *buf, uintptr_t buf_len);

/**
 * \brief Frees the opendal_error, ok to call on NULL
 */
void opendal_error_free(struct opendal_error *ptr);

/**
 * \brief Return the next object to be listed
 *
 * Lister is an iterator of the objects under its path, this method is the same as
 * calling next() on the iterator
 *
 * For examples, please see the comment section of opendal_operator_list()
 * @see opendal_operator_list()
 */
struct opendal_result_lister_next opendal_lister_next(struct opendal_lister *self);

/**
 * \brief Free the heap-allocated metadata used by opendal_lister
 */
void opendal_lister_free(struct opendal_lister *ptr);

/**
 * \brief append a path into the deleter
 */
struct opendal_error *opendal_deleter_delete(struct opendal_deleter *self, const char *path);

/**
 * \brief check the path is deleted
 */
struct opendal_result_deleter_deleted opendal_deleter_deleted(struct opendal_deleter *self,
                                                              const char *path);

/**
 * \brief delete all the paths in the deleter.
 */
struct opendal_result_deleter_flush opendal_deleter_flush(struct opendal_deleter *self);

/**
 * \brief Free the heap-allocated metadata used by opendal_lister
 */
void opendal_deleter_free(struct opendal_deleter *ptr);

/**
 * \brief Free the heap-allocated metadata used by opendal_metadata
 */
void opendal_metadata_free(struct opendal_metadata *ptr);

/**
 * \brief Return the content_length of the metadata
 *
 * # Example
 * ```C
 * // ... previously you wrote "Hello, World!" to path "/testpath"
 * opendal_result_stat s = opendal_operator_stat(op, "/testpath");
 * assert(s.error == NULL);
 *
 * opendal_metadata *meta = s.meta;
 * assert(opendal_metadata_content_length(meta) == 13);
 * ```
 */
uint64_t opendal_metadata_content_length(const struct opendal_metadata *self);

/**
 * \brief Return the content_md5 of the metadata
 */
char *opendal_metadata_content_md5(const struct opendal_metadata *self);

/**
 * \brief Return whether the path represents a file
 *
 * # Example
 * ```C
 * // ... previously you wrote "Hello, World!" to path "/testpath"
 * opendal_result_stat s = opendal_operator_stat(op, "/testpath");
 * assert(s.error == NULL);
 *
 * opendal_metadata *meta = s.meta;
 * assert(opendal_metadata_is_file(meta));
 * ```
 */
bool opendal_metadata_is_file(const struct opendal_metadata *self);

/**
 * \brief Return the etag of the metadata
 *
 * # Example
 * ```C
 * // ... previously you wrote "Hello, World!" to path "/testpath"
 * opendal_result_stat s = opendal_operator_stat(op, "/testpath");
 * assert(s.error == NULL);
 *
 * opendal_metadata *meta = s.meta;
 * assert(opendal_metadata_etag(meta) != NULL);
 * ```
 */
char *opendal_metadata_etag(const struct opendal_metadata *self);

/**
 * \brief Return whether the path represents a directory
 *
 * # Example
 * ```C
 * // ... previously you wrote "Hello, World!" to path "/testpath"
 * opendal_result_stat s = opendal_operator_stat(op, "/testpath");
 * assert(s.error == NULL);
 *
 * opendal_metadata *meta = s.meta;
 *
 * // this is not a directory
 * assert(!opendal_metadata_is_dir(meta));
 * ```
 *
 * \todo This is not a very clear example. A clearer example will be added
 * after we support opendal_operator_mkdir()
 */
bool opendal_metadata_is_dir(const struct opendal_metadata *self);

/**
 * \brief Return the last_modified of the metadata, in milliseconds
 *
 * # Example
 * ```C
 * // ... previously you wrote "Hello, World!" to path "/testpath"
 * opendal_result_stat s = opendal_operator_stat(op, "/testpath");
 * assert(s.error == NULL);
 *
 * opendal_metadata *meta = s.meta;
 * assert(opendal_metadata_last_modified_ms(meta) != -1);
 * ```
 */
int64_t opendal_metadata_last_modified_ms(const struct opendal_metadata *self);

/**
 * \brief Free the heap-allocated operator pointed by opendal_operator.
 *
 * Please only use this for a pointer pointing at a valid opendal_operator.
 * Calling this function on NULL does nothing, but calling this function on pointers
 * of other type will lead to segfault.
 *
 * # Example
 *
 * ```C
 * opendal_operator *op = opendal_operator_new("fs", NULL);
 * // ... use this op, maybe some reads and writes
 *
 * // free this operator
 * opendal_operator_free(op);
 * ```
 */
void opendal_operator_free(const struct opendal_operator *ptr);

/**
 * \brief Construct an operator based on `scheme` and `options`
 *
 * NOTICE: This interface has been deprecated, please use opendal_operator_new2 instead
 *
 * Uses an array of key-value pairs to initialize the operator based on provided `scheme`
 * and `options`. For each scheme, i.e. Backend, different options could be set, you may
 * reference the [documentation](https://opendal.apache.org/docs/category/services/) for
 * each service, especially for the **Configuration Part**.
 *
 * @param scheme the service scheme you want to specify, e.g. "fs", "s3", "supabase"
 * @param options the pointer to the options for this operator, it could be NULL, which means no
 * option is set
 * @see opendal_operator_options
 * @return A valid opendal_result_operator_new setup with the `scheme` and `options` is the construction
 * succeeds. On success the operator field is a valid pointer to a newly allocated opendal_operator,
 * and the error field is NULL. Otherwise, the operator field is a NULL pointer and the error field.
 *
 * # Example
 *
 * Following is an example.
 * ```C
 * // Allocate a new options
 * opendal_operator_options *options = opendal_operator_options_new();
 * // Set the options you need
 * opendal_operator_options_set(options, "root", "/myroot");
 *
 * // Construct the operator based on the options and scheme
 * opendal_result_operator_new result = opendal_operator_new("memory", options);
 * opendal_operator* op = result.op;
 *
 * // you could free the options right away since the options is not used afterwards
 * opendal_operator_options_free(options);
 *
 * // ... your operations
 * ```
 *
 * # Safety
 *
 * The only unsafe case is passing an invalid c string pointer to the `scheme` argument.
 */
struct opendal_result_operator_new opendal_operator_new(const char *scheme,
                                                        const struct opendal_operator_options *options);

/**
 * \brief Construct an operator based on `scheme` and `config` (optimized version)
 *
 * This is an optimized version of opendal_operator_new that avoids HashMap overhead
 * by directly using a configuration structure. This provides better performance for
 * operator initialization.
 *
 * @param scheme the service scheme you want to specify, e.g. "s3", "oss", "azblob"
 * @param config the pointer to the configuration structure
 * @see opendal_operator_config
 * @see opendal_operator_config_new
 * @return A valid opendal_result_operator_new with the operator and error fields
 *
 * # Example
 *
 * ```C
 * // Allocate a new config
 * opendal_operator_config *config = opendal_operator_config_new();
 *
 * // Set the required fields
 * config->bucket = "my-bucket";
 * config->endpoint = "https://s3.amazonaws.com";
 * config->access_key_id = "my-access-key";
 * config->secret_access_key = "my-secret-key";
 * config->region = "us-east-1";
 *
 * // Construct the operator based on the config and scheme
 * opendal_result_operator_new result = opendal_operator_new2("s3", config);
 * opendal_operator* op = result.op;
 *
 * // You can free the config right away since it's copied
 * opendal_operator_config_free(config);
 *
 * // ... your operations
 * ```
 *
 * # Safety
 *
 * The only unsafe case is passing invalid pointers to the `scheme` or `config` arguments.
 */
struct opendal_result_operator_new opendal_operator_new2(const char *scheme,
                                                         const struct opendal_operator_config *config);

/**
 * \brief Blocking write raw bytes to `path`.
 *
 * Write the `bytes` into the `path` blocking by `op_ptr`.
 * Error is NULL if successful, otherwise it contains the error code and error message.
 *
 * \note It is important to notice that the `bytes` that is passes in will be consumed by this
 *       function. Therefore, you should not use the `bytes` after this function returns.
 *
 * @param op The opendal_operator created previously
 * @param path The designated path you want to write your bytes in
 * @param bytes The opendal_byte typed bytes to be written
 * @see opendal_operator
 * @see opendal_bytes
 * @see opendal_error
 * @return NULL if succeeds, otherwise it contains the error code and error message.
 *
 * # Example
 *
 * Following is an example
 * ```C
 * //...prepare your opendal_operator, named op for example
 *
 * // prepare your data
 * char* data = "Hello, World!";
 * opendal_bytes bytes = opendal_bytes { .data = (uint8_t*)data, .len = 13 };
 *
 * // now you can write!
 * opendal_error *err = opendal_operator_write(op, "/testpath", bytes);
 *
 * // Assert that this succeeds
 * assert(err == NULL);
 * ```
 *
 * # Safety
 *
 * It is **safe** under the cases below
 * * The memory pointed to by `path` must contain a valid nul terminator at the end of
 *   the string.
 * * The `bytes` provided has valid byte in the `data` field and the `len` field is set
 *   correctly.
 *
 */
struct opendal_error *opendal_operator_write(const struct opendal_operator *op,
                                             const char *path,
                                             const struct opendal_bytes *bytes);

/**
 * write if match
 */
struct opendal_error *opendal_operator_write_with_if_match(const struct opendal_operator *op,
                                                           const char *path,
                                                           const struct opendal_bytes *bytes);

/**
 * write if none match
 */
struct opendal_error *opendal_operator_write_with_if_none_match(const struct opendal_operator *op,
                                                                const char *path,
                                                                const struct opendal_bytes *bytes);

/**
 * write if not exists
 */
struct opendal_error *opendal_operator_write_with_if_not_exists(const struct opendal_operator *op,
                                                                const char *path,
                                                                const struct opendal_bytes *bytes);

/**
 * \brief Blocking read the data from `path`.
 *
 * Read the data out from `path` blocking by operator.
 *
 * @param op The opendal_operator created previously
 * @param path The path you want to read the data out
 * @see opendal_operator
 * @see opendal_result_read
 * @see opendal_error
 * @return Returns opendal_result_read, the `data` field is a pointer to a newly allocated
 * opendal_bytes, the `error` field contains the error. If the `error` is not NULL, then
 * the operation failed and the `data` field is a nullptr.
 *
 * \note If the read operation succeeds, the returned opendal_bytes is newly allocated on heap.
 * After your usage of that, please call opendal_bytes_free() to free the space.
 *
 * # Example
 *
 * Following is an example
 * ```C
 * // ... you have write "Hello, World!" to path "/testpath"
 *
 * opendal_result_read r = opendal_operator_read(op, "testpath");
 * assert(r.error == NULL);
 *
 * opendal_bytes bytes = r.data;
 * assert(bytes.len == 13);
 * opendal_bytes_free(&bytes);
 * ```
 *
 * # Safety
 *
 * It is **safe** under the cases below
 * * The memory pointed to by `path` must contain a valid nul terminator at the end of
 *   the string.
 */
struct opendal_result_read opendal_operator_read(const struct opendal_operator *op,
                                                 const char *path);

/**
 * \brief Blocking read the data from `path`.
 *
 * Read the data out from `path` blocking by operator, returns
 * an opendal_result_read with error code.
 *
 * @param op The opendal_operator created previously
 * @param path The path you want to read the data out
 * @see opendal_operator
 * @see opendal_result_read
 * @see opendal_code
 * @return Returns opendal_code
 *
 * \note If the read operation succeeds, the returned opendal_bytes is newly allocated on heap.
 * After your usage of that, please call opendal_bytes_free() to free the space.
 *
 * # Example
 *
 * Following is an example
 * ```C
 * // ... you have created an operator named op
 *
 * opendal_result_operator_reader result = opendal_operator_reader(op, "/testpath");
 * assert(result.error == NULL);
 * // The reader is in result.reader
 * opendal_reader *reader = result.reader;
 * ```
 *
 * # Safety
 *
 * It is **safe** under the cases below
 * * The memory pointed to by `path` must contain a valid nul terminator at the end of
 *   the string.
 */
struct opendal_result_operator_reader opendal_operator_reader(const struct opendal_operator *op,
                                                              const char *path);

/**
 * \brief Blocking create a writer for the specified path.
 *
 * This function prepares a writer that can be used to write data to the specified path
 * using the provided operator. If successful, it returns a valid writer; otherwise, it
 * returns an error.
 *
 * @param op The opendal_operator created previously
 * @param path The designated path where the writer will be used
 * @see opendal_operator
 * @see opendal_result_operator_writer
 * @see opendal_error
 * @return Returns opendal_result_operator_writer, containing a writer and an opendal_error.
 * If the operation succeeds, the `writer` field holds a valid writer and the `error` field
 * is null. Otherwise, the `writer` will be null and the `error` will be set correspondingly.
 *
 * # Example
 *
 * Following is an example
 * ```C
 * //...prepare your opendal_operator, named op for example
 *
 * opendal_result_operator_writer result = opendal_operator_writer(op, "/testpath");
 * assert(result.error == NULL);
 * opendal_writer *writer = result.writer;
 * // Use the writer to write data...
 * ```
 *
 * # Safety
 *
 * It is **safe** under the cases below
 * * The memory pointed to by `path` must contain a valid nul terminator at the end of
 *   the string.
 */
struct opendal_result_operator_writer opendal_operator_writer(const struct opendal_operator *op,
                                                              const char *path);

/**
 * \brief Blocking create a append_writer for the specified path.
 *
 * This function prepares a append writer that can be used to append data to the specified path
 * using the provided operator. If successful, it returns a valid writer with append option; otherwise, it
 * returns an error.
 *
 * @param op The opendal_operator created previously
 * @param path The designated path where the writer will be used
 * @see opendal_operator
 * @see opendal_result_operator_writer
 * @see opendal_error
 * @return Returns opendal_result_operator_writer, containing a writer and an opendal_error.
 * If the operation succeeds, the `writer` field holds a valid writer and the `error` field
 * is null. Otherwise, the `writer` will be null and the `error` will be set correspondingly.
 *
 * # Safety
 *
 * It is **safe** under the cases below
 * * The memory pointed to by `path` must contain a valid nul terminator at the end of
 *   the string.
 */
struct opendal_result_operator_writer opendal_operator_append_writer(const struct opendal_operator *op,
                                                                     const char *path);

/**
 * \brief Blocking create a ob_multipart_writer for the specified path.
 *
 * ob_multipart_writer is designed to enable writing with a part ID. Although Opendal's
 * MultipartWriter automatically performs uploads based on buffer conditions, to maintain
 * compatibilty with ob's existing code logic, it is necessary to expose a method for
 * uplaoding with a specified part_id.
 *
 * This function prepares a ob_multipart_writer that can be used to write data to the
 * specified path using the provided operator. If successful, it returns a valid
 * ob_multipart_writer; otherwise, it returns an error.
 *
 * @param op The opendal_operator created previously
 * @param path The designated path where the writer will be used
 * @see opendal_operator
 * @see opendal_result_operator_multipart_writer.
 * @see opendal_error
 * @return Returns opendal_result_operator_multipart_writer, containing a multipart_writer
 * and an opendal_error.
 * If the operation succeeds, the `multipart_writer` field holds a valid writer and the `error` field
 * is null. Otherwise, the `multipart_writer` will be null and the `error` will be set correspondingly.
 */
struct opendal_result_operator_multipart_writer opendal_operator_multipart_writer(const struct opendal_operator *op,
                                                                                  const char *path);

/**
 * \brief Blocking delete the object in `path`.
 *
 * Delete the object in `path` blocking by `op_ptr`.
 * Error is NULL if successful, otherwise it contains the error code and error message.
 *
 * @param op The opendal_operator created previously
 * @param path The designated path you want to delete
 * @see opendal_operator
 * @see opendal_error
 * @return NULL if succeeds, otherwise it contains the error code and error message.
 *
 * # Example
 *
 * Following is an example
 * ```C
 * //...prepare your opendal_operator, named op for example
 *
 * // prepare your data
 * char* data = "Hello, World!";
 * opendal_bytes bytes = opendal_bytes { .data = (uint8_t*)data, .len = 13 };
 * opendal_error *error = opendal_operator_write(op, "/testpath", bytes);
 *
 * assert(error == NULL);
 *
 * // now you can delete!
 * opendal_error *error = opendal_operator_delete(op, "/testpath");
 *
 * // Assert that this succeeds
 * assert(error == NULL);
 * ```
 *
 * # Safety
 *
 * It is **safe** under the cases below
 * * The memory pointed to by `path` must contain a valid nul terminator at the end of
 *   the string.
 */
struct opendal_error *opendal_operator_delete(const struct opendal_operator *op, const char *path);

/**
 * \brief Blocking put tagging to object in `path`
 *
 * Put tagging to object in `path` blocking by `op_ptr`
 * Error is NULL if successful, otherwise it contains the error code and error message.
 *
 * @param op The opendal_operator created previously
 * @param path The designated path you want to put tagging to
 * @param tagging The tagging you want to put
 */
struct opendal_error *opendal_operator_put_object_tagging(const struct opendal_operator *op,
                                                          const char *path,
                                                          const struct opendal_object_tagging *tagging);

/**
 * \brief Blocking get tagging of object in `path`
 *
 * Get tagging of object in `path` blocking by `op_ptr`
 * If successful, it returns a valid tagging; otherwise, it returns an error.
 *
 * @param op The opendal_operator created previously
 * @param path The path of the object that you want to retrieve tagging
 */
struct opendal_result_get_object_tagging opendal_operator_get_object_tagging(const struct opendal_operator *op,
                                                                             const char *path);

/**
 * \brief Check whether the path exists.
 *
 * If the operation succeeds, no matter the path exists or not,
 * the error should be a nullptr. Otherwise, the field `is_exist`
 * is filled with false, and the error is set
 *
 * @param op The opendal_operator created previously
 * @param path The path you want to check existence
 * @see opendal_operator
 * @see opendal_result_is_exist
 * @see opendal_error
 * @return Returns opendal_result_is_exist, the `is_exist` field contains whether the path exists.
 * However, it the operation fails, the `is_exist` will contain false and the error will be set.
 *
 * # Example
 *
 * ```C
 * // .. you previously wrote some data to path "/mytest/obj"
 * opendal_result_is_exist e = opendal_operator_is_exist(op, "/mytest/obj");
 * assert(e.error == NULL);
 * assert(e.is_exist);
 *
 * // but you previously did **not** write any data to path "/yourtest/obj"
 * opendal_result_is_exist e = opendal_operator_is_exist(op, "/yourtest/obj");
 * assert(e.error == NULL);
 * assert(!e.is_exist);
 * ```
 *
 * # Safety
 *
 * It is **safe** under the cases below
 * * The memory pointed to by `path` must contain a valid nul terminator at the end of
 *   the string.
 */
__attribute__((deprecated("Use opendal_operator_exists() instead.")))
struct opendal_result_is_exist opendal_operator_is_exist(const struct opendal_operator *op,
                                                         const char *path);

/**
 * \brief Check whether the path exists.
 *
 * If the operation succeeds, no matter the path exists or not,
 * the error should be a nullptr. Otherwise, the field `exists`
 * is filled with false, and the error is set
 *
 * @param op The opendal_operator created previously
 * @param path The path you want to check existence
 * @see opendal_operator
 * @see opendal_result_exists
 * @see opendal_error
 * @return Returns opendal_result_exists, the `exists` field contains whether the path exists.
 * However, it the operation fails, the `exists` will contain false and the error will be set.
 *
 * # Example
 *
 * ```C
 * // .. you previously wrote some data to path "/mytest/obj"
 * opendal_result_exists e = opendal_operator_exists(op, "/mytest/obj");
 * assert(e.error == NULL);
 * assert(e.exists);
 *
 * // but you previously did **not** write any data to path "/yourtest/obj"
 * opendal_result_exists e = opendal_operator_exists(op, "/yourtest/obj");
 * assert(e.error == NULL);
 * assert(!e.exists);
 * ```
 *
 * # Safety
 *
 * It is **safe** under the cases below
 * * The memory pointed to by `path` must contain a valid nul terminator at the end of
 *   the string.
 */
struct opendal_result_exists opendal_operator_exists(const struct opendal_operator *op,
                                                     const char *path);

/**
 * \brief Stat the path, return its metadata.
 *
 * Error is NULL if successful, otherwise it contains the error code and error message.
 *
 * @param op The opendal_operator created previously
 * @param path The path you want to stat
 * @see opendal_operator
 * @see opendal_result_stat
 * @see opendal_metadata
 * @return Returns opendal_result_stat, containing a metadata and an opendal_error.
 * If the operation succeeds, the `meta` field would hold a valid metadata and
 * the `error` field should hold nullptr. Otherwise, the metadata will contain a
 * NULL pointer, i.e. invalid, and the `error` will be set correspondingly.
 *
 * # Example
 *
 * ```C
 * // ... previously you wrote "Hello, World!" to path "/testpath"
 * opendal_result_stat s = opendal_operator_stat(op, "/testpath");
 * assert(s.error == NULL);
 *
 * const opendal_metadata *meta = s.meta;
 *
 * // ... you could now use your metadata, notice that please only access metadata
 * // using the APIs provided by OpenDAL
 * ```
 *
 * # Safety
 *
 * It is **safe** under the cases below
 * * The memory pointed to by `path` must contain a valid nul terminator at the end of
 *   the string.
 */
struct opendal_result_stat opendal_operator_stat(const struct opendal_operator *op,
                                                 const char *path);

/**
 * \brief Blocking list the objects in `path`.
 *
 * List the object in `path` blocking by `op_ptr`, return a result with an
 * opendal_lister. Users should call opendal_lister_next() on the
 * lister.
 *
 * @param op The opendal_operator created previously
 * @param path The designated path you want to list
 * @see opendal_lister
 * @return Returns opendal_result_list, containing a lister and an opendal_error.
 * If the operation succeeds, the `lister` field would hold a valid lister and
 * the `error` field should hold nullptr. Otherwise, the `lister`` will contain a
 * NULL pointer, i.e. invalid, and the `error` will be set correspondingly.
 *
 * # Example
 *
 * Following is an example
 * ```C
 * // You have written some data into some files path "root/dir1"
 * // Your opendal_operator was called op
 * opendal_result_list l = opendal_operator_list(op, "root/dir1");
 * assert(l.error == ERROR);
 *
 * opendal_lister *lister = l.lister;
 * opendal_list_entry *entry;
 *
 * while ((entry = opendal_lister_next(lister)) != NULL) {
 *     const char* de_path = opendal_list_entry_path(entry);
 *     const char* de_name = opendal_list_entry_name(entry);
 *     // ...... your operations
 *
 *     // remember to free the entry after you are done using it
 *     opendal_list_entry_free(entry);
 * }
 *
 * // and remember to free the lister
 * opendal_lister_free(lister);
 * ```
 *
 * # Safety
 *
 * It is **safe** under the cases below
 * * The memory pointed to by `path` must contain a valid nul terminator at the end of
 *   the string.
 */
struct opendal_result_list opendal_operator_list(const struct opendal_operator *op,
                                                 const char *path,
                                                 uintptr_t limit,
                                                 bool recursive,
                                                 const char *start_after);

/**
 * \brief Create a deleter by opendal_operator
 *
 * You can use the deleter to delete objects in batch.
 */
struct opendal_result_operator_deleter opendal_operator_deleter(const struct opendal_operator *op);

/**
 * \brief Blocking create the directory in `path`.
 *
 * Create the directory in `path` blocking by `op_ptr`.
 * Error is NULL if successful, otherwise it contains the error code and error message.
 *
 * @param op The opendal_operator created previously
 * @param path The designated directory you want to create
 * @see opendal_operator
 * @see opendal_error
 * @return NULL if succeeds, otherwise it contains the error code and error message.
 *
 * # Example
 *
 * Following is an example
 * ```C
 * //...prepare your opendal_operator, named op for example
 *
 * // create your directory
 * opendal_error *error = opendal_operator_create_dir(op, "/testdir/");
 *
 * // Assert that this succeeds
 * assert(error == NULL);
 * ```
 *
 * # Safety
 *
 * It is **safe** under the cases below
 * * The memory pointed to by `path` must contain a valid nul terminator at the end of
 *   the string.
 */
struct opendal_error *opendal_operator_create_dir(const struct opendal_operator *op,
                                                  const char *path);

/**
 * \brief Blocking rename the object in `path`.
 *
 * Rename the object in `src` to `dest` blocking by `op`.
 * Error is NULL if successful, otherwise it contains the error code and error message.
 *
 * @param op The opendal_operator created previously
 * @param src The designated source path you want to rename
 * @param dest The designated destination path you want to rename
 * @see opendal_operator
 * @see opendal_error
 * @return NULL if succeeds, otherwise it contains the error code and error message.
 *
 * # Example
 *
 * Following is an example
 * ```C
 * //...prepare your opendal_operator, named op for example
 *
 * // prepare your data
 * char* data = "Hello, World!";
 * opendal_bytes bytes = opendal_bytes { .data = (uint8_t*)data, .len = 13 };
 * opendal_error *error = opendal_operator_write(op, "/testpath", bytes);
 *
 * assert(error == NULL);
 *
 * // now you can rename!
 * opendal_error *error = opendal_operator_rename(op, "/testpath", "/testpath2");
 *
 * // Assert that this succeeds
 * assert(error == NULL);
 * ```
 *
 * # Safety
 *
 * It is **safe** under the cases below
 * * The memory pointed to by `path` must contain a valid nul terminator at the end of
 *   the string.
 */
struct opendal_error *opendal_operator_rename(const struct opendal_operator *op,
                                              const char *src,
                                              const char *dest);

/**
 * \brief Blocking copy the object in `path`.
 *
 * Copy the object in `src` to `dest` blocking by `op`.
 * Error is NULL if successful, otherwise it contains the error code and error message.
 *
 * @param op The opendal_operator created previously
 * @param src The designated source path you want to copy
 * @param dest The designated destination path you want to copy
 * @see opendal_operator
 * @see opendal_error
 * @return NULL if succeeds, otherwise it contains the error code and error message.
 *
 * # Example
 *
 * Following is an example
 * ```C
 * //...prepare your opendal_operator, named op for example
 *
 * // prepare your data
 * char* data = "Hello, World!";
 * opendal_bytes bytes = opendal_bytes { .data = (uint8_t*)data, .len = 13 };
 * opendal_error *error = opendal_operator_write(op, "/testpath", bytes);
 *
 * assert(error == NULL);
 *
 * // now you can rename!
 * opendal_error *error = opendal_operator_copy(op, "/testpath", "/testpath2");
 *
 * // Assert that this succeeds
 * assert(error == NULL);
 * ```
 *
 * # Safety
 *
 * It is **safe** under the cases below
 * * The memory pointed to by `path` must contain a valid nul terminator at the end of
 *   the string.
 */
struct opendal_error *opendal_operator_copy(const struct opendal_operator *op,
                                            const char *src,
                                            const char *dest);

/**
 * free the c char
 */
void opendal_c_char_free(char *ptr);

/**
 * \brief panic test function.
 */
struct opendal_error *opendal_panic_test(void);

/**
 * 释放异步操作 operator 的内存
 */
void opendal_async_operator_free(const struct opendal_async_operator *ptr);

struct opendal_error *opendal_async_operator_new(const char *scheme,
                                                 const struct opendal_operator_config *config,
                                                 struct opendal_async_operator **async_operator);

void opendal_async_operator_write(const struct opendal_async_operator *op,
                                  const char *path,
                                  const struct opendal_bytes *bytes,
                                  OpenDalAsyncCallbackFn callback,
                                  void *ctx);

void opendal_async_operator_read(const struct opendal_async_operator *op,
                                 const char *path,
                                 uint8_t *buf,
                                 uintptr_t len,
                                 uintptr_t offset,
                                 OpenDalAsyncCallbackFn callback,
                                 void *ctx);

/**
 * write with if match, only the object is not exist, or the content
 * is match, the write will succeed. Because not all the services support if_match,
 * we use write with if not exists and read to implement it.
 */
void opendal_async_operator_write_with_if_match(const struct opendal_async_operator *op,
                                                const char *path,
                                                const struct opendal_bytes *bytes,
                                                OpenDalAsyncCallbackFn callback,
                                                void *ctx);

void opendal_async_operator_write_with_worm_check(const struct opendal_async_operator *op,
                                                  const char *path,
                                                  const struct opendal_bytes *bytes,
                                                  OpenDalAsyncCallbackFn callback,
                                                  void *ctx);

struct opendal_error *opendal_async_operator_multipart_writer(const struct opendal_async_operator *op,
                                                              const char *path,
                                                              struct opendal_async_multipart_writer **opendal_async_multipart_writer);

/**
 * doc placeholder
 */
void opendal_async_multipart_writer_free(struct opendal_async_multipart_writer *ptr);

/**
 * doc placeholder
 */
struct opendal_error *opendal_async_multipart_writer_initiate(struct opendal_async_multipart_writer *self);

/**
 * Noticed that this function will be called in multiple threads from oceanbase.
 * so we maintain mutex in type::ob_multipart_writer::ObMultipartWriter.
 * then we can clone the self.inner to avoid rust borrow checker.
 */
void opendal_async_multipart_writer_write(struct opendal_async_multipart_writer *self,
                                          const struct opendal_bytes *bytes,
                                          uintptr_t part_id,
                                          OpenDalAsyncCallbackFn callback,
                                          void *ctx);

/**
 * doc placeholder
 */
struct opendal_error *opendal_async_multipart_writer_abort(struct opendal_async_multipart_writer *self);

/**
 * doc placeholder
 */
struct opendal_error *opendal_async_multipart_writer_close(struct opendal_async_multipart_writer *self);

/**
 * \brief Get information of underlying accessor.
 *
 * # Example
 *
 * ```C
 * /// suppose you have a memory-backed opendal_operator* named op
 * char *scheme;
 * opendal_operator_info *info = opendal_operator_info_new(op);
 *
 * scheme = opendal_operator_info_get_scheme(info);
 * assert(!strcmp(scheme, "memory"));
 *
 * /// free the heap memory
 * free(scheme);
 * opendal_operator_info_free(info);
 * ```
 */
struct opendal_operator_info *opendal_operator_info_new(const struct opendal_operator *op);

/**
 * \brief Free the heap-allocated opendal_operator_info
 */
void opendal_operator_info_free(struct opendal_operator_info *ptr);

/**
 * \brief Return the nul-terminated operator's scheme, i.e. service
 *
 * \note: The string is on heap, remember to free it
 */
char *opendal_operator_info_get_scheme(const struct opendal_operator_info *self);

/**
 * \brief Return the nul-terminated operator's working root path
 *
 * \note: The string is on heap, remember to free it
 */
char *opendal_operator_info_get_root(const struct opendal_operator_info *self);

/**
 * \brief Return the nul-terminated operator backend's name, could be empty if underlying backend has no
 * namespace concept.
 *
 * \note: The string is on heap, remember to free it
 */
char *opendal_operator_info_get_name(const struct opendal_operator_info *self);

/**
 * \brief Return the operator's full capability
 */
struct opendal_capability opendal_operator_info_get_full_capability(const struct opendal_operator_info *self);

/**
 * \brief Return the operator's native capability
 */
struct opendal_capability opendal_operator_info_get_native_capability(const struct opendal_operator_info *self);

/**
 * \brief Frees the heap memory used by the opendal_bytes
 */
void opendal_bytes_free(struct opendal_bytes *ptr);

/**
 * \brief Constructs a new opendal_operator_options
 */
struct opendal_object_tagging *opendal_object_tagging_new(void);

/**
 * \brief Set the value of the key in the opendal_object_tagging
 * @param key The key to be set
 * @param value The value to be set
 */
void opendal_object_tagging_set(struct opendal_object_tagging *self,
                                const char *key,
                                const char *value);

/**
 * \brief Get the value of the key in the opendal_object_tagging
 * @param key The key to be get
 */
struct opendal_result_object_tagging_get opendal_object_tagging_get(const struct opendal_object_tagging *self,
                                                                    const char *key);

/**
 * \brief Frees the heap memory used by the opendal_object_tagging
 */
void opendal_object_tagging_free(struct opendal_object_tagging *ptr);

/**
 * \brief Construct a heap-allocated opendal_operator_options
 *
 * @return An empty opendal_operator_option, which could be set by
 * opendal_operator_option_set().
 *
 * @see opendal_operator_option_set
 */
struct opendal_operator_options *opendal_operator_options_new(void);

/**
 * \brief Set a Key-Value pair inside opendal_operator_options
 *
 * # Safety
 *
 * This function is unsafe because it dereferences and casts the raw pointers
 * Make sure the pointer of `key` and `value` point to a valid string.
 *
 * # Example
 *
 * ```C
 * opendal_operator_options *options = opendal_operator_options_new();
 * opendal_operator_options_set(options, "root", "/myroot");
 *
 * // .. use your opendal_operator_options
 *
 * opendal_operator_options_free(options);
 * ```
 */
struct opendal_error *opendal_operator_options_set(struct opendal_operator_options *self,
                                                   const char *key,
                                                   const char *value);

/**
 * \brief Free the allocated memory used by [`opendal_operator_options`]
 */
void opendal_operator_options_free(struct opendal_operator_options *ptr);

struct ObSpan *ob_new_span(uint64_t tenant_id, const char *trace_id);

void ob_drop_span(struct ObSpan *span);

/**
 * \brief Construct a new opendal_operator_config on heap
 *
 * The returned config is initialized with default values.
 * You need to set the required fields before using it.
 *
 * @return A pointer to newly allocated opendal_operator_config
 * @see opendal_operator_config_free
 */
struct opendal_operator_config *opendal_operator_config_new(void);

/**
 * \brief Free the heap memory used by opendal_operator_config
 *
 * # Safety
 *
 * The pointer must be a valid pointer returned by opendal_operator_config_new
 *
 * @param ptr The pointer to opendal_operator_config to be freed
 */
void opendal_operator_config_free(struct opendal_operator_config *ptr);

/**
 * \brief Path of entry.
 *
 * Path is relative to operator's root. Only valid in current operator.
 *
 * \note To free the string, you can directly call free()
 */
char *opendal_entry_path(const struct opendal_entry *self);

/**
 * \brief Name of entry.
 *
 * Name is the last segment of path.
 * If this entry is a dir, `Name` MUST endswith `/`
 * Otherwise, `Name` MUST NOT endswith `/`.
 *
 * \note To free the string, you can directly call free()
 */
char *opendal_entry_name(const struct opendal_entry *self);

/**
 * \brief Metadata of entry.
 *
 * \note To free the metadata, you can directly call opendal_metadata_free()
 */
struct opendal_metadata *opendal_entry_metadata(const struct opendal_entry *self);

/**
 * \brief Frees the heap memory used by the opendal_list_entry
 */
void opendal_entry_free(struct opendal_entry *ptr);

/**
 * \brief Read data from the reader.
 */
struct opendal_result_reader_read opendal_reader_read(struct opendal_reader *self,
                                                      uint8_t *buf,
                                                      uintptr_t len,
                                                      uintptr_t offset);

/**
 * \brief Frees the heap memory used by the opendal_reader.
 */
void opendal_reader_free(struct opendal_reader *ptr);

/**
 * \brief Write data to the writer.
 */
struct opendal_result_writer_write opendal_writer_write(struct opendal_writer *self,
                                                        const struct opendal_bytes *bytes);

/**
 * \brief Write data to the writer with the offset.
 */
struct opendal_result_writer_write opendal_writer_write_with_offset(struct opendal_writer *self,
                                                                    uint64_t offset,
                                                                    const struct opendal_bytes *bytes);

/**
 * \brief Abort the pending writer.
 */
struct opendal_error *opendal_writer_abort(struct opendal_writer *self);

/**
 * \brief close the writer.
 */
struct opendal_error *opendal_writer_close(struct opendal_writer *self);

/**
 * \brief Frees the heap memory used by the opendal_writer.
 * \note This function make sure all data have been stored.
 */
void opendal_writer_free(struct opendal_writer *ptr);

/**
 * \brief Initiate the multipart writer.
 */
struct opendal_error *opendal_multipart_writer_initiate(struct opendal_multipart_writer *self);

/**
 * \brief Write data with part id to the multipart writer.
 */
struct opendal_result_writer_write opendal_multipart_writer_write(struct opendal_multipart_writer *self,
                                                                  const struct opendal_bytes *bytes,
                                                                  uintptr_t part_id);

/**
 * \brief Abort the pending multipart writer.
 */
struct opendal_error *opendal_multipart_writer_abort(struct opendal_multipart_writer *self);

/**
 * \brief close the multipart writer.
 */
struct opendal_error *opendal_multipart_writer_close(struct opendal_multipart_writer *self);

/**
 * \brief Frees the heap memory used by the opendal_multipart_writer.
 * \note This function make sure all data have been stored.
 */
void opendal_multipart_writer_free(struct opendal_multipart_writer *ptr);

#ifdef __cplusplus
} // extern "C"
#endif // __cplusplus

#endif /* _OPENDAL_H */
