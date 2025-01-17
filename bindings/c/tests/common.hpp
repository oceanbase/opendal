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

#include "opendal.h"
#include <vector>
#include <random>
#include <iostream>
#include <chrono>
#include <sstream>
#include <iomanip>
#include <ctime>
#include <cstring>

static constexpr char scheme[] = "xxx";
static constexpr char region[] = "xxx";
static constexpr char endpoint[] = "xxx";
static constexpr char bucket[] = "xxx";
static constexpr char access_key_id[] = "xxx";
static constexpr char secret_access_key[] = "xxx";

extern "C" void ob_log_handler(const char *level, const char *message) 
{
  std::cout << "obdal log: " << "[" << level << "] " << message << std::endl;
}

void *my_alloc(size_t size, size_t align) 
{
    // printf("my_alloc %zu %zu\n", size, align);
    return malloc(size);
}

void my_free(void *ptr) 
{
    // printf("my_free\n");
    free(ptr);
}

int64_t get_current_time() 
{
  auto now = std::chrono::system_clock::now();
  auto epoch = now.time_since_epoch();
  auto milliseconds = std::chrono::duration_cast<std::chrono::milliseconds>(epoch).count();
  return milliseconds;
}

std::string get_formatted_time() 
{
  auto now = std::chrono::system_clock::now();

  std::time_t now_c = std::chrono::system_clock::to_time_t(now);
  std::tm tm = *std::localtime(&now_c);
  auto milliseconds = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()) % 1000;

  std::stringstream ss;
  ss << std::put_time(&tm, "%Y%m%d_%H%M_") << std::setw(3) << std::setfill('0') << milliseconds.count();

  return ss.str();
}

std::vector<unsigned char> generateRandomBytes(std::size_t size) 
{
  // Create a random device to generate random numbers
  std::random_device rd;

  // Create a random engine and seed it with the random device
  std::mt19937_64 gen(rd());

  // Create a distribution to produce random bytes
  std::uniform_int_distribution<unsigned char> dist(0, 255);

  // Create a vector to hold the random bytes
  std::vector<unsigned char> randomBytes(size);

  // Generate random bytes and store them in the vector
  for (std::size_t i = 0; i < size; ++i) {
    randomBytes[i] = dist(gen);
  }

  return randomBytes;
}

bool generate_random_bytes(char *buf, std::size_t size)
{
  if (buf == nullptr || size == 0) {
    return false;
  }
  std::random_device rd;
  std::mt19937_64 gen(rd());
  static const char alphanum[] =
        "0123456789"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz";
  std::uniform_int_distribution<unsigned int> dist(0, strlen(alphanum) - 1);
  for (std::size_t i = 0; i < size; i++) {
    buf[i] = alphanum[dist(gen)];
  }
  return true;
}

// dump and free the opendal error
void dump_and_free_error(opendal_error *&error) 
{
  if (error != nullptr) {
    std::cout << "[ERRCODE: " << error->code << " ]" 
              << " [MESSAGE: " << error->message.data << "]"
              << " [IS_TEMPORARY: " << error->is_temporary << "]"
              << std::endl;
    opendal_error_free(error);
    error = nullptr;
  }
}