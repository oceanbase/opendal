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
#include <algorithm>
#include <chrono>
#include <sstream>
#include <iomanip>
#include <ctime>
#include <cstring>
#include <unistd.h>
#include <cassert>
#include <string>
static constexpr char scheme[] = "xxx";
static constexpr char region[] = "xxx";
static constexpr char endpoint[] = "xxx";
static constexpr char bucket[] = "xxx";
static constexpr char access_key_id[] = "xxx";
static constexpr char secret_access_key[] = "xxx";

extern "C" void ob_log_handler(const char *level, const char *message) 
{
  // std::cout << "obdal log: " << "[" << level << "] " << message << std::endl;
}

void *my_alloc(size_t size, size_t align) 
{
    void *ptr = malloc(size);
    // printf("my_alloc %zu %zu %p\n", size, align, ptr);
    return ptr;
}

void my_free(void *ptr) 
{
    // printf("my_free %p\n", ptr);
    free(ptr);
}

// compare opendal_bytes with c_char *
// return 0 if equal, -1 if bytes < str, 1 if bytes > str
int strcmp(const opendal_bytes &bytes, const char *str)
{
  if (str == nullptr) {
    std::cerr << "str should not be null" << std::endl;
    return -1;
  }
  int i = 0;
  while (i < bytes.len && *(str + i) != '\0') {
    if (bytes.data[i] != *(str + i)) {
      return bytes.data[i] < *(str + i) ? -1 : 1;
    }
    i++;
  }
  if (i == bytes.len && *(str + i) == '\0') {
    return 0;
  }
  return i == bytes.len ? -1 : 1;
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

template<class T>
void shuffle_vec(std::vector<T> &vec)
{
  std::random_device rd;
  std::mt19937 gen(rd());

  std::shuffle(vec.begin(), vec.end(), gen);
}

// select sz numbers from the range [l, r]
bool select_random_numbers(
    const int64_t l, 
    const int64_t r, 
    const size_t sz, 
    std::vector<int64_t> &selected)
{
  if (l > r || sz > r - l + 1) {
    std::cerr << "Error: sz is large than the nunmber of available elements in the range." << std::endl;
    return false;
  }

  std::vector<int64_t> numbers;
  for (int64_t i = l; i <= r; i++) {
    numbers.push_back(i);
  }

  shuffle_vec(numbers);

  for (int64_t i = 0; i < sz; i++) {
    selected.push_back(numbers[i]);
  }
  return true;
}

// Evenly divide the interval [l, r]
// eages:
//      divide [0, 9] into 5 parts evenly
//      [0, 2), [2, 4), [4, 6), [6, 8), [8, 10)
bool divide_interval_evenly(
    const int64_t l, 
    const int64_t r, 
    const size_t sz, 
    std::vector<std::tuple<int64_t, int64_t, int64_t>> &ranges)
{
  if (sz == 0 || l > r || (r - l + 1) % sz != 0) {
    std::cerr << "Invalid argument!" << ' ' << l << ' ' << r << ' ' << sz << std::endl;
    return false;
  }
  
  int64_t width = (r - l + 1) / sz;
  int64_t start = l;
  int64_t range_id = 0;
  while (start < r) {
    ranges.push_back(std::make_tuple(start, start + width, range_id));
    start += width;
    range_id++;
  }
  return true;
}


// dump the opendal error
void dump_error(const opendal_error *error) 
{
  if (error != nullptr) {
    std::cout << "[ERRCODE: " << error->code << " ]" 
              << " [MESSAGE: " << std::string((char *) error->message.data, error->message.len) << "]"
              << " [IS_TEMPORARY: " << error->is_temporary << "]"
              << std::endl;
  }
}

void free_error(opendal_error *&error)
{
  if (error != nullptr) {
    opendal_error_free(error);
    error = nullptr;
  }
}

class DisruptNetwork
{
public:
  DisruptNetwork() 
  { 
    pid_ = getpid();
    is_disrupted_ = false;
    open_disrupt_network(); 
  }
  ~DisruptNetwork() { close_disrupt_network(); }

  bool disrupted() { return is_disrupted_; }
private:
  void open_disrupt_network()
  {
    /*
     *                  1:        root qdisc
     *                /   \
     *              1:1   1:2     child class  
     *               |    
     *              10:   
     */
    system("tc qdisc add dev eth0 root handle 1: htb default 30");
    system("tc class add dev eth0 parent 1: classid 1:1 htb rate 10000mbit");
    system("tc class add dev eth0 parent 1: classid 1:2 htb rate 10mbit");
    system("tc filter add dev eth0 parent 1: protocol all prio 1 handle 1: cgroup");
    system("tc qdisc add dev eth0 parent 1:1 handle 10: netem loss 100%");
    system("cgcreate -g net_cls:/obdal_cgroup");
    system("echo 0x00010001 | tee /sys/fs/cgroup/net_cls/obdal_cgroup/net_cls.classid > /dev/null");
    
    std::string cmd = std::string("cgclassify -g net_cls:obdal_cgroup ") + std::to_string(pid_);

    assert(system(cmd.c_str()) == 0);
    is_disrupted_ = true;
  }

  void close_disrupt_network() 
  {
    system("echo | tee /sys/fs/cgroup/net_cls/ob_admin_osdq_cgroup/net_cls.classid");
    system("tc qdisc del dev eth0 root");
    is_disrupted_ = false;
  }
  
private:
  int pid_;
  bool is_disrupted_;
};