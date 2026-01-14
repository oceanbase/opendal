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

#ifndef OBDAL_NETWORK_DISRUPT_HPP_
#define OBDAL_NETWORK_DISRUPT_HPP_

#include <cassert>
#include <cerrno>
#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <sys/stat.h>
#include <unistd.h>

// NOTE: This header provides per-process network disruption for tests.
// It MUST NOT apply any global traffic shaping that could impact the whole machine.

static inline int run_cmd(const std::string &cmd)
{
  const int rc = std::system(cmd.c_str());
  if (rc != 0) {
    std::cerr << "[cmd failed] rc=" << rc << " cmd: " << cmd << std::endl;
  }
  return rc;
}

static inline bool file_exists(const std::string &path)
{
  return ::access(path.c_str(), F_OK) == 0;
}

static inline bool write_text_file(const std::string &path, const std::string &content)
{
  std::ofstream out(path);
  if (!out.is_open()) {
    std::cerr << "[write failed] open " << path << " errno=" << errno << std::endl;
    return false;
  }
  out << content;
  out.close();
  return out.good();
}

static inline bool ensure_dir(const std::string &path)
{
  if (::mkdir(path.c_str(), 0755) == 0) {
    return true;
  }
  if (errno == EEXIST) {
    return true;
  }
  std::cerr << "[mkdir failed] " << path << " errno=" << errno << std::endl;
  return false;
}

static inline std::string get_env_or_default(const char *key, const std::string &def)
{
  const char *v = std::getenv(key);
  return v == nullptr ? def : std::string(v);
}

static inline bool env_truthy(const char *key)
{
  const char *v = std::getenv(key);
  if (v == nullptr) {
    return false;
  }
  const std::string s(v);
  return s == "1" || s == "true" || s == "TRUE" || s == "yes" || s == "YES";
}

static inline bool is_cgroup_v2()
{
  // Unified hierarchy has this file at /sys/fs/cgroup/
  return file_exists("/sys/fs/cgroup/cgroup.controllers");
}

static inline std::string find_cgroup_v1_mountpoint_with_controller(const std::string &controller)
{
  std::ifstream in("/proc/mounts");
  if (!in.is_open()) {
    return "";
  }
  std::string line;
  while (std::getline(in, line)) {
    std::istringstream iss(line);
    std::string dev, mnt, fstype, opts;
    if (!(iss >> dev >> mnt >> fstype >> opts)) {
      continue;
    }
    if (fstype != "cgroup") {
      continue;
    }
    // opts is a comma-separated list of controllers and mount options.
    // We do a substring check which is good enough for test infra.
    if (opts.find(controller) != std::string::npos) {
      return mnt;
    }
  }
  return "";
}

static inline std::string shell_escape_single_quotes(const std::string &s)
{
  // For embedding inside single-quoted shell string.
  // ' -> '"'"'
  std::string out;
  out.reserve(s.size());
  for (char c : s) {
    if (c == '\'') {
      out += "'\"'\"'";
    } else {
      out += c;
    }
  }
  return out;
}

static inline bool has_cap_net_admin()
{
  // CAP_NET_ADMIN is bit 12.
  // Read /proc/self/status CapEff (hex) to avoid executing privileged commands just to probe.
  std::ifstream in("/proc/self/status");
  if (!in.is_open()) {
    return false;
  }
  std::string line;
  while (std::getline(in, line)) {
    if (line.rfind("CapEff:", 0) == 0) {
      std::string hex = line.substr(std::string("CapEff:").size());
      // trim leading spaces/tabs
      while (!hex.empty() && (hex[0] == ' ' || hex[0] == '\t')) {
        hex.erase(hex.begin());
      }
      uint64_t capeff = 0;
      std::stringstream ss;
      ss << std::hex << hex;
      ss >> capeff;
      return (capeff & (1ULL << 12)) != 0;
    }
  }
  return false;
}

static inline bool should_use_sudo_for_net_admin()
{
  // If user asked for it and we're not already root, we will prefix privileged commands with sudo -n.
  // Requires passwordless sudo; otherwise commands will fail.
  return (::geteuid() != 0) && env_truthy("OBDAL_TEST_USE_SUDO");
}

static inline std::string with_privilege_prefix(const std::string &cmd)
{
  if (should_use_sudo_for_net_admin()) {
    return "sudo -n " + cmd;
  }
  return cmd;
}

static inline int run_cmd_priv(const std::string &cmd)
{
  return run_cmd(with_privilege_prefix(cmd));
}

static inline bool write_text_file_priv(const std::string &path, const std::string &content)
{
  if (!should_use_sudo_for_net_admin()) {
    return write_text_file(path, content);
  }
  // Avoid fragile nested-quote shell by using sudo tee.
  // Content used in tests is numeric/hex, but we still quote safely.
  const std::string q_content = "'" + shell_escape_single_quotes(content) + "'";
  const std::string q_path = "'" + shell_escape_single_quotes(path) + "'";
  const std::string cmd = "printf %s " + q_content + " | sudo -n tee " + q_path + " >/dev/null";
  return run_cmd(cmd) == 0;
}

static inline bool ensure_dir_priv(const std::string &path)
{
  if (!should_use_sudo_for_net_admin()) {
    return ensure_dir(path);
  }
  const std::string q_path = shell_escape_single_quotes(path);
  return run_cmd_priv("mkdir -p '" + q_path + "'") == 0;
}

class DisruptNetwork
{
public:
  DisruptNetwork()
  {
    pid_ = getpid();
    is_disrupted_ = false;
    method_ = METHOD_NONE;
    open_disrupt_network();
  }
  ~DisruptNetwork() { close_disrupt_network(); }

  bool disrupted() { return is_disrupted_; }

private:
  enum Method
  {
    METHOD_NONE = 0,
    METHOD_IPTABLES_CGROUP_V1,
    METHOD_IPTABLES_CGROUP_V2,
  };

  static inline std::string make_unique_netcls_classid_hex(int pid)
  {
    // classid is 32-bit: (major << 16) | minor
    // Use major=0x0001, minor derived from pid (avoid 0).
    const uint32_t major = 0x0001;
    uint32_t minor = static_cast<uint32_t>(pid) & 0xFFFF;
    if (minor == 0) {
      minor = 1;
    }
    const uint32_t classid = (major << 16) | minor;
    std::stringstream ss;
    ss << "0x" << std::hex << std::setw(8) << std::setfill('0') << classid;
    return ss.str();
  }

  void open_disrupt_network()
  {
    if (is_disrupted_) {
      return;
    }

    // Allow overriding NIC for CI/container differences (kept for compatibility, not used by iptables path).
    dev_ = get_env_or_default("OBDAL_TEST_NET_DEV", "eth0");

    // Require the ability to perform NET_ADMIN operations:
    // - either we already have CAP_NET_ADMIN
    // - or user explicitly allows sudo escalation for tests (OBDAL_TEST_USE_SUDO=1)
    if (!has_cap_net_admin() && !should_use_sudo_for_net_admin()) {
      std::cerr << "[DisruptNetwork] missing CAP_NET_ADMIN. "
                << "Run tests as root, or set OBDAL_TEST_USE_SUDO=1 with passwordless sudo."
                << std::endl;
      return;
    }

    // IMPORTANT: Only disrupt THIS PROCESS network.
    // We refuse to apply any global traffic shaping/netem rules.
    if (is_cgroup_v2()) {
      if (try_open_cgroup_v2_iptables_drop()) {
        is_disrupted_ = true;
        method_ = METHOD_IPTABLES_CGROUP_V2;
        usleep(50 * 1000);
        return;
      }
    } else {
      if (try_open_cgroup_v1_iptables_drop()) {
        is_disrupted_ = true;
        method_ = METHOD_IPTABLES_CGROUP_V1;
        usleep(50 * 1000);
        return;
      }
    }

    std::cerr << "[DisruptNetwork] failed to disrupt per-process network. "
              << "Refusing to apply global traffic shaping. "
              << "Check cgroup/iptables setup." << std::endl;
  }

  void close_disrupt_network()
  {
    if (!is_disrupted_) {
      return;
    }

    switch (method_) {
    case METHOD_IPTABLES_CGROUP_V2:
      close_cgroup_v2_iptables_drop();
      break;
    case METHOD_IPTABLES_CGROUP_V1:
      close_cgroup_v1_iptables_drop();
      break;
    default:
      break;
    }

    is_disrupted_ = false;
    method_ = METHOD_NONE;
  }

  bool try_open_cgroup_v2_iptables_drop()
  {
    // cgroup v2 unified hierarchy
    cgroup_relpath_ = "obdal_cgroup_" + std::to_string(pid_);
    cgroup_path_ = "/sys/fs/cgroup/" + cgroup_relpath_;
    if (!ensure_dir_priv(cgroup_path_)) {
      return false;
    }
    if (!write_text_file_priv(cgroup_path_ + "/cgroup.procs", std::to_string(pid_))) {
      run_cmd_priv("rmdir " + cgroup_path_ + " >/dev/null 2>&1 || true");
      return false;
    }

    // Match this cgroup2 path (relative to cgroup2 root).
    ipt_spec_out_ = "-m cgroup --path " + cgroup_relpath_ + " -j DROP";
    ipt_spec_in_ = "-m cgroup --path " + cgroup_relpath_ + " -j DROP";

    if (run_cmd_priv("iptables -t filter -I OUTPUT 1 " + ipt_spec_out_) != 0) {
      close_cgroup_v2_iptables_drop();
      return false;
    }
    if (run_cmd_priv("iptables -t filter -I INPUT 1 " + ipt_spec_in_) != 0) {
      close_cgroup_v2_iptables_drop();
      return false;
    }
    return true;
  }

  void close_cgroup_v2_iptables_drop()
  {
    if (!ipt_spec_out_.empty()) {
      run_cmd_priv("iptables -t filter -D OUTPUT " + ipt_spec_out_ + " >/dev/null 2>&1 || true");
    }
    if (!ipt_spec_in_.empty()) {
      run_cmd_priv("iptables -t filter -D INPUT " + ipt_spec_in_ + " >/dev/null 2>&1 || true");
    }

    // Move pid back to root cgroup and remove our cgroup dir.
    write_text_file_priv("/sys/fs/cgroup/cgroup.procs", std::to_string(pid_));
    if (!cgroup_path_.empty()) {
      run_cmd_priv("rmdir " + cgroup_path_ + " >/dev/null 2>&1 || true");
    }

    ipt_spec_out_.clear();
    ipt_spec_in_.clear();
    cgroup_path_.clear();
    cgroup_relpath_.clear();
  }

  bool try_open_cgroup_v1_iptables_drop()
  {
    // cgroup v1 net_cls hierarchy required
    cgroup_root_ = find_cgroup_v1_mountpoint_with_controller("net_cls");
    if (cgroup_root_.empty()) {
      return false;
    }

    cgroup_path_ = cgroup_root_ + "/obdal_cgroup_" + std::to_string(pid_);
    if (!ensure_dir_priv(cgroup_path_)) {
      return false;
    }

    classid_hex_ = make_unique_netcls_classid_hex(pid_);
    if (!write_text_file_priv(cgroup_path_ + "/net_cls.classid", classid_hex_)) {
      close_cgroup_v1_iptables_drop();
      return false;
    }
    // IMPORTANT: use cgroup.procs so all threads of this process are moved (tokio threads etc).
    if (!write_text_file_priv(cgroup_path_ + "/cgroup.procs", std::to_string(pid_))) {
      close_cgroup_v1_iptables_drop();
      return false;
    }

    ipt_spec_out_ = "-m cgroup --cgroup " + classid_hex_ + " -j DROP";
    ipt_spec_in_ = "-m cgroup --cgroup " + classid_hex_ + " -j DROP";
    if (run_cmd_priv("iptables -t filter -I OUTPUT 1 " + ipt_spec_out_) != 0) {
      close_cgroup_v1_iptables_drop();
      return false;
    }
    if (run_cmd_priv("iptables -t filter -I INPUT 1 " + ipt_spec_in_) != 0) {
      close_cgroup_v1_iptables_drop();
      return false;
    }

    return true;
  }

  void close_cgroup_v1_iptables_drop()
  {
    if (!ipt_spec_out_.empty()) {
      run_cmd_priv("iptables -t filter -D OUTPUT " + ipt_spec_out_ + " >/dev/null 2>&1 || true");
    }
    if (!ipt_spec_in_.empty()) {
      run_cmd_priv("iptables -t filter -D INPUT " + ipt_spec_in_ + " >/dev/null 2>&1 || true");
    }

    if (!cgroup_root_.empty()) {
      // Move pid back to root of net_cls mount.
      write_text_file_priv(cgroup_root_ + "/cgroup.procs", std::to_string(pid_));
    }
    if (!cgroup_path_.empty()) {
      run_cmd_priv("rmdir " + cgroup_path_ + " >/dev/null 2>&1 || true");
    }

    ipt_spec_out_.clear();
    ipt_spec_in_.clear();
    cgroup_path_.clear();
    cgroup_root_.clear();
    classid_hex_.clear();
  }

private:
  int pid_;
  bool is_disrupted_;
  Method method_;
  std::string dev_;
  std::string cgroup_path_;
  std::string cgroup_root_;
  std::string cgroup_relpath_;
  std::string classid_hex_;
  std::string ipt_spec_out_;
  std::string ipt_spec_in_;
};

#endif

