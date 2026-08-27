// SPDX-License-Identifier: MIT
// cpp-netlink-watch — Netlink socket monitor (/proc/net/netlink)
// Build: g++ -std=c++23 -O2 -Wall -Wextra src/main.cpp -o netlink-watch
// Usage: ./netlink-watch [--proto N] [--groups] [--drops] [--pid PID] [--top N]
//                        [--watch N] [--json] [--demo] [--file PATH]
//                        [--no-color] [--selftest]

#include <algorithm>
#include <bit>
#include <cctype>
#include <charconv>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <map>
#include <optional>
#include <set>
#include <sstream>
#include <string>
#include <string_view>
#include <thread>
#include <unistd.h>
#include <utility>
#include <vector>

// ─────────────────────────────────────────────────────────────────────────────
// Mutable ANSI palette (--no-color must actually clear it)
// ─────────────────────────────────────────────────────────────────────────────
static std::string C_RESET   = "\x1b[0m";
static std::string C_BOLD    = "\x1b[1m";
static std::string C_DIM     = "\x1b[2m";
static std::string C_RED     = "\x1b[31m";
static std::string C_GREEN   = "\x1b[32m";
static std::string C_YELLOW  = "\x1b[33m";
static std::string C_BLUE    = "\x1b[34m";
static std::string C_CYAN    = "\x1b[36m";
static std::string C_MAGENTA = "\x1b[35m";

static void disable_color() {
  C_RESET = C_BOLD = C_DIM = C_RED = C_GREEN = C_YELLOW = C_BLUE = C_CYAN = C_MAGENTA = "";
}

// ─────────────────────────────────────────────────────────────────────────────
// Netlink socket model (one row in /proc/net/netlink)
// ─────────────────────────────────────────────────────────────────────────────
struct NetlinkSock {
  std::string sk;        // kernel socket address (16 hex chars)
  int proto = -1;        // protocol family id (Eth column)
  long long pid = -1;    // netlink port id / owning pid (0 = kernel/unbound; can exceed 2^31-1)
  unsigned groups = 0;   // multicast group bitmask (hex)
  long rmem = 0;         // receive queue memory (bytes)
  long wmem = 0;         // send queue memory (bytes)
  int dump = 0;          // dump flag (in-progress dump request)
  int locks = 0;         // lock counter
  long drops = 0;        // dropped messages (ENOBUFS, requires NETLINK_RECV_NO_ENOBUFS)
  long inode = 0;        // socket inode

  int group_count() const { return std::popcount(groups); }
  bool has_groups() const { return groups != 0; }
  bool is_kernel() const { return pid == 0; }
};

struct Snapshot {
  long long ts = 0;
  std::vector<NetlinkSock> socks;
  std::map<long long, std::string> procs;

  std::size_t count_proto(int p) const {
    return static_cast<std::size_t>(
      std::count_if(socks.begin(), socks.end(), [&](const NetlinkSock& s) { return s.proto == p; }));
  }
  std::size_t count_groups() const {
    return static_cast<std::size_t>(
      std::count_if(socks.begin(), socks.end(), [](const NetlinkSock& s) { return s.has_groups(); }));
  }
  std::size_t count_kernel() const {
    return static_cast<std::size_t>(
      std::count_if(socks.begin(), socks.end(), [](const NetlinkSock& s) { return s.is_kernel(); }));
  }
  long total_drops() const {
    long d = 0;
    for (const auto& s : socks) d += s.drops;
    return d;
  }
  std::set<int> protos() const {
    std::set<int> p;
    for (const auto& s : socks) p.insert(s.proto);
    return p;
  }
};

// ─────────────────────────────────────────────────────────────────────────────
// Netlink protocol family names (linux/netlink.h NETLINK_*)
// ─────────────────────────────────────────────────────────────────────────────
static const char* family_name(int proto) {
  switch (proto) {
    case 0:  return "ROUTE";
    case 1:  return "UNUSED";
    case 2:  return "USERSOCK";
    case 3:  return "FIREWALL";
    case 4:  return "INET_DIAG";
    case 5:  return "NFLOG";
    case 6:  return "XFRM";
    case 7:  return "SELINUX";
    case 8:  return "ISCSI";
    case 9:  return "AUDIT";
    case 10: return "FIB_LOOKUP";
    case 11: return "CONNECTOR";
    case 12: return "NETFILTER";
    case 13: return "IP6_FW";
    case 14: return "DNRTMSG";
    case 15: return "KOBJECT_UEVENT";
    case 16: return "GENERIC";
    case 17: return "SCSI";
    case 18: return "ECRYPTFS";
    case 19: return "RDMA";
    case 20: return "CRYPTO";
    case 21: return "SMC";
    case 22: return "DEVLINK";
    case 23: return "DATAPATH";
    default: return "UNKNOWN";
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────
static long long now_secs() {
  return std::chrono::duration_cast<std::chrono::seconds>(
           std::chrono::system_clock::now().time_since_epoch()).count();
}

static std::optional<long long> parse_ll(std::string_view s, int base = 10) {
  auto start = s.find_first_not_of(" \t");
  if (start == std::string_view::npos) return std::nullopt;
  s.remove_prefix(start);
  long long v = 0;
  auto [ptr, ec] = std::from_chars(s.data(), s.data() + s.size(), v, base);
  if (ec != std::errc()) return std::nullopt;
  if (ptr != s.data() + s.size()) return std::nullopt;
  return v;
}

static std::string trim(std::string_view s) {
  while (!s.empty() && (s.front() == ' ' || s.front() == '\t')) s.remove_prefix(1);
  while (!s.empty() && (s.back() == ' ' || s.back() == '\t' || s.back() == '\r')) s.remove_suffix(1);
  return std::string(s);
}

static std::vector<std::string> split_ws(std::string_view s) {
  std::vector<std::string> out;
  std::istringstream ss{std::string(s)};
  std::string tok;
  while (ss >> tok) out.push_back(tok);
  return out;
}

static std::string pad(std::string s, std::size_t w) {
  if (s.size() >= w) return s;
  return s + std::string(w - s.size(), ' ');
}
static std::string padl(std::string s, std::size_t w) {
  if (s.size() >= w) return s;
  return std::string(w - s.size(), ' ') + s;
}

// resolve pid -> comm for every socket (tolerant to dead processes and
// non-pid port ids that can exceed 2^31-1)
static void resolve_procs(Snapshot& snap) {
  for (const auto& s : snap.socks) {
    if (s.pid <= 0 || s.pid > 2147483647LL || snap.procs.contains(s.pid)) continue;
    std::ifstream f("/proc/" + std::to_string(s.pid) + "/comm");
    std::string c;
    if (f) std::getline(f, c);
    snap.procs[s.pid] = c;
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// /proc/net/netlink line format:
//   sk               Eth Pid        Groups   Rmem     Wmem     Dump  Locks    Drops    Inode
//   0000000000000000 0   239535     00000113 0        0        0     2        0        2322592
//  (first line is the header)
// ─────────────────────────────────────────────────────────────────────────────
static bool parse_netlink_file(const std::string& path, Snapshot& snap) {
  std::ifstream f(path);
  if (!f) return false;
  std::string line;
  std::size_t lineno = 0;
  while (std::getline(f, line)) {
    ++lineno;
    std::string t = trim(line);
    if (t.empty()) continue;
    if (t.starts_with('#') || t.starts_with("sk") || t.starts_with("Sl")) continue;  // header / comments
    auto toks = split_ws(line);
    if (toks.size() < 10) continue;  // malformed row -> skip
    NetlinkSock s;
    s.sk = toks[0];
    if (auto v = parse_ll(toks[1])) s.proto = static_cast<int>(*v);
    if (auto v = parse_ll(toks[2])) s.pid = *v;
    if (auto v = parse_ll(toks[3], 16)) s.groups = static_cast<unsigned>(*v);
    if (auto v = parse_ll(toks[4])) s.rmem = static_cast<long>(*v);
    if (auto v = parse_ll(toks[5])) s.wmem = static_cast<long>(*v);
    if (auto v = parse_ll(toks[6])) s.dump = static_cast<int>(*v);
    if (auto v = parse_ll(toks[7])) s.locks = static_cast<int>(*v);
    if (auto v = parse_ll(toks[8])) s.drops = static_cast<long>(*v);
    if (auto v = parse_ll(toks[9])) s.inode = static_cast<long>(*v);
    snap.socks.push_back(std::move(s));
  }
  return true;
}

// ─────────────────────────────────────────────────────────────────────────────
// Filters
// ─────────────────────────────────────────────────────────────────────────────
struct Filters {
  int proto = -1;        // -1 = all
  bool groups_only = false;
  bool drops_only = false;
  long long pid = -1;
  int top = 0;
  bool demo = false;
  bool json = false;
  std::string file;
  int watch = 0;
  bool color = true;
};

static bool passes(const NetlinkSock& s, const Filters& f) {
  if (f.proto >= 0 && s.proto != f.proto) return false;
  if (f.groups_only && !s.has_groups()) return false;
  if (f.drops_only && s.drops == 0) return false;
  if (f.pid >= 0 && s.pid != f.pid) return false;
  return true;
}

// ─────────────────────────────────────────────────────────────────────────────
// Render (terminal table)
// ─────────────────────────────────────────────────────────────────────────────
static std::string family_color(int proto) {
  // route/generic family hues for readability
  switch (proto) {
    case 0:  return C_CYAN;    // ROUTE
    case 9:  return C_YELLOW;  // AUDIT
    case 15: return C_MAGENTA; // KOBJECT_UEVENT
    case 16: return C_GREEN;   // GENERIC
    case 12: return C_RED;     // NETFILTER
    case 4:  return C_BLUE;    // INET_DIAG
    default: return C_DIM;
  }
}

static void render_snapshot(const Snapshot& snap, const Filters& f, bool watch_mode) {
  std::size_t shown = 0;
  std::size_t total_shown = 0;
  for (const auto& s : snap.socks) if (passes(s, f)) ++total_shown;

  std::cout << C_BOLD << "  Netlink sockets  /proc/net/netlink" << C_RESET << "   "
            << C_DIM << snap.socks.size() << " total · " << snap.procs.size() << " procs resolved" << C_RESET << "\n";
  std::cout << C_DIM << "  sk               family(proto)  pid    comm  grps rmem   wmem  dump lk drops  inode" << C_RESET << "\n";
  std::cout << C_DIM << "  " << std::string(84, '-') << C_RESET << "\n";

  for (const auto& s : snap.socks) {
    if (!passes(s, f)) continue;
    if (f.top > 0 && shown >= static_cast<std::size_t>(f.top)) break;
    ++shown;
    std::string fam = family_name(s.proto);
    std::string famc = family_color(s.proto);
    std::string pid_str = s.is_kernel() ? "0" : std::to_string(s.pid);
    std::string comm = s.is_kernel() ? "-kernel-" : (snap.procs.contains(s.pid) ? snap.procs.at(s.pid) : "?");
    std::string grp = s.has_groups() ? std::to_string(s.group_count()) : "0";
    std::string drops_str = s.drops > 0 ? (C_RED + std::to_string(s.drops) + C_RESET) : std::to_string(s.drops);
    std::string rmem_s = s.rmem > 0 ? std::to_string(s.rmem) : "0";
    std::string wmem_s = s.wmem > 0 ? std::to_string(s.wmem) : "0";
    std::string locks_s = s.locks > 0 ? std::to_string(s.locks) : "0";

    std::cout << "  " << s.sk << "  "
              << famc << pad(fam, 15) << C_RESET << "(" << padl(std::to_string(s.proto), 2) << ") "
              << pad(pid_str, 6) << " " << pad(comm, 9) << " "
              << padl(grp, 3) << " " << padl(rmem_s, 5) << " " << padl(wmem_s, 5) << " "
              << padl(std::to_string(s.dump), 3) << " " << padl(locks_s, 2) << " "
              << padl(drops_str, 6) << " " << padl(std::to_string(s.inode), 7) << "\n";
  }

  // aggregates
  auto protos = snap.protos();
  std::cout << "\n  " << C_DIM << "families: " << C_RESET;
  bool first = true;
  for (int p : protos) {
    if (!first) std::cout << C_DIM << ", " << C_RESET;
    first = false;
    std::size_t n = snap.count_proto(p);
    std::cout << family_color(p) << family_name(p) << C_RESET << "(" << n << ")";
  }
  std::cout << "\n";
  std::cout << C_DIM << "  multicast listeners: " << C_RESET << snap.count_groups()
            << "  ·  kernel/unbound: " << C_RESET << snap.count_kernel()
            << C_DIM << "  ·  total drops: " << C_RESET
            << (snap.total_drops() > 0 ? C_RED : C_GREEN) << snap.total_drops() << C_RESET
            << C_DIM << "  ·  shown: " << C_RESET << shown << "/" << total_shown << "\n";
  if (watch_mode) std::cout << C_DIM << "  ts=" << snap.ts << C_RESET << "\n";
  std::cout << "\n";
}

// ─────────────────────────────────────────────────────────────────────────────
// JSON output
// ─────────────────────────────────────────────────────────────────────────────
static void render_json(std::ostream& os, const Snapshot& snap, bool demo) {
  os << "{\n  \"summary\": {\n";
  os << "    \"ts\": " << snap.ts << ",\n";
  os << "    \"total\": " << snap.socks.size() << ",\n";
  os << "    \"with_groups\": " << snap.count_groups() << ",\n";
  os << "    \"kernel\": " << snap.count_kernel() << ",\n";
  os << "    \"drops\": " << snap.total_drops() << ",\n";
  os << "    \"demo\": " << (demo ? "true" : "false") << "\n";
  os << "  },\n  \"sockets\": [\n";
  bool first = true;
  for (const auto& s : snap.socks) {
    if (!first) os << ",\n";
    first = false;
    os << "    {\"sk\": \"" << s.sk << "\", \"proto\": " << s.proto
       << ", \"family\": \"" << family_name(s.proto) << "\", \"pid\": " << s.pid
       << ", \"comm\": \"" << (snap.procs.contains(s.pid) ? snap.procs.at(s.pid) : "") << "\""
       << ", \"groups\": " << s.group_count() << ", \"rmem\": " << s.rmem
       << ", \"wmem\": " << s.wmem << ", \"dump\": " << s.dump
       << ", \"locks\": " << s.locks << ", \"drops\": " << s.drops
       << ", \"inode\": " << s.inode << "}";
  }
  os << "\n  ]\n}\n";
}

// ─────────────────────────────────────────────────────────────────────────────
// Demo dataset (synthetic busy host: udev + audit + route manager + apps)
// ─────────────────────────────────────────────────────────────────────────────
static bool dump_to_file(const std::string& path, const std::string& content) {
  std::ofstream f(path);
  if (!f) return false;
  f << content;
  return true;
}

static bool demo_load_file(const std::string& path, Snapshot& snap) {
  std::string demo =
    "sk               Eth Pid        Groups   Rmem     Wmem     Dump  Locks    Drops    Inode\n"
    "0000000000000000 0   3133       00000000 0        0        0     2        0        9310177\n"
    "0000000000000000 0   0          00000000 0        0        0     2        0        9310178\n"
    "0000000000000000 4   3133       00000000 0        0        0     2        0        9310181\n"
    "0000000000000000 6   3133       00000000 0        0        0     2        0        9310184\n"
    "0000000000000000 9   5214       00000000 0        0        0     2        0        9310190\n"
    "0000000000000000 9   5214       00000000 0        0        0     2        0        9310193\n"
    "0000000000000000 10  3133       00000000 0        0        0     2        0        9310201\n"
    "0000000000000000 12  3133       00000000 0        0        0     2        0        9310205\n"
    "0000000000000000 15  2115       00000555 0        1024     0     2        0        9822214\n"
    "0000000000000000 15  2115       00001555 0        768      0     2        0        9822217\n"
    "0000000000000000 15  0          00000000 0        0        0     2        0        25019\n"
    "0000000000000000 16  3315       00000000 0        0        0     2        0        1205517\n"
    "0000000000000000 16  3315       00000000 0        0        0     2        0        1205518\n"
    "0000000000000000 16  3316       00000000 0        0        0     2        0        1205521\n"
    "0000000000000000 16  3316       00000000 0        0        0     2        0        1205524\n"
    "0000000000000000 16  1082       00000000 2048     2048     1     2        0        1133888\n"
    "0000000000000000 16  1082       00000000 0        0        0     2        0        1133891\n"
    "0000000000000000 16  7011       00000000 0        0        0     2        0        1488371\n"
    "0000000000000000 16  7011       00000000 0        0        0     2        0        1488372\n"
    "0000000000000000 16  2301669796 00000000 0        0        0     2        0        2323626\n"
    "0000000000000000 16  2301669796 00000000 0        0        0     2        0        2323629\n"
    "0000000000000000 16  6120       00000000 0        0        0     2        0        1612206\n"
    "0000000000000000 20  3133       00000000 0        0        0     2        0        9310210\n"
    "0000000000000000 22  3133       00000000 0        0        0     2        0        9310213\n"
    "0000000000000000 23  3133       00000000 0        128      0     2        4        9310216\n"
    "# dropped-messages socket (DATAPATH/mptcp, ENOBUFS storms):\n"
    "0000000000000000 23  3133       00000000 0        0        0     2        17       9310217\n"
    "0000000000000000 23  3133       00000000 0        0        0     2        0        9310218\n"
    "0000000000000000 21  3133       00000000 0        0        0     2        0        9310219\n"
    "0000000000000000 2   4422       00000100 0        0        0     2        0        1999111\n"
    "0000000000000000 3   4422       00000000 0        0        0     2        0        1999114\n"
    "0000000000000000 5   4422       00000000 0        0        0     2        0        1999117\n"
    "0000000000000000 19  4422       00000000 4096     0        0     2        0        1999120\n"
    "# comment + trailing annotation tolerated\n"
    "0000000000000000 19  4422       00000000 0        0        0     2        3        1999123  # rdma retrans drops\n";
  if (!dump_to_file(path, demo)) return false;
  return parse_netlink_file(path, snap);
}

// ─────────────────────────────────────────────────────────────────────────────
// Watch mode (periodic refresh with deltas)
// ─────────────────────────────────────────────────────────────────────────────
static std::string sock_key(const NetlinkSock& s) {
  return s.sk + "|" + std::to_string(s.proto) + "|" + std::to_string(s.pid) + "|" +
         std::to_string(s.groups) + "|" + std::to_string(s.inode);
}

static void render_delta(const Snapshot& prev, const Snapshot& cur, const Filters& f) {
  auto key = [](const NetlinkSock& s) { return sock_key(s); };
  std::set<std::string> prev_ids, cur_ids;
  for (const auto& s : prev.socks) if (passes(s, f)) prev_ids.insert(key(s));
  for (const auto& s : cur.socks)  if (passes(s, f)) cur_ids.insert(key(s));
  std::vector<std::string> added, removed;
  for (const auto& k : cur_ids)  if (!prev_ids.contains(k)) added.push_back(k);
  for (const auto& k : prev_ids) if (!cur_ids.contains(k)) removed.push_back(k);
  long drops_delta = 0;
  for (const auto& s : cur.socks) if (passes(s, f)) drops_delta += s.drops;
  std::cout << C_DIM << "  delta vs previous: "
            << C_GREEN << "+" << added.size() << " new   "
            << C_RED << "-" << removed.size() << " gone   "
            << C_CYAN << "total " << cur.socks.size() << C_RESET
            << (added.empty() && removed.empty() ? "  (stable)" : "") << "\n\n";
}

// ─────────────────────────────────────────────────────────────────────────────
// Selftest (ad-hoc truth for this binary)
// ─────────────────────────────────────────────────────────────────────────────
static int g_pass = 0, g_fail = 0;
static void check(bool ok, const std::string& what) {
  if (ok) { ++g_pass; } else { ++g_fail; std::cout << "    FAIL  " << what << "\n"; }
}

static int selftest() {
  std::cout << "== parse helpers ==\n";
  check(parse_ll("  42") == 42LL, "parse_ll trims spaces");
  check(!parse_ll("12a").has_value(), "parse_ll trailing garbage -> nullopt");
  check(parse_ll("00000113", 16) == 0x113LL, "parse_ll hex groups");
  check(std::popcount(0x113u) == 4, "popcount 0x113 == 4");

  std::cout << "== family names ==\n";
  check(std::string(family_name(0)) == "ROUTE", "family 0 ROUTE");
  check(std::string(family_name(9)) == "AUDIT", "family 9 AUDIT");
  check(std::string(family_name(15)) == "KOBJECT_UEVENT", "family 15 KOBJECT_UEVENT");
  check(std::string(family_name(16)) == "GENERIC", "family 16 GENERIC");
  check(std::string(family_name(23)) == "DATAPATH", "family 23 DATAPATH");
  check(std::string(family_name(99)) == "UNKNOWN", "unknown family -> UNKNOWN");

  std::cout << "== /proc/net/netlink parser ==\n";
  {
    Snapshot s;
    check(parse_netlink_file("/proc/net/netlink", s), "opens real /proc/net/netlink");
    check(s.ts == 0, "ts not set by parser (set by caller)");
    if (!s.socks.empty()) {
      const auto& s0 = s.socks.front();
      check(s0.sk.size() == 16, "sk is 16 hex chars");
      check(s0.proto >= 0 && s0.proto <= 23, "real proto in range");
      check(s0.pid >= 0, "real pid >= 0");
      check(s0.inode > 0, "real inode > 0");
      check(s0.rmem >= 0 && s0.wmem >= 0, "real rmem/wmem >= 0");
    }
    std::string dump =
      "sk               Eth Pid        Groups   Rmem     Wmem     Dump  Locks    Drops    Inode\n"
      "0000000000000000 0   3133       00000000 0        0        0     2        0        9310177\n"
      "0000000000000000 9   5214       00000555 4096     2048     1     2        12       9822214\n"
      "0000000000000000 16  1082       00000000 0        0        0     2        0        1133888\n"
      "# comment tolerated\n"
      "0000000000000000 23  3133       00000000 0        0        0     2        17       9310216  # trailing\n";
    Snapshot s2;
    std::string path = "/tmp/netlink-selftest.table";
    if (dump_to_file(path, dump)) check(parse_netlink_file(path, s2), "parses synthetic dump");
    else check(false, "cannot write dump");
    check(s2.socks.size() == 4, "4 rows parsed (comments skipped)");
    if (s2.socks.size() == 4) {
      check(s2.socks[0].proto == 0 && s2.socks[0].pid == 3133, "socks[0] ROUTE pid 3133");
      check(s2.socks[0].groups == 0 && !s2.socks[0].has_groups(), "socks[0] no groups");
      check(s2.socks[1].proto == 9 && s2.socks[1].groups == 0x555u, "socks[1] AUDIT groups 0x555");
      check(s2.socks[1].group_count() == 6, "socks[1] popcount 6");
      check(s2.socks[1].rmem == 4096 && s2.socks[1].wmem == 2048, "socks[1] rmem/wmem");
      check(s2.socks[1].dump == 1 && s2.socks[1].locks == 2, "socks[1] dump=1 locks=2");
      check(s2.socks[1].drops == 12, "socks[1] drops == 12");
      check(s2.socks[2].pid == 1082 && s2.socks[2].proto == 16, "socks[2] GENERIC pid 1082");
      check(s2.socks[3].proto == 23 && s2.socks[3].drops == 17, "socks[3] DATAPATH drops 17");
      check(s2.socks[3].inode == 9310216LL, "socks[3] inode");
      check(s2.socks[0].is_kernel() == false && s2.socks[3].is_kernel() == false,
            "is_kernel false for userspace pids");
      check(std::is_sorted(s2.socks.begin(), s2.socks.end(),
                           [](const NetlinkSock& a, const NetlinkSock& b) { return a.inode < b.inode; })
            || std::is_sorted(s2.socks.begin(), s2.socks.end(),
                              [](const NetlinkSock& a, const NetlinkSock& b) { return a.proto < b.proto; }),
            "synthetic dump sorted by inode or proto (stable input)");
    }
    std::remove(path.c_str());
  }

  std::cout << "== kernel sockets ==\n";
  {
    Snapshot s;
    s.socks.clear(); s.procs.clear();
    demo_load_file("/tmp/netlink-demo1.table", s);
    NetlinkSock k;
    k.pid = 0; k.proto = 15; k.groups = 0;
    check(k.is_kernel(), "pid 0 -> kernel socket");
    check(!s.socks.empty(), "demo loads non-empty");
    std::remove("/tmp/netlink-demo1.table");
  }

  std::cout << "== filters ==\n";
  {
    Snapshot s;
    demo_load_file("/tmp/netlink-demo2.table", s);
    Filters f;
    f.proto = 15;
    int n = 0;
    for (const auto& x : s.socks) if (passes(x, f)) ++n;
    check(n == 3, "demo family 15 count == 3");
    f = Filters{};
    f.proto = 16;
    n = 0;
    for (const auto& x : s.socks) if (passes(x, f)) ++n;
    check(n == 11, "demo family 16 count == 11");
    f = Filters{};
    f.drops_only = true;
    n = 0;
    for (const auto& x : s.socks) if (passes(x, f)) ++n;
    check(n == 3, "demo drops>0 count == 3");
    f = Filters{};
    f.groups_only = true;
    n = 0;
    for (const auto& x : s.socks) if (passes(x, f)) ++n;
    check(n == 3, "demo with-groups count == 3");
    f = Filters{};
    f.pid = 1082;
    n = 0;
    for (const auto& x : s.socks) if (passes(x, f)) ++n;
    check(n == 2, "demo pid 1082 -> 2 sockets");
    std::remove("/tmp/netlink-demo2.table");
  }

  std::cout << "== demo snapshot ==\n";
  {
    Snapshot s;
    s.socks.clear(); s.procs.clear();
    demo_load_file("/tmp/netlink-demo3.table", s);
    check(s.socks.size() == 33, "demo has 33 sockets");
    check(s.count_proto(0) == 2, "demo 2 ROUTE");
    check(s.count_proto(9) == 2, "demo 2 AUDIT");
    check(s.count_proto(15) == 3, "demo 3 KOBJECT_UEVENT");
    check(s.count_proto(16) == 11, "demo 11 GENERIC");
    check(s.count_proto(23) == 3, "demo 3 DATAPATH");
    check(s.count_groups() == 3, "demo 3 multicast listeners");
    check(s.count_kernel() == 2, "demo 2 kernel sockets");
    check(s.total_drops() == 24, "demo total drops == 24");
    check(s.protos().size() == 16, "demo 16 distinct families");
    std::remove("/tmp/netlink-demo3.table");
  }

  std::cout << "== JSON validity ==\n";
  {
    Snapshot s;
    s.ts = 1785117430;
    s.socks.clear(); s.procs.clear();
    demo_load_file("/tmp/netlink-demo4.table", s);
    std::ostringstream os;
    render_json(os, s, true);
    std::string j = os.str();
    check(j.starts_with("{\n  \"summary\": {"), "json starts with quoted summary key");
    check(j.find("\"sockets\": [") != std::string::npos, "json has quoted sockets array");
    check(j.find("\"family\": \"AUDIT\"") != std::string::npos, "json family quoted");
    check(j.find("\"drops\": 17") != std::string::npos, "json drops value present");
    check(std::count(j.begin(), j.end(), '{') == std::count(j.begin(), j.end(), '}'),
          "json braces balanced");
    check(j.rfind("}") == j.size() - 2, "json ends with closing brace");
    std::remove("/tmp/netlink-demo4.table");
  }

  std::cout << "== real /proc + comm resolution ==\n";
  {
    Snapshot s;
    check(parse_netlink_file("/proc/net/netlink", s), "reads real /proc/net/netlink");
    s.ts = now_secs();
    resolve_procs(s);
    if (!s.socks.empty()) {
      bool any_user = false;
      for (const auto& x : s.socks) if (x.pid > 0) { any_user = true; break; }
      if (any_user) {
        bool any_comm = false;
        for (const auto& [pid, comm] : s.procs) if (!comm.empty()) { any_comm = true; break; }
        check(any_comm, "at least one userland pid resolved to a comm");
      } else {
        std::cout << "  INFO  host has only kernel netlink sockets\n";
        check(true, "kernel-only host tolerated");
      }
    } else {
      std::cout << "  INFO  host has 0 netlink sockets\n";
      check(true, "sparse host tolerated");
    }
  }

  std::cout << "\nRESULT: " << g_pass << " passed, " << g_fail << " failed\n";
  return g_fail == 0 ? 0 : 1;
}

// ─────────────────────────────────────────────────────────────────────────────
// main
// ─────────────────────────────────────────────────────────────────────────────
static void usage() {
  std::cout <<
    "Usage: ./netlink-watch [options]\n"
    "  Linux netlink socket monitor — /proc/net/netlink\n"
    "\n"
    "  --proto N            filter by protocol family id (0 ROUTE .. 23 DATAPATH)\n"
    "  --groups             only sockets listening on multicast groups\n"
    "  --drops              only sockets with dropped messages (drops > 0)\n"
    "  --pid PID            only sockets owned by that pid\n"
    "  --top N              show only the first N sockets\n"
    "  --watch N            refresh every N seconds, printing deltas\n"
    "  --json               machine-readable JSON output\n"
    "  --demo               synthetic 33-socket demo (udev + audit + route + apps)\n"
    "  --file PATH          parse a dump file instead of /proc (tolerates # comments)\n"
    "  --no-color           disable ANSI colors (0 escapes in pipes)\n"
    "  --selftest           run self-tests\n"
    "  -h, --help           show this help\n";
}

int main(int argc, char** argv) {
  Filters f;
  for (int i = 1; i < argc; ++i) {
    std::string_view a{argv[i]};
    auto next_val = [&](const char* flag) -> std::optional<std::string> {
      if (i + 1 < argc) { ++i; return std::string(argv[i]); }
      std::cerr << "Missing value for " << flag << "\n";
      return std::nullopt;
    };
    if (a == "-h" || a == "--help") { usage(); return 0; }
    else if (a == "--selftest")     { return selftest(); }
    else if (a == "--no-color")     { f.color = false; disable_color(); }
    else if (a == "--json")         { f.json = true; }
    else if (a == "--demo")         { f.demo = true; }
    else if (a == "--groups")       { f.groups_only = true; }
    else if (a == "--drops")        { f.drops_only = true; }
    else if (a == "--proto") {
      auto v = next_val("--proto"); if (!v) return 2;
      if (auto n = parse_ll(*v)) {
        f.proto = static_cast<int>(*n);
        if (f.proto < 0 || f.proto > 23) { std::cerr << "Bad --proto (0..23)\n"; return 2; }
      } else { std::cerr << "Bad --proto\n"; return 2; }
    }
    else if (a == "--pid") {
      auto v = next_val("--pid"); if (!v) return 2;
      if (auto n = parse_ll(*v)) f.pid = *n; else { std::cerr << "Bad --pid\n"; return 2; }
    }
    else if (a == "--top") {
      auto v = next_val("--top"); if (!v) return 2;
      if (auto n = parse_ll(*v)) f.top = static_cast<int>(*n); else { std::cerr << "Bad --top\n"; return 2; }
    }
    else if (a == "--watch") {
      auto v = next_val("--watch"); if (!v) return 2;
      if (auto n = parse_ll(*v)) f.watch = static_cast<int>(*n); else { std::cerr << "Bad --watch\n"; return 2; }
      if (f.watch <= 0) f.watch = 0;
    }
    else if (a == "--file") {
      auto v = next_val("--file"); if (!v) return 2;
      f.file = *v;
    }
    else { std::cerr << "Unknown option: " << a << "\n"; usage(); return 2; }
  }

  if (f.watch > 0) {
    Snapshot prev, cur;
    auto load = [&](Snapshot& s) {
      s.socks.clear(); s.procs.clear();
      bool ok = f.demo ? demo_load_file("/tmp/netlink-watch-demo.table", s)
                       : f.file.empty() ? parse_netlink_file("/proc/net/netlink", s)
                                        : parse_netlink_file(f.file, s);
      if (ok) { s.ts = now_secs(); resolve_procs(s); }
      return ok;
    };
    load(prev);
    for (;;) {
      load(cur);
      render_snapshot(cur, f, true);
      render_delta(prev, cur, f);
      prev = std::move(cur);
      std::this_thread::sleep_for(std::chrono::seconds(static_cast<unsigned>(f.watch)));
    }
  }

  Snapshot s;
  s.ts = now_secs();
  if (f.demo) {
    if (!demo_load_file("/tmp/netlink-watch-demo.table", s)) { std::cerr << "Cannot write demo table\n"; return 1; }
  } else if (!f.file.empty()) {
    if (!parse_netlink_file(f.file, s)) { std::cerr << "Cannot open " << f.file << "\n"; return 1; }
  } else {
    if (!parse_netlink_file("/proc/net/netlink", s)) { std::cerr << "Cannot open /proc/net/netlink\n"; return 1; }
  }
  resolve_procs(s);
  if (f.json) render_json(std::cout, s, f.demo);
  else        render_snapshot(s, f, false);
  return 0;
}