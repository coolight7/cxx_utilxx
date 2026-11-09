/// 插件网络能力实现: HTTP / TCP / WebSocket / UDP
///
/// 设计与安全边界见 plugin_net_hub.h。文件结构:
/// 1) 公共小工具 (URL / 头解析 / 正文解码 / base64 / SHA-1 / UTF-8 校验);
/// 2) `Stream`: 一条连接的读写与背压 (其余连接类型都继承它);
/// 3) `PluginNetHub::Impl`: 服务表、连接表、HTTP 待回答表与操作分发;
/// 4) HTTP 客户端 / HTTP 服务端 / TCP / WebSocket 四组实现;
/// 5) 对外 (同步 / 异步 / 取消 / 卸载) 入口。
///
/// 线程: 全部 socket 状态只在网络线程上访问; 对外入口投递到网络线程并**有界等待**
/// (网络线程不会等插件框架线程, 所以不会互锁)。

#include "utilxx/plugin_net_hub.h"

#include "utilxx/plugin_net_hub_tls.h"

#include "utilxx/http_client.h"
#include "utilxx/http_server.h"
#include "utilxx/tcp.h"
#include "utilxx/udp.h"


#include "utilxx_base/asio_error.h"
#include "utilxx_base/json.h"
#include "utilxx_base/log.h"
#include "utilxx_base/string_util.h"

#include <asio/bind_cancellation_slot.hpp>
#include <asio/buffer.hpp>
#include <asio/cancellation_signal.hpp>
#include <asio/connect.hpp>
#include <asio/co_spawn.hpp>
#include <asio/detached.hpp>
#include <asio/error.hpp>
#include <asio/io_context.hpp>
#include <asio/ip/address.hpp>
#include <asio/ip/multicast.hpp>
#include <asio/ip/tcp.hpp>
#include <asio/ip/udp.hpp>
#include <asio/post.hpp>
#include <asio/read.hpp>
#include <asio/redirect_error.hpp>
#include <asio/steady_timer.hpp>
#include <asio/use_awaitable.hpp>
#include <asio/write.hpp>

#include <algorithm>
#include <atomic>
#include <charconv>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <cstring>
#include <deque>
#include <filesystem>
#include <fstream>
#include <limits>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <random>
#include <set>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

namespace utilxx {

using utilxx_base::AsioErrorCode;
using utilxx_base::Json;

namespace {

/// 安全解析 JSON 文本 (`utilxx_base::Json::parse` 对非法输入抛异常, C 边界不允许异常穿越)
///
/// - `ok` 非空时写出"输入是否为合法 JSON"; 失败时返回空对象
/// - 空输入按合法空对象处理 (调用方语义: 缺省参数)
Json parseJsonSafe(std::string_view text, bool *ok = nullptr) {
  if (ok) {
    *ok = false;
  }
  if (text.empty()) {
    if (ok) {
      *ok = true;
    }
    return Json::object();
  }
  try {
    Json parsed = Json::parse(text);
    if (ok) {
      *ok = true;
    }
    return parsed;
  } catch (...) {
    return Json::object();
  }
}

/// 把一段可能来自操作系统的文本转成 UTF-8 (系统错误文本是本机编码, 直接当 UTF-8 用会乱码)
std::string osTextToUtf8(const std::string &text) {
  std::string out = text;
  utilxx_base::autoConvertToUtf8(out);
  return out;
}

/* ==================== 上限 (改大之前先想清楚内存) ==================== */

/// 单条连接一次读的字节数
constexpr size_t kReadChunk = 16 * 1024;
/// 请求头 / 响应头上限
constexpr size_t kMaxHeadBytes = 16 * 1024;
/// HTTP 正文上限 (请求与响应共用; 超过按 413 / truncated 处理)
constexpr int64_t kMaxHttpBody = 8 * 1024 * 1024;
/// WebSocket 单条消息上限
constexpr int64_t kMaxWsMessage = 8 * 1024 * 1024;
/// 单条连接的发送队列上限 (背压)
constexpr size_t kMaxOutQueue = 4 * 1024 * 1024;
/// 单个 HTTP 服务最多登记几条静态路由
constexpr size_t kMaxStaticRoutes = 1024;
/// 单条内存内容路由的上限 (大内容清用文件)
constexpr int64_t kMaxStaticBytes = 8 * 1024 * 1024;
/// 静态路由 URL 尾段里的文件名长度上限 (只用于展示)
constexpr size_t kMaxStaticFileName = 120;
/// 每个插件最多几个同类服务
constexpr int32_t kMaxServersPerKind = 8;
/// 每个插件最多几条连接 (客户端 + 服务端)
constexpr size_t kMaxConnectionsPerPlugin = 64;
/// 每个插件最多几个 UDP 通道 (每个通道一个 socket, 防止把进程 fd 用完)
constexpr size_t kMaxUdpChannelsPerPlugin = 32;
/// 每个插件同时进行的 HTTP 客户端请求
constexpr size_t kMaxHttpClientsPerPlugin = 16;
/// 每个 HTTP 服务同时等待插件回答的请求
constexpr size_t kMaxHttpPendingPerServer = 64;
/// HTTP 客户端默认超时
constexpr int64_t kDefaultHttpTimeoutMs = 15000;
/// 同步入口等网络线程的上界
constexpr uint32_t kCallWaitMs = 5000;

/* ==================== 文本小工具 ==================== */

std::string lowerAscii(std::string text) {
  for (char &c : text) {
    if (c >= 'A' && c <= 'Z') {
      c = static_cast<char>(c - 'A' + 'a');
    }
  }
  return text;
}

std::string_view trimAscii(std::string_view text) {
  while (!text.empty() && (text.front() == ' ' || text.front() == '\t' ||
                           text.front() == '\r' || text.front() == '\n')) {
    text.remove_prefix(1);
  }
  while (!text.empty() && (text.back() == ' ' || text.back() == '\t' ||
                           text.back() == '\r' || text.back() == '\n')) {
    text.remove_suffix(1);
  }
  return text;
}

bool startsWith(std::string_view text, std::string_view prefix) {
  return text.size() >= prefix.size() && text.compare(0, prefix.size(), prefix) == 0;
}

bool iequals(std::string_view a, std::string_view b) {
  if (a.size() != b.size()) {
    return false;
  }
  for (size_t i = 0; i < a.size(); ++i) {
    char x = a[i];
    char y = b[i];
    if (x >= 'A' && x <= 'Z') x = static_cast<char>(x - 'A' + 'a');
    if (y >= 'A' && y <= 'Z') y = static_cast<char>(y - 'A' + 'a');
    if (x != y) {
      return false;
    }
  }
  return true;
}

/// 是否是合法 UTF-8 (只用来决定"要不要多给一个 text 字段")
bool isValidUtf8(std::string_view text) {
  size_t i = 0;
  const size_t n = text.size();
  while (i < n) {
    const unsigned char c = static_cast<unsigned char>(text[i]);
    if (c < 0x80) {
      ++i;
      continue;
    }
    size_t extra = 0;
    uint32_t code = 0;
    if ((c & 0xE0) == 0xC0) {
      extra = 1;
      code = c & 0x1F;
    } else if ((c & 0xF0) == 0xE0) {
      extra = 2;
      code = c & 0x0F;
    } else if ((c & 0xF8) == 0xF0) {
      extra = 3;
      code = c & 0x07;
    } else {
      return false;
    }
    if (i + extra >= n) {
      return false;
    }
    for (size_t k = 1; k <= extra; ++k) {
      const unsigned char cc = static_cast<unsigned char>(text[i + k]);
      if ((cc & 0xC0) != 0x80) {
        return false;
      }
      code = (code << 6) | (cc & 0x3F);
    }
    // 过长编码与代理区不算合法
    if ((extra == 1 && code < 0x80) || (extra == 2 && code < 0x800) ||
        (extra == 3 && code < 0x10000) || code > 0x10FFFF ||
        (code >= 0xD800 && code <= 0xDFFF)) {
      return false;
    }
    i += extra + 1;
  }
  return true;
}

/// 把一段字节变成安全的 JSON 文本: 非法 UTF-8 字节换成 '?'
///
/// 用途: HTTP 头值按规范可能是 ISO-8859-1, 直接写进 JSON 会让 LLM/JS 的发解析失败。
std::string toSafeText(std::string_view text) {
  if (isValidUtf8(text)) {
    return std::string{text};
  }
  std::string out;
  out.reserve(text.size());
  size_t i = 0;
  while (i < text.size()) {
    const unsigned char c = static_cast<unsigned char>(text[i]);
    if (c < 0x80) {
      out.push_back(static_cast<char>(c));
      ++i;
      continue;
    }
    size_t extra = 0;
    if ((c & 0xE0) == 0xC0) {
      extra = 1;
    } else if ((c & 0xF0) == 0xE0) {
      extra = 2;
    } else if ((c & 0xF8) == 0xF0) {
      extra = 3;
    }
    bool valid = extra > 0 && i + extra < text.size();
    if (valid) {
      for (size_t k = 1; k <= extra; ++k) {
        if ((static_cast<unsigned char>(text[i + k]) & 0xC0) != 0x80) {
          valid = false;
          break;
        }
      }
    }
    if (valid) {
      out.append(text.substr(i, extra + 1));
      i += extra + 1;
    } else {
      out.push_back('?');
      ++i;
    }
  }
  return out;
}

/// 错误码 → 可读原因（系统给的文本是本机编码，按 UTF-8 转一次，见上面的 osTextToUtf8）
std::string errorTextOf(const AsioErrorCode &ec) {
  return osTextToUtf8(ec.message());
}

std::string hexEncode(const unsigned char *data, size_t size) {
  static const char *kDigits = "0123456789abcdef";
  std::string out;
  out.reserve(size * 2);
  for (size_t i = 0; i < size; ++i) {
    out.push_back(kDigits[(data[i] >> 4) & 0x0F]);
    out.push_back(kDigits[data[i] & 0x0F]);
  }
  return out;
}

std::vector<unsigned char> randomBytes(size_t count) {
  std::vector<unsigned char> bytes(count);
  static std::mutex rngMutex;
  static std::mt19937_64 rng{[] {
    std::random_device rd;
    std::seed_seq seq{rd(), rd(), rd(), rd(), rd(), rd(), rd(), rd()};
    std::mt19937_64 engine{seq};
    return engine;
  }()};
  {
    std::lock_guard lock{rngMutex};
    for (size_t i = 0; i < count; i += 8) {
      const uint64_t value = rng();
      for (size_t b = 0; b < 8 && i + b < count; ++b) {
        bytes[i + b] = static_cast<unsigned char>((value >> (8 * b)) & 0xFF);
      }
    }
  }
  return bytes;
}

/// SHA-1 (WebSocket 握手用; 只要一个用途, 不引入加密库)
std::string sha1Raw(std::string_view data) {
  uint32_t h[5] = {0x67452301u, 0xEFCDAB89u, 0x98BADCFEu, 0x10325476u,
                   0xC3D2E1F0u};
  std::string message{data};
  const uint64_t bitLen = static_cast<uint64_t>(message.size()) * 8;
  message.push_back(static_cast<char>(0x80));
  while (message.size() % 64 != 56) {
    message.push_back('\0');
  }
  for (int i = 7; i >= 0; --i) {
    message.push_back(static_cast<char>((bitLen >> (8 * i)) & 0xFF));
  }
  for (size_t offset = 0; offset + 64 <= message.size(); offset += 64) {
    uint32_t w[80] = {};
    for (size_t i = 0; i < 16; ++i) {
      const auto *p = reinterpret_cast<const unsigned char *>(message.data() +
                                                             offset + i * 4);
      w[i] = (static_cast<uint32_t>(p[0]) << 24) |
             (static_cast<uint32_t>(p[1]) << 16) |
             (static_cast<uint32_t>(p[2]) << 8) | static_cast<uint32_t>(p[3]);
    }
    for (size_t i = 16; i < 80; ++i) {
      w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]);
      w[i] = (w[i] << 1) | (w[i] >> 31);
    }
    uint32_t a = h[0];
    uint32_t b = h[1];
    uint32_t c = h[2];
    uint32_t d = h[3];
    uint32_t e = h[4];
    for (size_t i = 0; i < 80; ++i) {
      uint32_t f = 0;
      uint32_t k = 0;
      if (i < 20) {
        f = (b & c) | ((~b) & d);
        k = 0x5A827999u;
      } else if (i < 40) {
        f = b ^ c ^ d;
        k = 0x6ED9EBA1u;
      } else if (i < 60) {
        f = (b & c) | (b & d) | (c & d);
        k = 0x8F1BBCDCu;
      } else {
        f = b ^ c ^ d;
        k = 0xCA62C1D6u;
      }
      const uint32_t temp = ((a << 5) | (a >> 27)) + f + e + k + w[i];
      e = d;
      d = c;
      c = (b << 30) | (b >> 2);
      b = a;
      a = temp;
    }
    h[0] += a;
    h[1] += b;
    h[2] += c;
    h[3] += d;
    h[4] += e;
  }
  unsigned char out[20] = {};
  for (size_t i = 0; i < 5; ++i) {
    out[i * 4 + 0] = static_cast<unsigned char>((h[i] >> 24) & 0xFF);
    out[i * 4 + 1] = static_cast<unsigned char>((h[i] >> 16) & 0xFF);
    out[i * 4 + 2] = static_cast<unsigned char>((h[i] >> 8) & 0xFF);
    out[i * 4 + 3] = static_cast<unsigned char>(h[i] & 0xFF);
  }
  return std::string(reinterpret_cast<const char *>(out), sizeof(out));
}

std::string wsAcceptKey(std::string_view clientKey) {
  static constexpr std::string_view kGuid =
      "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
  const std::string digest = sha1Raw(std::string{clientKey} + std::string{kGuid});
  return utilxx_base::base64Encode(digest);
}

std::string wsClientKey() {
  const auto bytes = randomBytes(16);
  return utilxx_base::base64Encode(
      std::string_view{reinterpret_cast<const char *>(bytes.data()), bytes.size()});
}

const char *statusTextOf(int status) {
  switch (status) {
  case 200: return "OK";
  case 201: return "Created";
  case 202: return "Accepted";
  case 204: return "No Content";
  case 206: return "Partial Content";
  case 301: return "Moved Permanently";
  case 302: return "Found";
  case 303: return "See Other";
  case 304: return "Not Modified";
  case 307: return "Temporary Redirect";
  case 308: return "Permanent Redirect";
  case 400: return "Bad Request";
  case 401: return "Unauthorized";
  case 403: return "Forbidden";
  case 404: return "Not Found";
  case 405: return "Method Not Allowed";
  case 408: return "Request Timeout";
  case 411: return "Length Required";
  case 413: return "Payload Too Large";
  case 416: return "Range Not Satisfiable";
  case 426: return "Upgrade Required";
  case 429: return "Too Many Requests";
  case 500: return "Internal Server Error";
  case 501: return "Not Implemented";
  case 502: return "Bad Gateway";
  case 503: return "Service Unavailable";
  case 504: return "Gateway Timeout";
  default: return "";
  }
}

Json errorJson(std::string_view code, std::string_view message) {
  Json out = Json::object();
  out["ok"] = false;
  out["error"] = std::string{code};
  out["message"] = std::string{message};
  return out;
}

/// JSON 值的文本形式 (字符串原样, 其它类型 dump; 头字段值用)
std::string jsonTextOf(const Json &value) {
  if (value.is_string()) {
    return value.get<std::string>();
  }
  if (value.is_null()) {
    return {};
  }
  return value.dump();
}

/* ==================== URL ==================== */

struct ParsedUrl {
  bool ok = false;
  std::string error;
  std::string scheme; ///< http / https / ws / wss
  std::string host;   ///< 不含端口
  uint16_t port = 0;
  std::string path; ///< 以 / 开头, 含查询串
  std::string target; ///< path + 查询串 (同 path)
};

ParsedUrl parseUrl(const std::string &text) {
  ParsedUrl out;
  const size_t schemeEnd = text.find("://");
  if (schemeEnd == std::string::npos) {
    out.error = "地址必须以 <scheme>:// 开头";
    return out;
  }
  out.scheme = lowerAscii(text.substr(0, schemeEnd));
  const size_t authorityStart = schemeEnd + 3;
  size_t authorityEnd = text.find_first_of("/?#", authorityStart);
  if (authorityEnd == std::string::npos) {
    authorityEnd = text.size();
  }
  const std::string authority = text.substr(authorityStart, authorityEnd - authorityStart);
  if (authority.empty()) {
    out.error = "地址缺少主机名";
    return out;
  }
  std::string hostPort = authority;
  const size_t at = hostPort.find_last_of('@');
  if (at != std::string::npos) {
    hostPort = hostPort.substr(at + 1); ///< 丢弃 userinfo (鉴权走请求头)
  }
  if (!hostPort.empty() && hostPort.front() == '[') {
    const size_t close = hostPort.find(']');
    if (close == std::string::npos) {
      out.error = "IPv6 地址缺少 ]";
      return out;
    }
    out.host = hostPort.substr(1, close - 1);
    if (close + 1 < hostPort.size()) {
      if (hostPort[close + 1] != ':') {
        out.error = "IPv6 地址端口写法不合法";
        return out;
      }
      const std::string portText = hostPort.substr(close + 2);
      if (!portText.empty()) {
        try {
          const int value = std::stoi(portText);
          if (value <= 0 || value > 65535) {
            out.error = "端口超出范围";
            return out;
          }
          out.port = static_cast<uint16_t>(value);
        } catch (...) {
          out.error = "端口不是数字";
          return out;
        }
      }
    }
  } else {
    const size_t colon = hostPort.rfind(':');
    if (colon != std::string::npos) {
      out.host = hostPort.substr(0, colon);
      const std::string portText = hostPort.substr(colon + 1);
      if (!portText.empty()) {
        try {
          const int value = std::stoi(portText);
          if (value <= 0 || value > 65535) {
            out.error = "端口超出范围";
            return out;
          }
          out.port = static_cast<uint16_t>(value);
        } catch (...) {
          out.error = "端口不是数字";
          return out;
        }
      }
    } else {
      out.host = hostPort;
    }
  }
  if (out.host.empty()) {
    out.error = "地址缺少主机名";
    return out;
  }
  if (out.port == 0) {
    out.port = (out.scheme == "https" || out.scheme == "wss") ? 443 : 80;
  }
  std::string path = text.substr(authorityEnd);
  if (path.empty()) {
    path = "/";
  } else if (path.front() == '?') {
    path = "/" + path;
  } else if (path.front() == '#') {
    path = "/";
  }
  // 片段不发给服务端
  const size_t hash = path.find('#');
  if (hash != std::string::npos) {
    path = path.substr(0, hash);
  }
  out.path = path;
  out.target = path;
  out.ok = true;
  return out;
}

/// Host 请求头: 默认端口不写 (与浏览器 / curl 一致), IPv6 字面量要加回方括号
std::string hostHeaderOf(const ParsedUrl &url) {
  const bool isIpv6 = url.host.find(':') != std::string::npos;
  const std::string host = isIpv6 ? "[" + url.host + "]" : url.host;
  const uint16_t defaultPort =
      (url.scheme == "https" || url.scheme == "wss") ? 443 : 80;
  if (url.port == defaultPort) {
    return host;
  }
  return host + ":" + std::to_string(url.port);
}

/// 扩展名 → Content-Type (只覆盖音频/视频/文本这几类常见格式)
std::string contentTypeOfName(const std::string &name) {
  const size_t dot = name.find_last_of('.');
  if (dot == std::string::npos) {
    return {};
  }
  const std::string ext = lowerAscii(name.substr(dot + 1));
  if (ext == "mp3") return "audio/mpeg";
  if (ext == "m4a" || ext == "mp4") return "audio/mp4";
  if (ext == "flac") return "audio/flac";
  if (ext == "wav") return "audio/wav";
  if (ext == "ogg" || ext == "opus") return "audio/ogg";
  if (ext == "aac") return "audio/aac";
  if (ext == "webm") return "video/webm";
  if (ext == "mkv") return "video/x-matroska";
  if (ext == "ts") return "video/mp2t";
  if (ext == "m3u8") return "application/vnd.apple.mpegurl";
  if (ext == "lrc") return "text/plain; charset=utf-8";
  if (ext == "txt" || ext == "json") return "text/plain; charset=utf-8";
  if (ext == "jpg" || ext == "jpeg") return "image/jpeg";
  if (ext == "png") return "image/png";
  return {};
}

/// URL 尾段只保留 unreserved 字符, 其余百分号编码 (中文文件名也能用)
std::string urlEncodePathSegment(const std::string &text) {
  static const char *kDigits = "0123456789ABCDEF";
  std::string out;
  out.reserve(text.size());
  for (const unsigned char c : text) {
    const bool unreserved = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                            (c >= '0' && c <= '9') || c == '-' || c == '_' ||
                            c == '.' || c == '~';
    if (unreserved) {
      out.push_back(static_cast<char>(c));
      continue;
    }
    out.push_back('%');
    out.push_back(kDigits[(c >> 4) & 0x0F]);
    out.push_back(kDigits[c & 0x0F]);
  }
  return out;
}

std::string fileNameOfPath(const std::string &path) {
  const size_t slash = path.find_last_of("/\\");
  return slash == std::string::npos ? path : path.substr(slash + 1);
}

/// 静态路由的文件名只用于 URL 展示: 去掉路径分隔与控制字符, 限长
std::string sanitizeStaticFileName(const std::string &name) {
  std::string out;
  out.reserve((std::min)(name.size(), kMaxStaticFileName));
  for (const unsigned char c : name) {
    if (out.size() >= kMaxStaticFileName) {
      break;
    }
    if (c < 0x20 || c == 0x7F || c == '/' || c == '\\') {
      continue;
    }
    out.push_back(static_cast<char>(c));
  }
  return out;
}

/// 32 位十六进制随机串 (静态路由 URL 里的 token)
std::string randomTokenHex() {
  const auto bytes = randomBytes(16);
  return hexEncode(bytes.data(), bytes.size());
}

/// 单段 Range (`bytes=start-end` / `bytes=start-` / `bytes=-suffix`)
struct ByteRange {
  bool present = false;    ///< 请求里有没有 Range
  bool satisfiable = true; ///< 不合法时回 416
  int64_t start = 0;
  int64_t end = 0; ///< 闭区间
};

int64_t parseNonNegativeInt(const std::string &text) {
  if (text.empty() || text.size() > 18) {
    return -1;
  }
  int64_t value = 0;
  for (const char c : text) {
    if (c < '0' || c > '9') {
      return -1;
    }
    value = value * 10 + (c - '0');
  }
  return value;
}

ByteRange parseRangeHeader(const std::string &header, int64_t size) {
  ByteRange range;
  if (header.empty()) {
    return range;
  }
  range.present = true;
  if (header.size() < 6 || lowerAscii(header.substr(0, 6)) != "bytes=") {
    range.satisfiable = false;
    return range;
  }
  const std::string text{trimAscii(std::string_view{header}.substr(6))};
  // 多段不支持: 当成"没有 Range", 整段返回 (比 416 更宽容, 播放器只用单段)
  if (text.find(',') != std::string::npos) {
    range.present = false;
    return range;
  }
  const size_t dash = text.find('-');
  if (dash == std::string::npos) {
    range.satisfiable = false;
    return range;
  }
  const std::string first{trimAscii(std::string_view{text}.substr(0, dash))};
  const std::string second{trimAscii(std::string_view{text}.substr(dash + 1))};
  if (first.empty()) {
    // 后缀形式: 最后 N 个字节
    const int64_t suffix = parseNonNegativeInt(second);
    if (suffix <= 0 || size <= 0) {
      range.satisfiable = false;
      return range;
    }
    range.start = (std::max)(int64_t{0}, size - suffix);
    range.end = size - 1;
    return range;
  }
  const int64_t start = parseNonNegativeInt(first);
  if (start < 0) {
    range.satisfiable = false;
    return range;
  }
  int64_t end = size - 1;
  if (!second.empty()) {
    end = parseNonNegativeInt(second);
    if (end < 0) {
      range.satisfiable = false;
      return range;
    }
  }
  if (start >= size || start > end) {
    range.satisfiable = false;
    return range;
  }
  range.start = start;
  range.end = (std::min)(end, size - 1);
  return range;
}

/// 从参数里取客户端 TLS 选项 (http.request / http.fetch / http.download / ws.connect 共用)
///
/// `tlsVerify` 默认开; `caFile` / `caPem` 是**追加**信任的 CA (不影响系统根证书);
/// `serverName` 可以覆盖 SNI 与主机名校验用的名字 (调试 / IP 访问时用)。
void parseTlsOptions(const Json &args, TlsClientOptions &options) {
  options.verify = args.value("tlsVerify", true);
  options.caFile = args.value("caFile", std::string{});
  options.caPem = args.value("caPem", std::string{});
  options.serverName = args.value("serverName", std::string{});
}

/// 下载文件名规整:
/// - 只接受"纯名字": 路径分隔符与 `..` 一律拒绕, 拿到的文件名拿不到别的目录;
/// - 非法字符 (Windows 不允许的那些) 换成 `_`, 去掉前导点与空名字;
/// - 没给名字时按 URL 的最后一段推。
std::string downloadFileNameOf(const std::string &raw, const std::string &url) {
  std::string name{trimAscii(raw)};
  if (name.empty()) {
    std::string path = url;
    const size_t schemeEnd = path.find("://");
    if (schemeEnd != std::string::npos) {
      const size_t slash = path.find('/', schemeEnd + 3);
      path = slash == std::string::npos ? std::string{} : path.substr(slash);
    }
    const size_t query = path.find_first_of("?#");
    if (query != std::string::npos) {
      path = path.substr(0, query);
    }
    const size_t slash = path.find_last_of('/');
    name = slash == std::string::npos ? path : path.substr(slash + 1);
  }
  std::string safe;
  safe.reserve(name.size());
  for (const char c : name) {
    const unsigned char u = static_cast<unsigned char>(c);
    if (u < 0x20 || c == '/' || c == '\\' || c == ':' || c == '*' ||
        c == '?' || c == '"' || c == '<' || c == '>' || c == '|') {
      safe.push_back('_');
    } else {
      safe.push_back(c);
    }
  }
  size_t start = 0;
  while (start < safe.size() && (safe[start] == '.' || safe[start] == ' ')) {
    ++start;
  }
  safe = safe.substr(start);
  while (!safe.empty() && (safe.back() == '.' || safe.back() == ' ')) {
    safe.pop_back();
  }
  if (safe.empty() || safe == "..") {
    safe = "download.bin";
  }
  if (safe.size() > 128) {
    safe = safe.substr(safe.size() - 128);
  }
  return safe;
}

/* ==================== HTTP 头 / 正文 ==================== */

struct HttpHead {
  bool request = false;
  std::string method;
  std::string target;
  std::string version;
  int status = 0;
  std::string reason;
  std::vector<std::pair<std::string, std::string>> headers;

  std::string header(std::string_view name) const {
    for (const auto &item : headers) {
      if (iequals(item.first, name)) {
        return item.second;
      }
    }
    return {};
  }
  bool hasHeader(std::string_view name) const {
    for (const auto &item : headers) {
      if (iequals(item.first, name)) {
        return true;
      }
    }
    return false;
  }
  Json headersJson() const {
    Json out = Json::object();
    for (const auto &item : headers) {
      const std::string key = lowerAscii(toSafeText(item.first));
      if (out.contains(key)) {
        // 重复头 (Set-Cookie 等) 用换行拼起来; 单值头按规范也可以这样看
        const std::string previous = out.value(key, std::string{});
        out[key] = previous + "\n" + toSafeText(item.second);
      } else {
        out[key] = toSafeText(item.second);
      }
    }
    return out;
  }
};

/// 解析请求头或响应头 (输入不含结尾空行也可以)
bool parseHttpHead(std::string_view text, bool request, HttpHead &out) {
  out = HttpHead{};
  out.request = request;
  size_t pos = 0;
  bool firstLine = true;
  while (pos <= text.size()) {
    size_t lineEnd = text.find('\n', pos);
    std::string_view line = lineEnd == std::string_view::npos
                                ? text.substr(pos)
                                : text.substr(pos, lineEnd - pos);
    if (!line.empty() && line.back() == '\r') {
      line.remove_suffix(1);
    }
    if (firstLine) {
      firstLine = false;
      if (request) {
        const size_t sp1 = line.find(' ');
        const size_t sp2 = sp1 == std::string_view::npos
                              ? std::string_view::npos
                              : line.find(' ', sp1 + 1);
        if (sp1 == std::string_view::npos || sp2 == std::string_view::npos) {
          return false;
        }
        out.method = std::string{line.substr(0, sp1)};
        out.target = std::string{line.substr(sp1 + 1, sp2 - sp1 - 1)};
        out.version = std::string{line.substr(sp2 + 1)};
      } else {
        const size_t sp1 = line.find(' ');
        if (sp1 == std::string_view::npos) {
          return false;
        }
        if (!startsWith(line, "HTTP/")) {
          return false;
        }
        out.version = std::string{line.substr(0, sp1)};
        const std::string_view rest = line.substr(sp1 + 1);
        const size_t sp2 = rest.find(' ');
        const std::string codeText{rest.substr(0, sp2)};
        try {
          out.status = std::stoi(codeText);
        } catch (...) {
          return false;
        }
        if (sp2 != std::string_view::npos) {
          out.reason = std::string{rest.substr(sp2 + 1)};
        }
      }
    } else if (!line.empty()) {
      const size_t colon = line.find(':');
      if (colon == std::string_view::npos) {
        return false;
      }
      out.headers.emplace_back(std::string{line.substr(0, colon)},
                               std::string{trimAscii(line.substr(colon + 1))});
    }
    if (lineEnd == std::string_view::npos) {
      break;
    }
    pos = lineEnd + 1;
  }
  return firstLine == false && (!request || !out.method.empty()) &&
         (request || out.status > 0);
}

/// 请求行里 target 的路径与查询串
void splitTarget(std::string_view target, std::string &path, std::string &query) {
  const size_t mark = target.find('?');
  if (mark == std::string_view::npos) {
    path = std::string{target};
    query.clear();
    return;
  }
  path = std::string{target.substr(0, mark)};
  query = std::string{target.substr(mark + 1)};
}

/* ==================== 有界等待槽 (网络线程 → 调用线程) ==================== */

struct SyncSlot {
  std::mutex mutex;
  std::condition_variable cv;
  bool done = false;

  void set() {
    {
      std::lock_guard lock{mutex};
      done = true;
    }
    cv.notify_all();
  }

  bool wait(uint32_t timeoutMs) {
    std::unique_lock lock{mutex};
    return cv.wait_for(lock, std::chrono::milliseconds{timeoutMs},
                       [this] { return done; });
  }
};

} // namespace

/// `PluginNetHub::Impl` 已在 plugin_net_hub.h 里声明过 (嵌套类型), 这里不需要也不该再前置声明:
/// `struct PluginNetHub::Impl;` 这种带限定名的写法在 clang 上是错误
/// ("forward declaration of struct cannot have a nested name specifier"),
/// MSVC / GCC 能容忍它, 所以 Android / iOS 构建才会把它报出来。

/// 一条 TCP 连接 (客户端或服务端接受的那一端)
struct Stream : std::enable_shared_from_this<Stream> {
  Stream(std::shared_ptr<PluginNetHub::Impl> hub, asio::ip::tcp::socket socket);

  /// 接管库的一条 TCP 连接（发送队列、暂停、事件与 NetStream 那条路一致）
  Stream(std::shared_ptr<PluginNetHub::Impl> hub,
         std::shared_ptr<utilxx::TcpConnection> connection);
  virtual ~Stream() = default;

  std::shared_ptr<PluginNetHub::Impl> hub;
  std::string plugin;
  std::string id;
  std::string serverId; ///< 空 = 客户端连接
  std::string remote;
  std::string local;

  /// 连接的读写层: 纯 TCP 或客户端 TLS (建好之后所有读写都经过它)
  std::shared_ptr<NetStream> io;
  /// 走库的 `TcpConnection` 时非空（与 `io` 二选一）
  std::shared_ptr<utilxx::TcpConnection> tcpConn;
  std::vector<char> readBuf;
  std::deque<std::string> outQueue;
  size_t outBytes = 0;
  bool writing = false;
  bool closing = false;
  bool closeWhenFlushed = false;
  /// 暂停读 (不再产生 data 事件)。用于插件自己做背压: 接收端写不动时先暂停上游。
  bool paused = false;
  /// 是否已经有一个读在飞 (暂停/恢复靠它判断要不要重新排读)
  bool reading = false;
  /// `waitClosed()` 的等待点（关掉连接时取消）
  std::shared_ptr<asio::steady_timer> closedTimer;

  /// 等这条连接关掉（服务端的 accept 协程靠它挂到连接结束）
  asio::awaitable<void> waitClosed();

  void start();
  void startRead();
  void setPaused(bool value);
  void send(std::string data, std::string &err);
  void flushThenClose();
  void closeStream(std::string_view reason, std::string_view error);

  /// 收到字节 (网络线程; 实现里可以直接 closeStream)
  virtual void onBytes(const char *data, size_t size) = 0;
  /// 连接关闭事件 (`kind` 由实现决定怎么发布)
  virtual void onClosed(std::string_view reason, std::string_view error) = 0;
  /// 连接类别 (tcp / ws / http), 用于 info 与自省
  virtual const char *kind() const = 0;
  /// 发送队列排空后的回调 (默认什么也不做; 静态内容用它继续读下一段)
  virtual void onWritten() {}

private:
  void startWrite();
  void afterWrite(AsioErrorCode ec);
};

} // namespace utilxx

namespace utilxx {

struct HttpRequestTask;
struct TcpStream;
struct WsStream;
struct UdpChannel;

/// HTTP 客户端的三处用法: 同一个实现, 结果 JSON 的字段不同
///   Request  = `http.request` (原始响应: 正文 + headers)
///   Fetch    = `http.fetch`   (只要结果、不要中间事件的形态)
///   Download = `http.download` (正文流式写文件, 结果里给路径与字节数)
enum class HttpMode : int32_t { Request = 0, Fetch = 1, Download = 2 };

/* ==================== 网络中心 ==================== */

struct PluginNetHub::Impl : std::enable_shared_from_this<PluginNetHub::Impl> {
  PublishFn publish;
  PostFn postToFramework;

  asio::io_context io;
  std::unique_ptr<asio::executor_work_guard<asio::io_context::executor_type>>
      guard;
  std::thread thread;
  std::atomic<bool> running{false};
  std::atomic<int64_t> nextRequestId{1};
  std::atomic<int64_t> nextConnSeq{1};
  /// 插件私有数据根目录 (http.download 落盘用; 在 start() 之前设)
  std::string dataDir;

  /// 一个服务 (HTTP / TCP / WS)
  struct Server {
    /// 一条静态路由: 命中后由框架直接回答, **不发 `http.request` 事件**
    ///
    /// 原先另有一个"插件本地 HTTP 文件服务"（脚本侧的 serve 系列）。它已经并到这里:
    /// 同一个 HTTP 服务里既能自己回答请求, 也能挂几个文件 / 内存内容。
    struct StaticRoute {
      std::string path;        ///< 请求路径 (以 / 开头; 自动生成的带 token 段)
      std::string file;        ///< 本地文件绝对路径 (与 bytes 二选一)
      std::string bytes;       ///< 内存内容 (≤ kMaxStaticBytes)
      std::string contentType; ///< 响应用的 Content-Type
      std::string fileName;    ///< 只用于 URL 尾段与日志
      int64_t size = 0;
      int64_t mtimeMs = 0; ///< 文件登记时的修改时间 (内存内容为 0)
    };

    std::string plugin;
    std::string kind; ///< http | tcp | ws
    std::string id;
    std::string host;
    uint16_t port = 0;
    std::string pathPrefix; ///< http / ws 的路径前缀 (空 = 不限制)
    /// 只当静态文件服务用: 没命中静态路由的请求直接回 404, 不发 `http.request`
    bool staticOnly = false;
    std::shared_ptr<asio::ip::tcp::acceptor> acceptor;
    int64_t maxBody = kMaxHttpBody;
    int32_t requestTimeoutMs = 30000;
    int32_t maxConnections = 32;
    size_t pending = 0;          ///< 正在等插件回答的 HTTP 请求数
    std::set<std::string> conns; ///< 该服务下的连接 id
    std::string url;             ///< http://host:port (只对 http / ws 有意义)
    /// 静态路由 (HTTP 服务专用; 按登记顺序匹配)
    std::vector<std::shared_ptr<StaticRoute>> routes;
    /// HTTP 服务实例（kind == "http" 时由库提供服务；tcp / ws 还是自己 accept）
    std::shared_ptr<utilxx::HttpServer> http;
    /// TCP 服务实例（kind == "tcp" 时由库 accept）
    std::shared_ptr<utilxx::TcpServer> tcp;
  };

  std::map<std::string, std::shared_ptr<Server>> servers; ///< plugin|kind|id
  std::map<std::string, std::shared_ptr<Stream>> conns;   ///< plugin|id

  /// UDP 通道 (广播 / 组播 / 单播都走它; 一个通道 = 一个 socket)
  std::map<std::string, std::shared_ptr<UdpChannel>> udpChannels; ///< plugin|id

  /// 一条等插件回答的 HTTP 请求（handler 协程在这里等，`http.respond` 叫醒它）
  struct PendingResponse {
    Json payload;    ///< 插件给的响应（`answered` 为真时有效）
    bool answered = false;
    std::shared_ptr<asio::steady_timer> timer;
  };
  struct PendingHttp {
    std::string plugin;
    std::string serverKey;
    std::shared_ptr<PendingResponse> wait;
  };
  std::map<int64_t, PendingHttp> pendingHttp;

  /// 进行中的 HTTP 客户端请求
  struct HttpWait {
    std::string plugin;
    DoneFn done;
    std::shared_ptr<HttpRequestTask> client;
  };
  std::map<int64_t, HttpWait> httpWaits;

  /* ---------- 小工具 ---------- */

  static std::string serverKeyOf(const std::string &plugin,
                                 const std::string &kind,
                                 const std::string &id) {
    return plugin + "|" + kind + "|" + id;
  }
  static std::string connKeyOf(const std::string &plugin,
                               const std::string &id) {
    return plugin + "|" + id;
  }

  /// 发一条插件网络事件 (`payload` 里要带 `kind`)
  void emit(const std::string &pluginId, Json payload) {
    if (publish) {
      publish(pluginId, payload.dump());
    }
  }

  template <typename Fn> bool runSync(Fn &&fn, uint32_t waitMs = kCallWaitMs) {
    if (!running.load(std::memory_order_acquire)) {
      return false;
    }
    auto slot = std::make_shared<SyncSlot>();
    asio::post(io, [fn = std::forward<Fn>(fn), slot]() mutable {
      try {
        fn();
      } catch (const std::exception &e) {
        XX_LOGW("[utilxx] 网络线程任务异常: {}", e.what());
      }
      slot->set();
    });
    return slot->wait(waitMs);
  }

  int64_t allocateRequestId() {
    return nextRequestId.fetch_add(1, std::memory_order_relaxed);
  }

  /* ---------- 连接与服务记账 ---------- */

  size_t connectionCountOf(const std::string &plugin) const {
    size_t count = 0;
    for (const auto &item : conns) {
      if (item.second && item.second->plugin == plugin) {
        ++count;
      }
    }
    return count;
  }

  /// 登记一条连接 (超限返回 false)
  bool registerStream(const std::shared_ptr<Stream> &stream);

  /// 连接关闭后的清理 (`Stream::closeStream` 调用; 网络线程)
  void onStreamClosed(const std::shared_ptr<Stream> &stream);

  /// 取连接 (只能网络线程)
  std::shared_ptr<Stream> findConn(const std::string &plugin,
                                   const std::string &id) const;

  /// 起一个监听; 失败写 err
  bool listenServer(std::shared_ptr<Server> server, std::string &err);

  /// 起一个 HTTP 服务（交给库的 `HttpServer`，不自建 accept 循环）
  bool listenHttpServer(const std::shared_ptr<Server> &server,
                        std::string &err);

  /// 起一个 TCP 服务（交给库的 `TcpServer`）
  bool listenTcpServer(const std::shared_ptr<Server> &server, std::string &err);

  /// 接受一条 TCP 连接（库的 `TcpServer` 的 handler 进来的地方）
  asio::awaitable<void> onTcpAccepted(const std::shared_ptr<Server> &server,
                                      std::shared_ptr<utilxx::TcpConnection> conn);

  /// 一条 HTTP 请求的兑底处理：静态内存路由 -> 插件回答 -> 504
  asio::awaitable<void> handleHttpRequest(
      const std::shared_ptr<Server> &server,
      utilxx::HttpServer::Request &req,
      utilxx::HttpServer::Response &resp,
      std::string_view path, std::string_view peer);

  /// 把静态路由同步给库的服务（文件走 `enableFileRoute`，内存内容在兑底里比对）
  void rebuildHttpFileRoutes(const Server &server);

  void acceptNext(const std::shared_ptr<Server> &server);

  /// 接受一条连接并创建对应的 Stream 实现
  void onAccepted(const std::shared_ptr<Server> &server,
                  asio::ip::tcp::socket socket);

  /// 关掉某个插件的全部服务与连接 (网络线程; 卸载 / 停机)
  ///
  /// `cancelled` 非空时收走未完成 HTTP 客户端请求的完成回调 —— 它们要靠调用方
  /// 在插件框架线程上按"已取消"结算 (网络线程不能执行插件代码)。
  void closeAllOf(const std::string &plugin, bool allPlugins,
                  std::vector<DoneFn> *cancelled = nullptr);

  /* ---------- HTTP 静态内容 (文件 / 内存) ---------- */

  /// 按参数造一条静态路由 (path / token / 文件名 / 大小都在这里定好); 失败写 err
  bool buildStaticRoute(const Server &server, const Json &args,
                        const std::shared_ptr<Server::StaticRoute> &route,
                        std::string &err);

  /// 登记一条静态路由 (同一份文件 / 同一段内容重复登记复用已有条目)
  bool addStaticRoute(const std::shared_ptr<Server> &server, const Json &args,
                      Json &out);

  /// 找一条静态路由 (路径精确匹配)
  std::shared_ptr<Server::StaticRoute>
  findStaticRoute(const Server &server, const std::string &path) const;

  /// 删掉一条静态路由 (按路径)
  bool removeStaticRoute(const std::shared_ptr<Server> &server,
                         const std::string &path);

  /// 起 / 停网络线程 (幂等)
  void startThread();
  void stopThread();

  /* ---------- HTTP 服务端 (等插件回答的请求) ---------- */

  /// 登记一个等待回答的请求; 超出上限返回 0
  int64_t registerPendingHttp(const std::shared_ptr<Server> &server,
                              const std::shared_ptr<PendingResponse> &wait);
  std::shared_ptr<PendingResponse> takePendingHttp(int64_t requestId,
                                                   std::string *plugin);
  void dropPendingHttp(int64_t requestId);
  /// 叫醒某个服务下所有等回答的请求（服务停了 / 插件卸载了）
  void wakePendingOfServer(const std::string &serverKey);

  /* ---------- HTTP 客户端 ---------- */

  /// 开始一个 HTTP 请求 (网络线程); 失败时 out 写错误对象并返回 false
  ///
  /// `mode`: 0 = http.request / 1 = http.fetch / 2 = http.download
  bool startHttpRequest(const std::string &plugin, int64_t requestId,
                        const Json &args, DoneFn done, Json &out,
                        int32_t mode = 0);

  /// 完成一个 HTTP 客户端请求 (成功与失败都走这里)
  void finishHttpRequest(int64_t requestId, bool ok, Json payload);

  void cancelHttpRequest(const std::string &plugin, int64_t requestId,
                         Json &out);

  /* ---------- 服务与连接操作 (网络线程) ---------- */

  int32_t handleCall(const std::string &plugin, const std::string &op,
                     const Json &args, Json &out);

  void stopServers(const std::string &plugin, const std::string &kind,
                   const std::string &id, Json &out);
  void closeConn(const std::string &plugin, const std::string &id, Json &out);
  void sendConn(const std::string &plugin, const Json &args, Json &out);
  std::string infoJsonOnThread(const std::string &plugin, bool allPlugins);

  /* ---------- UDP 通道 (网络线程) ---------- */

  /// `udp.open`: 建通道并开始收包（失败写 out 并返回 false）
  bool openUdp(const std::string &plugin, const Json &args, Json &out);

  /// `udp.send`: 发一个包给目标地址（可以发给广播地址 / 组播组）
  void sendUdp(const std::string &plugin, const Json &args, Json &out);

  /// `udp.join` / `udp.leave`: 加入 / 退出组播组
  bool groupUdp(const std::string &plugin, const Json &args, bool join,
                Json &out);

  /// `udp.close`: 关一个通道
  void closeUdp(const std::string &plugin, const std::string &id, Json &out);

  /// 关掉某个插件的全部 UDP 通道（卸载 / 停机；网络线程）
  void closeUdpOf(const std::string &plugin, bool allPlugins);

  /// 关掉一个通道并发 `udp.closed` 事件
  void shutdownUdp(const std::shared_ptr<UdpChannel> &channel,
                   const char *reason);

  /// `udp` 自省数据（`net.info` 用）
  Json udpInfoJson(const std::string &plugin, bool allPlugins) const;

  /// 一个服务的静态路由清单 (`http.serve` / `http.route` / info 共用同一份)
  Json staticRoutesJson(const Server &server) const;

  /// 服务的对地址去掉路径前缀 (`server.url` 里已经带了前缀, 路由的 path 里也带了)
  std::string staticBaseUrl(const Server &server) const;

  /// 当前是否在监听这个地址 (服务端存在且监听中)
  std::shared_ptr<Server> findServer(const std::string &plugin,
                                     const std::string &kind,
                                     const std::string &id) const;

  std::string nextServerId(const std::string &plugin,
                           const std::string &kind) const;
  std::string nextConnId(const std::string &plugin,
                         const std::string &prefix) const;
};

namespace {

/// endpoint → `1.2.3.4:5678`
std::string endpointText(const asio::ip::tcp::endpoint &endpoint) {
  return endpoint.address().to_string() + ":" + std::to_string(endpoint.port());
}

/// 连接 / 服务 id: 只允许字母数字与 . _ - (拼进事件与 info 里不会串味)
bool isValidId(std::string_view id) {
  if (id.empty() || id.size() > 64) {
    return false;
  }
  for (const char c : id) {
    const bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                    (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-';
    if (!ok) {
      return false;
    }
  }
  return true;
}

/// 取服务器绑定地址 (缺省只监听回环)
bool resolveBindHost(std::string &host, std::string &err) {
  if (host.empty()) {
    host = "127.0.0.1";
  }
  if (host == "localhost") {
    host = "127.0.0.1";
  }
  AsioErrorCode ec;
  (void)asio::ip::make_address(host, ec);
  if (ec) {
    err = "监听地址不是合法的 IP: " + host;
    return false;
  }
  return true;
}

} // namespace

/* ==================== Stream ==================== */

Stream::Stream(std::shared_ptr<PluginNetHub::Impl> hubRef,
               asio::ip::tcp::socket socketRef)
    : hub(std::move(hubRef)) {
  // 已连上的 socket 才有对端/本地地址 (客户端连接建立前是空的, 连上后再取一次)
  if (socketRef.is_open()) {
    AsioErrorCode ec;
    const auto remoteEndpoint = socketRef.remote_endpoint(ec);
    if (!ec) {
      remote = endpointText(remoteEndpoint);
    }
    const auto localEndpoint = socketRef.local_endpoint(ec);
    if (!ec) {
      local = endpointText(localEndpoint);
    }
  }
  io = std::make_shared<NetStream>(std::move(socketRef));
}

Stream::Stream(std::shared_ptr<PluginNetHub::Impl> hubRef,
               std::shared_ptr<utilxx::TcpConnection> connection)
    : hub(std::move(hubRef)), tcpConn(std::move(connection)) {
  // 库的连接已经建好, 对端 / 本地地址直接问它
  if (tcpConn) {
    remote = tcpConn->peerAddress();
    local = tcpConn->localAddress();
  }
}

void Stream::start() {
  readBuf.resize(kReadChunk);
  startRead();
}

asio::awaitable<void> Stream::waitClosed() {
  if (closing) {
    co_return;
  }
  closedTimer = std::make_shared<asio::steady_timer>(hub->io);
  // 一个远期的到期点: 关掉连接时取消它, 等的人就醒
  closedTimer->expires_after(std::chrono::hours{24 * 365});
  AsioErrorCode ec;
  co_await closedTimer->async_wait(asio::redirect_error(asio::use_awaitable, ec));
}

void Stream::startRead() {
  if (closing || paused || reading) {
    return;
  }
  reading = true;
  auto self = shared_from_this();
  if (tcpConn) {
    // 库的连接: 一次一条 recv 协程, 收完再排下一条（与暂停 / 关闭一致）
    asio::co_spawn(
        hub->io.get_executor(),
        [self]() -> asio::awaitable<void> {
          auto got = co_await self->tcpConn->recv();
          self->reading = false;
          if (self->closing) {
            co_return;
          }
          if (!got) {
            self->closeStream("error", got.error());
            co_return;
          }
          if (got->eof) {
            self->closeStream("remote_closed", {});
            co_return;
          }
          if (!got->data.empty()) {
            self->onBytes(got->data.data(), got->data.size());
          }
          if (!self->closing) {
            self->startRead();
          }
        },
        asio::detached
    );
    return;
  }
  io->async_read_some(
      asio::buffer(readBuf), [self](AsioErrorCode ec, size_t size) {
        self->reading = false;
        if (self->closing) {
          return;
        }
        if (ec) {
          const bool eof = NetStream::isPeerClosed(ec);
          self->closeStream(eof ? "remote_closed" : "error", errorTextOf(ec));
          return;
        }
        if (size > 0) {
          self->onBytes(self->readBuf.data(), size);
        }
        if (!self->closing) {
          self->startRead();
        }
      });
}

/// 暂停 / 恢复读 (网络线程调用; 暂停只影响 data 事件, 已收的字节照旧发出)
void Stream::setPaused(bool value) {
  paused = value;
  if (!paused) {
    startRead();
  }
}

void Stream::send(std::string data, std::string &err) {
  if (closing || closeWhenFlushed) {
    err = "closed";
    return;
  }
  if (outBytes + data.size() > kMaxOutQueue) {
    err = "queue_full";
    return;
  }
  outBytes += data.size();
  outQueue.push_back(std::move(data));
  startWrite();
}

void Stream::startWrite() {
  if (writing) {
    return;
  }
  if (outQueue.empty()) {
    if (closeWhenFlushed) {
      closeStream("local_close", {});
    }
    return;
  }
  writing = true;
  auto self = shared_from_this();
  if (tcpConn) {
    std::string chunk = std::move(outQueue.front());
    outQueue.pop_front();
    asio::co_spawn(
        hub->io.get_executor(),
        [self, chunk = std::move(chunk)]() -> asio::awaitable<void> {
          auto sent = co_await self->tcpConn->send(chunk);
          self->writing = false;
          self->outBytes -= chunk.size();
          if (self->closing) {
            co_return;
          }
          if (!sent) {
            self->closeStream("error", sent.error());
            co_return;
          }
          self->onWritten();
          if (!self->closing) {
            self->startWrite();
          }
        },
        asio::detached
    );
    return;
  }
  asio::async_write(*io, asio::buffer(outQueue.front()),
                    [self](AsioErrorCode ec, size_t) { self->afterWrite(ec); });
}

void Stream::afterWrite(AsioErrorCode ec) {
  writing = false;
  if (closing) {
    return;
  }
  if (ec) {
    closeStream("error", errorTextOf(ec));
    return;
  }
  if (!outQueue.empty()) {
    outBytes -= outQueue.front().size();
    outQueue.pop_front();
  }
  onWritten();
  if (closing) {
    return;
  }
  startWrite();
}

void Stream::flushThenClose() {
  closeWhenFlushed = true;
  if (!writing && outQueue.empty()) {
    closeStream("local_close", {});
  }
}

void Stream::closeStream(std::string_view reason, std::string_view error) {
  if (closing) {
    return;
  }
  closing = true;
  if (tcpConn) {
    tcpConn->abort();
  } else if (io) {
    io->close();
  }
  if (closedTimer) {
    closedTimer->cancel();
  }
  onClosed(reason, error);
  if (hub) {
    hub->onStreamClosed(shared_from_this());
  }
}

/* ==================== 记账 ==================== */

std::shared_ptr<Stream>
PluginNetHub::Impl::findConn(const std::string &plugin,
                             const std::string &id) const {
  const auto it = conns.find(connKeyOf(plugin, id));
  return it == conns.end() ? nullptr : it->second;
}

bool PluginNetHub::Impl::registerStream(const std::shared_ptr<Stream> &stream) {
  if (!stream) {
    return false;
  }
  if (connectionCountOf(stream->plugin) >= kMaxConnectionsPerPlugin) {
    return false;
  }
  conns[connKeyOf(stream->plugin, stream->id)] = stream;
  if (!stream->serverId.empty()) {
    const auto server = findServer(stream->plugin, stream->kind(), stream->serverId);
    if (server) {
      server->conns.insert(stream->id);
    }
  }
  return true;
}

void PluginNetHub::Impl::onStreamClosed(const std::shared_ptr<Stream> &stream) {
  if (!stream) {
    return;
  }
  const auto it = conns.find(connKeyOf(stream->plugin, stream->id));
  if (it != conns.end() && it->second == stream) {
    conns.erase(it);
  }
  if (!stream->serverId.empty()) {
    const auto server = findServer(stream->plugin, stream->kind(), stream->serverId);
    if (server) {
      server->conns.erase(stream->id);
    }
  }
}

std::shared_ptr<PluginNetHub::Impl::Server>
PluginNetHub::Impl::findServer(const std::string &plugin,
                               const std::string &kind,
                               const std::string &id) const {
  const auto it = servers.find(serverKeyOf(plugin, kind, id));
  return it == servers.end() ? nullptr : it->second;
}

std::string PluginNetHub::Impl::nextServerId(const std::string &plugin,
                                             const std::string &kind) const {
  for (int i = 1; i < 10000; ++i) {
    const std::string candidate = kind + std::to_string(i);
    if (!findServer(plugin, kind, candidate)) {
      return candidate;
    }
  }
  return kind + "_x";
}

std::string PluginNetHub::Impl::nextConnId(const std::string &plugin,
                                           const std::string &prefix) const {
  for (int i = 1; i < 100000; ++i) {
    const std::string candidate = prefix + std::to_string(i);
    if (!findConn(plugin, candidate)) {
      return candidate;
    }
  }
  return prefix + "_x";
}

/* ==================== 监听与接受 ==================== */

bool PluginNetHub::Impl::listenServer(std::shared_ptr<Server> server,
                                      std::string &err) {
  int32_t sameKind = 0;
  for (const auto &item : servers) {
    if (item.second && item.second->plugin == server->plugin &&
        item.second->kind == server->kind) {
      ++sameKind;
    }
  }
  if (sameKind >= kMaxServersPerKind) {
    err = "同类服务已达上限";
    return false;
  }
  if (!resolveBindHost(server->host, err)) {
    return false;
  }
  if (server->kind == "http") {
    // HTTP 服务交给库（它有 accept 循环、路由、静态文件与保活）
    return listenHttpServer(server, err);
  }
  if (server->kind == "tcp") {
    // TCP 服务交给库（accept 与连接上限在库那边）
    return listenTcpServer(server, err);
  }
  try {
    asio::ip::tcp::endpoint endpoint{
        asio::ip::make_address(server->host), server->port};
    auto acceptor = std::make_shared<asio::ip::tcp::acceptor>(io);
    acceptor->open(endpoint.protocol());
    acceptor->set_option(asio::ip::tcp::acceptor::reuse_address(true));
    acceptor->bind(endpoint);
    acceptor->listen(asio::socket_base::max_listen_connections);
    server->port = acceptor->local_endpoint().port();
    server->acceptor = acceptor;
    if (server->kind == "http" || server->kind == "ws") {
      server->url = (server->kind == "http" ? "http://" : "ws://") +
                    server->host + ":" + std::to_string(server->port) +
                    server->pathPrefix;
    }
    servers[serverKeyOf(server->plugin, server->kind, server->id)] = server;
    acceptNext(server);
    return true;
  } catch (const std::exception &e) {
    err = osTextToUtf8(e.what());
    return false;
  }
}

void PluginNetHub::Impl::acceptNext(const std::shared_ptr<Server> &server) {
  if (!server || !server->acceptor || !running.load(std::memory_order_acquire)) {
    return;
  }
  if (!server->acceptor->is_open()) {
    return; ///< 服务已关: 不再接受 (关监听后会回来一次 operation_aborted)
  }
  auto socket = std::make_shared<asio::ip::tcp::socket>(io);
  auto self = shared_from_this();
  server->acceptor->async_accept(*socket,
                                 [self, server, socket](AsioErrorCode ec) {
    if (!ec && socket->is_open()) {
      self->onAccepted(server, std::move(*socket));
    }
    self->acceptNext(server);
  });
}

/* ==================== HTTP 静态内容 (文件 / 内存) ==================== */

namespace {

/// 文件修改时间 → 毫秒时间戳 (只用于去重与展示)
int64_t mtimeMsOf(std::filesystem::file_time_type time) {
  using namespace std::chrono;
  const auto systemTime = time_point_cast<milliseconds>(
      time - std::filesystem::file_time_type::clock::now() +
      system_clock::now());
  return static_cast<int64_t>(systemTime.time_since_epoch().count());
}

/// UTF-8 路径 → `std::filesystem::path` (Windows 上按 UTF-8 → 原生宽字符)
std::filesystem::path pathFromUtf8(const std::string &text) {
  std::u8string u8(reinterpret_cast<const char8_t *>(text.data()), text.size());
  return std::filesystem::path(u8);
}

} // namespace

bool PluginNetHub::Impl::buildStaticRoute(
    const Server &server, const Json &args,
    const std::shared_ptr<Server::StaticRoute> &route, std::string &err) {
  const std::string path{trimAscii(args.value("path", std::string{}))};
  const std::string file{trimAscii(args.value("file", std::string{}))};
  const std::string fileNameArg{
      trimAscii(args.value("fileName", std::string{}))};
  const std::string contentTypeArg{
      trimAscii(args.value("contentType", std::string{}))};

  std::string bytes;
  const bool hasBytes = args.contains("bytes") || args.contains("bytesBase64");
  const std::string base64 = args.value("bytesBase64", std::string{});
  if (!base64.empty()) {
    const auto decoded = utilxx_base::base64Decode(base64);
    if (!decoded.has_value()) {
      err = "bytesBase64 解不开";
      return false;
    }
    bytes = *decoded;
  } else if (args.contains("bytes")) {
    const Json &value = args["bytes"];
    if (!value.is_string()) {
      err = "bytes 必须是字符串";
      return false;
    }
    bytes = value.get<std::string>();
  }
  if (file.empty() && !hasBytes) {
    err = "静态内容要给 file, 或 bytes / bytesBase64";
    return false;
  }
  if (!file.empty() && hasBytes) {
    err = "file 与 bytes 只能二选一";
    return false;
  }

  if (!file.empty()) {
    std::error_code sizeEc;
    const auto fsPath = pathFromUtf8(file);
    if (!std::filesystem::is_regular_file(fsPath, sizeEc)) {
      err = "文件不存在或不是普通文件: " + file;
      return false;
    }
    const auto size = std::filesystem::file_size(fsPath, sizeEc);
    if (sizeEc) {
      err = "读不到文件大小: " + file;
      return false;
    }
    std::error_code timeEc;
    route->file = file;
    route->size = static_cast<int64_t>(size);
    route->mtimeMs = mtimeMsOf(std::filesystem::last_write_time(fsPath, timeEc));
    route->fileName = fileNameArg.empty() ? fileNameOfPath(file) : fileNameArg;
  } else {
    if (static_cast<int64_t>(bytes.size()) > kMaxStaticBytes) {
      err = "内容过大 (上限 8 MiB), 大内容请先落盘再用 file";
      return false;
    }
    route->bytes = std::move(bytes);
    route->size = static_cast<int64_t>(route->bytes.size());
    route->fileName = fileNameArg.empty() ? "content.bin" : fileNameArg;
  }

  if (path.empty()) {
    // 没给路径就自己生成一个带随机 token 的: 猜不到的 URL, 也不做路径解析
    // (服务的路径前缀要带上: 请求路径里是带着前缀来的, 匹配也是按完整路径比)
    route->path = server.pathPrefix + "/f/" + randomTokenHex() + "/" +
                  urlEncodePathSegment(sanitizeStaticFileName(route->fileName));
  } else {
    if (path.front() != '/') {
      err = "path 必须以 / 开头";
      return false;
    }
    if (path.size() > 512) {
      err = "path 过长";
      return false;
    }
    if (path.find("..") != std::string::npos) {
      err = "path 里不能有 ..";
      return false;
    }
    if (!server.pathPrefix.empty() && !startsWith(path, server.pathPrefix)) {
      err = "path 不在服务的路径前缀 " + server.pathPrefix + " 下";
      return false;
    }
    route->path = path;
  }

  route->contentType = contentTypeArg.empty()
                           ? contentTypeOfName(route->fileName)
                           : contentTypeArg;
  if (route->contentType.empty()) {
    route->contentType = "application/octet-stream";
  }
  return true;
}

bool PluginNetHub::Impl::addStaticRoute(const std::shared_ptr<Server> &server,
                                        const Json &args, Json &out) {
  if (!server) {
    out = errorJson("not_found", "服务不存在");
    return false;
  }
  if (server->routes.size() >= kMaxStaticRoutes) {
    out = errorJson("too_many", "静态路由已达上限 (" +
                                   std::to_string(kMaxStaticRoutes) + " 条)");
    return false;
  }
  auto route = std::make_shared<Server::StaticRoute>();
  std::string err;
  if (!buildStaticRoute(*server, args, route, err)) {
    out = errorJson("bad_args", err);
    return false;
  }
  const std::string wantedPath{trimAscii(args.value("path", std::string{}))};
  bool reused = false;
  for (const auto &existing : server->routes) {
    if (!existing) {
      continue;
    }
    const bool sameSource =
        route->file.empty()
            ? (existing->file.empty() && existing->bytes == route->bytes)
            : (existing->file == route->file && existing->size == route->size &&
               existing->mtimeMs == route->mtimeMs);
    if (!sameSource) {
      continue;
    }
    // 明确给了一个不同的 path = 想要另一个入口, 不复用
    if (!wantedPath.empty() && existing->path != route->path) {
      continue;
    }
    route = existing;
    reused = true;
    break;
  }
  if (!reused) {
    server->routes.push_back(route);
  }
  // 库那边的文件路由表要跟着改（内存内容由兑底处理器按路由表现查，不用动）
  rebuildHttpFileRoutes(*server);

  out = Json::object();
  out["ok"] = true;
  out["serverId"] = server->id;
  out["path"] = route->path;
  out["url"] = staticBaseUrl(*server) + route->path;
  out["size"] = route->size;
  out["mtimeMs"] = route->mtimeMs;
  out["contentType"] = route->contentType;
  out["fileName"] = route->fileName;
  out["reused"] = reused;
  out["routes"] = staticRoutesJson(*server);
  out["routeCount"] = static_cast<int64_t>(server->routes.size());
  return true;
}

std::shared_ptr<PluginNetHub::Impl::Server::StaticRoute>
PluginNetHub::Impl::findStaticRoute(const Server &server,
                                    const std::string &path) const {
  for (const auto &route : server.routes) {
    if (route && route->path == path) {
      return route;
    }
  }
  return nullptr;
}

bool PluginNetHub::Impl::removeStaticRoute(const std::shared_ptr<Server> &server,
                                           const std::string &path) {
  if (!server) {
    return false;
  }
  for (auto it = server->routes.begin(); it != server->routes.end(); ++it) {
    if (*it && (*it)->path == path) {
      server->routes.erase(it);
      rebuildHttpFileRoutes(*server);
      return true;
    }
  }
  return false;
}
/* ==================== HTTP 服务端（交给库的 HttpServer） ==================== */

namespace {

/// 回一条固定文本的小响应（内部错误 / 404 / 503 / 504 用）
void setSimpleHttpResponse(utilxx::HttpServer::Request &req,
                           utilxx::HttpServer::Response &resp,
                           boost::beast::http::status status,
                           std::string_view text) {
  namespace http = boost::beast::http;
  resp.version(req.version());
  resp.result(status);
  resp.set(http::field::content_type, "text/plain; charset=utf-8");
  resp.body().assign(std::string{text} + "\n");
  resp.keep_alive(req.keep_alive());
}

/// 把插件给的响应（status / headers / body|bodyBase64 / contentType）填进响应
void fillHttpResponse(utilxx::HttpServer::Request &req,
                      utilxx::HttpServer::Response &resp,
                      const Json &payload) {
  namespace http = boost::beast::http;
  int status = 200;
  if (payload.is_object() && payload.contains("status")) {
    const Json &value = payload["status"];
    if (value.is_number_integer()) {
      status = static_cast<int>(value.get<int64_t>());
    }
  }
  if (status < 100 || status > 599) {
    status = 500;
  }
  std::string body;
  bool fromBase64 = false;
  if (payload.is_object()) {
    const std::string base64 = payload.value("bodyBase64", std::string{});
    if (!base64.empty()) {
      const auto decoded = utilxx_base::base64Decode(base64);
      if (decoded.has_value()) {
        body = *decoded;
        fromBase64 = true;
      }
    }
    if (!fromBase64) {
      body = payload.value("body", std::string{});
      if (body.empty()) {
        body = payload.value("text", std::string{});
      }
    }
  }
  if (status == 204 || status == 304) {
    body.clear();
  }
  resp.version(req.version());
  resp.result(status);
  bool hasContentType = false;
  if (payload.is_object() && payload["headers"].is_object()) {
    for (const auto &item : payload["headers"].items()) {
      const std::string name{item.first};
      if (iequals(name, "content-type")) {
        hasContentType = true;
      }
      resp.set(name, toSafeText(jsonTextOf(item.second)));
    }
  }
  if (!hasContentType) {
    resp.set(http::field::content_type,
             payload.is_object()
                 ? payload.value("contentType",
                                 std::string{"application/octet-stream"})
                 : std::string{"application/octet-stream"});
  }
  resp.body() = std::move(body);
  resp.keep_alive(req.keep_alive());
}

/// 回一条静态内存路由（200 / 206 / 416）；文件内容的静态路由由库直接发
void setStaticContentResponse(
    utilxx::HttpServer::Request &req, utilxx::HttpServer::Response &resp,
    const PluginNetHub::Impl::Server::StaticRoute &route) {
  namespace http = boost::beast::http;
  const int64_t size = route.size;
  const auto rangeField = req[http::field::range];
  const ByteRange range = parseRangeHeader(
      std::string{rangeField.data(), rangeField.size()}, size);
  if (range.present && !range.satisfiable) {
    resp.version(req.version());
    resp.result(http::status::range_not_satisfiable);
    resp.set(http::field::content_range, "bytes */" + std::to_string(size));
    resp.body().clear();
    resp.keep_alive(req.keep_alive());
    return;
  }
  const bool partial = range.present && size > 0;
  const int64_t start = partial ? range.start : 0;
  const int64_t length =
      size <= 0 ? 0 : (partial ? range.end - range.start + 1 : size);
  resp.version(req.version());
  resp.result(partial ? http::status::partial_content : http::status::ok);
  resp.set(http::field::content_type, route.contentType.empty()
                                          ? "application/octet-stream"
                                          : route.contentType);
  resp.set(http::field::accept_ranges, "bytes");
  resp.set(http::field::cache_control, "no-store");
  if (partial) {
    resp.set(http::field::content_range,
             "bytes " + std::to_string(start) + "-" +
                 std::to_string(start + length - 1) + "/" + std::to_string(size));
  }
  resp.body() = route.bytes.substr(static_cast<size_t>(start),
                                   static_cast<size_t>(length));
  resp.keep_alive(req.keep_alive());
}

/// 版本号 → 事件里的版本串
std::string httpVersionText(unsigned version) {
  if (version == 11) {
    return "HTTP/1.1";
  }
  if (version == 10) {
    return "HTTP/1.0";
  }
  return "HTTP/1." + std::to_string(version % 10);
}

} // namespace

bool PluginNetHub::Impl::listenHttpServer(const std::shared_ptr<Server> &server,
                                          std::string &err) {
  utilxx::HttpServer::Config config;
  config.address = server->host;
  config.port = server->port;
  config.requestTimeout = std::chrono::seconds{
      (std::max)(int64_t{1}, static_cast<int64_t>((server->requestTimeoutMs + 999) / 1000))};
  config.maxConnections =
      static_cast<size_t>((std::max)(int32_t{1}, server->maxConnections));
  // 请求体上限跟着插件给的 maxBodyBytes 走（库超出会自己回 413）
  config.maxRequestBody =
      static_cast<uint64_t>((std::max)(int64_t{0}, server->maxBody));
  // 插件服务不打访问日志: 网络事件里已经能看出谁请求了什么
  config.accessLogEnabled = false;
  auto http = std::make_shared<utilxx::HttpServer>(config);
  auto self = shared_from_this();
  http->setFallbackHandler(
      [self, server](utilxx::HttpServer::Request &req,
                     utilxx::HttpServer::Response &resp, std::string_view path,
                     std::string_view peer) -> asio::awaitable<void> {
        co_await self->handleHttpRequest(server, req, resp, path, peer);
      });
  try {
    http->startAsync(io.get_executor());
  } catch (const std::exception &e) {
    err = osTextToUtf8(e.what());
    return false;
  }
  server->http = http;
  server->port = http->port();
  server->url = "http://" + server->host + ":" +
                std::to_string(server->port) + server->pathPrefix;
  servers[serverKeyOf(server->plugin, server->kind, server->id)] = server;
  rebuildHttpFileRoutes(*server);
  return true;
}

void PluginNetHub::Impl::rebuildHttpFileRoutes(const Server &server) {
  if (!server.http) {
    return;
  }
  // 库按路径表精确匹配文件路由；改过静态路由就整表重发一遍（最多 1024 条，很便宜）
  server.http->clearFileRoutes();
  for (const auto &route : server.routes) {
    if (route && !route->file.empty()) {
      server.http->enableFileRoute(route->path, route->file, route->contentType);
    }
  }
}

bool PluginNetHub::Impl::listenTcpServer(const std::shared_ptr<Server> &server,
                                         std::string &err) {
  utilxx::TcpServer::Config config;
  config.address = server->host;
  config.port = server->port;
  config.maxConnections =
      static_cast<size_t>((std::max)(int32_t{1}, server->maxConnections));
  config.connection.connectTimeout = std::chrono::seconds{10};
  // 长连接: 不设单次读写期限（空闲多久都不算错）
  config.connection.ioTimeout = std::chrono::milliseconds{0};
  auto self = shared_from_this();
  auto tcpServer = std::make_shared<utilxx::TcpServer>(
      config,
      [self, server](std::shared_ptr<utilxx::TcpConnection> conn)
          -> asio::awaitable<void> {
        co_await self->onTcpAccepted(server, std::move(conn));
      });
  auto started = tcpServer->startAsync(io.get_executor());
  if (!started) {
    err = started.error();
    return false;
  }
  server->tcp = tcpServer;
  server->port = tcpServer->port();
  servers[serverKeyOf(server->plugin, server->kind, server->id)] = server;
  return true;
}

asio::awaitable<void> PluginNetHub::Impl::handleHttpRequest(
    const std::shared_ptr<Server> &server, utilxx::HttpServer::Request &req,
    utilxx::HttpServer::Response &resp, std::string_view path,
    std::string_view peer) {
  auto self = shared_from_this();
  namespace http = boost::beast::http;
  const std::string fullPath{path};

  // 服务带路径前缀时，前缀之外的请求直接 404（与旧实现一致）
  if (!server->pathPrefix.empty() && !startsWith(fullPath, server->pathPrefix)) {
    setSimpleHttpResponse(req, resp, http::status::not_found, "not found");
    co_return;
  }

  // 静态路由（内存内容）：命中后由框架直接回，不发 http.request 事件
  if (req.method() == http::verb::get || req.method() == http::verb::head) {
    if (auto route = findStaticRoute(*server, fullPath)) {
      setStaticContentResponse(req, resp, *route);
      co_return;
    }
  }
  if (server->staticOnly) {
    // 这个服务就是拿来发静态内容的：没命中就 404，不去等插件回答
    setSimpleHttpResponse(req, resp, http::status::not_found, "没有这条静态路由");
    co_return;
  }

  auto wait = std::make_shared<PendingResponse>();
  const int64_t requestId = registerPendingHttp(server, wait);
  if (requestId == 0) {
    setSimpleHttpResponse(req, resp, http::status::service_unavailable,
                          "等待回答的请求过多");
    co_return;
  }
  wait->timer = std::make_shared<asio::steady_timer>(io);
  wait->timer->expires_after(std::chrono::milliseconds{
      (std::max)(int64_t{1000}, static_cast<int64_t>(server->requestTimeoutMs))});

  const std::string target{req.target()};
  std::string targetPath;
  std::string targetQuery;
  splitTarget(target, targetPath, targetQuery);
  const std::string &body = req.body();

  Json event;
  event["kind"] = "http.request";
  event["serverId"] = server->id;
  event["requestId"] = requestId;
  event["method"] = toSafeText(req.method_string());
  event["path"] = toSafeText(fullPath);
  event["query"] = toSafeText(targetQuery);
  event["target"] = toSafeText(target);
  event["version"] = httpVersionText(req.version());
  {
    Json headers = Json::object();
    for (const auto &field : req) {
      const std::string key = lowerAscii(toSafeText(field.name_string()));
      const std::string value = toSafeText(field.value());
      if (headers.contains(key)) {
        // 重复头（Cookie 等）用换行拼起来，与旧实现一致
        const std::string previous = headers.value(key, std::string{});
        headers[key] = previous + "\n" + value;
      } else {
        headers[key] = value;
      }
    }
    event["headers"] = std::move(headers);
  }
  event["remote"] = toSafeText(peer);
  event["bodyBytes"] = static_cast<int64_t>(body.size());
  event["bodyBase64"] = utilxx_base::base64Encode(body);
  if (isValidUtf8(body)) {
    event["body"] = toSafeText(body);
    event["text"] = toSafeText(body);
  }
  emit(server->plugin, std::move(event));

  AsioErrorCode ec;
  co_await wait->timer->async_wait(
      asio::redirect_error(asio::use_awaitable, ec));
  dropPendingHttp(requestId);
  if (!wait->answered) {
    setSimpleHttpResponse(req, resp, http::status::gateway_timeout,
                          "插件没有在时限内回答请求");
    co_return;
  }
  fillHttpResponse(req, resp, wait->payload);
}

/* ==================== HTTP 服务端 (等插件回答) ==================== */

int64_t PluginNetHub::Impl::registerPendingHttp(
    const std::shared_ptr<Server> &server,
    const std::shared_ptr<PendingResponse> &wait) {
  if (!server || !wait) {
    return 0;
  }
  if (server->pending >= kMaxHttpPendingPerServer) {
    return 0;
  }
  const int64_t requestId = allocateRequestId();
  PendingHttp pending;
  pending.plugin = server->plugin;
  pending.serverKey = serverKeyOf(server->plugin, server->kind, server->id);
  pending.wait = wait;
  pendingHttp[requestId] = std::move(pending);
  ++server->pending;
  return requestId;
}

std::shared_ptr<PluginNetHub::Impl::PendingResponse>
PluginNetHub::Impl::takePendingHttp(int64_t requestId, std::string *plugin) {
  const auto it = pendingHttp.find(requestId);
  if (it == pendingHttp.end()) {
    return nullptr;
  }
  if (plugin) {
    *plugin = it->second.plugin;
  }
  const auto serverIt = servers.find(it->second.serverKey);
  if (serverIt != servers.end() && serverIt->second &&
      serverIt->second->pending > 0) {
    --serverIt->second->pending;
  }
  auto wait = it->second.wait;
  pendingHttp.erase(it);
  return wait;
}

void PluginNetHub::Impl::dropPendingHttp(int64_t requestId) {
  std::string plugin;
  (void)takePendingHttp(requestId, &plugin);
}

void PluginNetHub::Impl::wakePendingOfServer(const std::string &serverKey) {
  for (auto it = pendingHttp.begin(); it != pendingHttp.end();) {
    if (it->second.serverKey != serverKey) {
      ++it;
      continue;
    }
    // 服务停了：让还在等的 handler 回 504 收尾（不算"插件回答过"）
    if (it->second.wait && it->second.wait->timer) {
      it->second.wait->timer->cancel();
    }
    it = pendingHttp.erase(it);
  }
}

/* ==================== 关停某一插件的全部网络资源 ==================== */

void PluginNetHub::Impl::closeAllOf(const std::string &plugin, bool allPlugins,
                                  std::vector<DoneFn> *cancelled) {
  // 1) 服务: 关监听 (之后不再接受新连接)
  for (auto it = servers.begin(); it != servers.end();) {
    if (!it->second ||
        (allPlugins ? true : it->second->plugin == plugin)) {
      if (it->second->http) {
        // 库的服务: 关监听并叫醒还在等回答的请求（handler 会回 504）
        it->second->http->stop();
        wakePendingOfServer(
            serverKeyOf(it->second->plugin, it->second->kind, it->second->id));
      }
      if (it->second->tcp) {
        it->second->tcp->stop();
      }
      if (it->second->acceptor) {
        AsioErrorCode ignored;
        it->second->acceptor->close(ignored);
      }
      it = servers.erase(it);
    } else {
      ++it;
    }
  }
  // 2) 连接: 关 socket (closeStream 会走 onClosed → 事件)
  std::vector<std::shared_ptr<Stream>> closing;
  for (const auto &item : conns) {
    if (!item.second) {
      continue;
    }
    if (allPlugins || item.second->plugin == plugin) {
      closing.push_back(item.second);
    }
  }
  for (const auto &stream : closing) {
    stream->closeStream("plugin_unloaded", {});
  }
  // 3) UDP 通道: 关 socket (发 udp.closed 事件)
  closeUdpOf(plugin, allPlugins);
  // 4) 未回答的 HTTP 请求与未完成的客户端请求
  for (auto it = pendingHttp.begin(); it != pendingHttp.end();) {
    if (allPlugins || it->second.plugin == plugin) {
      if (it->second.wait && it->second.wait->timer) {
        it->second.wait->timer->cancel();
      }
      it = pendingHttp.erase(it);
    } else {
      ++it;
    }
  }
  std::vector<std::pair<int64_t, std::string>> waits;
  for (auto it = httpWaits.begin(); it != httpWaits.end();) {
    if (allPlugins || it->second.plugin == plugin) {
      waits.emplace_back(it->first, it->second.plugin);
      if (cancelled && it->second.done) {
        cancelled->push_back(std::move(it->second.done));
      }
      it = httpWaits.erase(it);
    } else {
      ++it;
    }
  }
  for (const auto &item : waits) {
    Json event = errorJson("cancelled", "插件已卸载或插件框架已停止");
    event["kind"] = "http.response";
    event["requestId"] = item.first;
    emit(item.second, std::move(event));
  }
}

/* ==================== TCP 连接 ==================== */

struct TcpStream : Stream {
  explicit TcpStream(std::shared_ptr<PluginNetHub::Impl> hubRef)
      : Stream(std::move(hubRef), std::shared_ptr<utilxx::TcpConnection>{}) {}

  std::shared_ptr<PluginNetHub::Impl::Server> server;

  /// 发起连接 (网络线程); 成功发 `socket.connected`, 失败发 `socket.closed`
  void connectTo(std::string host, uint16_t port, int32_t timeoutMs);
  void onConnected();

  /// 客户端还没连上 (这期间 send 要拒绝, 否则会写到未连接的 socket 上)
  bool connecting = false;

  const char *kind() const override { return "tcp"; }

  void onBytes(const char *data, size_t size) override {
    Json event;
    event["kind"] = "socket.data";
    event["id"] = id;
    if (!serverId.empty()) {
      event["serverId"] = serverId;
    }
    const std::string_view view{data, size};
    event["dataBase64"] =
        utilxx_base::base64Encode(std::string_view{data, size});
    if (isValidUtf8(view)) {
      event["text"] = std::string{view};
      event["data"] = std::string{view};
    }
    event["bytes"] = static_cast<int64_t>(size);
    hub->emit(plugin, std::move(event));
  }

  void onClosed(std::string_view reason, std::string_view error) override {
    Json event;
    event["kind"] = "socket.closed";
    event["id"] = id;
    if (!serverId.empty()) {
      event["serverId"] = serverId;
    }
    event["reason"] = std::string{reason};
    if (!error.empty()) {
      event["error"] = std::string{error};
    }
    hub->emit(plugin, std::move(event));
  }
};

/* ==================== HTTP 客户端 ==================== */

/// 一次 HTTP 客户端请求（`http.request` / `http.fetch` / `http.download`）
///
/// 协议（建连、TLS、重定向、chunked、正文上限）交给库里的 `utilxx::HttpClient`，
/// 这里只做三件事：把插件参数换算成请求配置、把结果拼成插件面熟的 JSON、管取消与超时。
/// 整条请求是一条协程，挂在集线器的 io_context 上。
struct HttpRequestTask : std::enable_shared_from_this<HttpRequestTask> {
  std::shared_ptr<PluginNetHub::Impl> hub;
  std::string plugin;
  int64_t requestId = 0;

  // 参数（由 startHttpRequest 填好）
  std::string url;
  std::string method = "GET";
  Json headers = Json::object();
  std::string body;
  int64_t timeoutMs = kDefaultHttpTimeoutMs;
  int64_t maxBytes = 0; ///< <= 0 = 不限制（正文全读进内存）
  bool followRedirects = true;
  int32_t maxRedirects = 3;
  TlsClientOptions tls; ///< https 时按 URL 填好（caFile / caPem / serverName 都在里面）

  /// 本次调用是哪种形态（结果 JSON 的字段不同）
  HttpMode mode = HttpMode::Request;
  /// fetch 的 bytes 形态才需要 bodyBase64
  bool wantBase64 = true;

  /// download: 落盘位置（目录由 startHttpRequest 准备好）
  std::string downloadDir;
  std::string downloadFileName;
  std::string downloadPath;

  // 运行状态
  bool finished = false;
  int64_t startedAtMs = 0;
  int64_t redirects = 0;
  int64_t downloadBytes = 0;
  std::shared_ptr<asio::steady_timer> timer;
  /// 取消信号：取消与超时都靠它把库里的协程拆掉（否则请求会一直占着连接）
  std::shared_ptr<asio::cancellation_signal> cancel;

  void begin() {
    finished = false;
    startedAtMs = nowMs();
    redirects = 0;
    downloadBytes = 0;
    cancel = std::make_shared<asio::cancellation_signal>();
    auto self = shared_from_this();
    // 整条请求的期限（含 DNS、建连、TLS 与读正文）：到点就让库里的协程停下来
    if (timeoutMs > 0) {
      timer = std::make_shared<asio::steady_timer>(hub->io);
      timer->expires_after(std::chrono::milliseconds{timeoutMs});
      timer->async_wait([self](AsioErrorCode ec) {
        if (ec) {
          return;
        }
        self->fail("timeout", "请求超时");
      });
    }
    asio::co_spawn(
        hub->io.get_executor(), self->run(),
        asio::bind_cancellation_slot(
            cancel->slot(),
            [self](std::exception_ptr error) { self->onDone(error); }));
  }

  /// 跑完整条请求（库的协程在这里被 await；取消会作为异常穿出来）
  asio::awaitable<void> run() {
    auto self = shared_from_this();
    const ParsedUrl parsed = parseUrl(url);
    if (!parsed.ok) {
      fail("bad_url", parsed.error);
      co_return;
    }
    if (parsed.scheme != "http" && parsed.scheme != "https") {
      fail("unsupported_scheme", "HTTP 客户端只支持 http:// 与 https://");
      co_return;
    }

    utilxx::HeaderMap headerMap;
    std::string contentType;
    if (headers.is_object()) {
      for (const auto &item : headers.items()) {
        const std::string name{item.first};
        // Content-Length / Connection / Transfer-Encoding 由库生成，写了也忽略
        if (iequals(name, "content-length") || iequals(name, "connection") ||
            iequals(name, "transfer-encoding")) {
          continue;
        }
        const std::string value = toSafeText(jsonTextOf(item.second));
        if (iequals(name, "content-type")) {
          contentType = value;
        }
        headerMap.set(name, value);
      }
    }
    if (!body.empty() && contentType.empty()) {
      contentType = "application/octet-stream";
    }

    utilxx::RequestConfig config;
    const auto budget = timeoutMs > 0 ? std::chrono::milliseconds{timeoutMs}
                                      : std::chrono::hours{24 * 365};
    config.connectTimeout = budget;
    config.readChunkTimeout = budget;
    config.followRedirect =
        followRedirects ? static_cast<size_t>((std::max)(0, maxRedirects)) : 0;
    config.keepAlive = false;
    // 正文上限：插件给了 maxBytes 就读满停下并标 truncated，不给就整份读进内存
    config.truncateToLimit = maxBytes > 0;
    config.maxResponseBody = maxBytes > 0 ? static_cast<uint64_t>(maxBytes) : 0;
    if (parsed.scheme == "https") {
      tls.enable = true;
      tls.host = parsed.host;
      config.sslVerify = tls.verify;
      config.sslVerifyHost = tls.verify;
      config.sslServerName = tls.serverName;
      if (!tls.caFile.empty() || !tls.caPem.empty()) {
        std::string tlsError;
        config.sslContext = tlsClientContext(tls, tlsError);
        if (!config.sslContext) {
          fail("tls_config", tlsError.empty() ? "TLS 配置不可用" : tlsError);
          co_return;
        }
      }
    }

    if (mode == HttpMode::Download) {
      downloadPath = downloadDir + "/" + downloadFileName;
      auto result = co_await utilxx::HttpClient::downloadAsync(
          url, downloadPath, headerMap, config,
          [self](uint64_t received, std::optional<uint64_t> total) {
            (void)total;
            self->downloadBytes = static_cast<int64_t>(received);
          });
      if (finished) {
        co_return;
      }
      if (!result) {
        failFromLibrary(result.error());
        co_return;
      }
      completeDownload(*result);
      co_return;
    }

    auto result = co_await utilxx::HttpClient::requestAsync(
        method, url, body, contentType, headerMap, config);
    if (finished) {
      co_return;
    }
    if (!result) {
      failFromLibrary(result.error());
      co_return;
    }
    completeResponse(*result);
  }

  /// 协程收尾：取消 / 超时已经在 fail() 里发出结果，这里只剩真正的异常
  void onDone(std::exception_ptr error) {
    if (!error || finished) {
      return;
    }
    std::string message = "请求失败";
    try {
      std::rethrow_exception(error);
    } catch (const std::exception &e) {
      message = e.what();
    } catch (...) {
    }
    fail("read_failed", message);
  }

  void completeResponse(const utilxx::HttpResponse &response) {
    if (finished) {
      return;
    }
    finished = true;
    stopTimer();
    redirects = static_cast<int64_t>(response.redirects);
    const int64_t bodyBytes = static_cast<int64_t>(response.body.size());
    Json out = Json::object();
    out["ok"] = true;
    out["url"] = url;
    out["status"] = response.status;
    out["statusText"] = statusTextOf(response.status);
    out["headers"] = headersJsonOf(response.headers);
    out["contentType"] = std::string{response.findHeader("content-type")};
    out["contentLength"] = contentLengthOf(response.headers);
    out["receivedBytes"] = bodyBytes;
    out["truncated"] = response.truncated;
    out["redirects"] = redirects;
    out["elapsedMs"] = nowMs() - startedAtMs;
    out["bodyBytes"] = bodyBytes;
    if (wantBase64) {
      out["bodyBase64"] = utilxx_base::base64Encode(response.body);
    }
    if (isValidUtf8(response.body)) {
      out["body"] = response.body;
    }
    hub->finishHttpRequest(requestId, true, std::move(out));
  }

  void completeDownload(const utilxx::DownloadResult &result) {
    if (finished) {
      return;
    }
    finished = true;
    stopTimer();
    downloadBytes = static_cast<int64_t>(result.bytes);
    Json out = Json::object();
    out["ok"] = true;
    out["url"] = url;
    out["status"] = result.status;
    out["statusText"] = statusTextOf(result.status);
    out["headers"] = headersJsonOf(result.headers);
    out["contentType"] = std::string{result.headers.getSingle("content-type")};
    out["contentLength"] = contentLengthOf(result.headers);
    out["receivedBytes"] = downloadBytes;
    out["truncated"] = false;
    out["redirects"] = redirects;
    out["elapsedMs"] = nowMs() - startedAtMs;
    out["path"] = downloadPath;
    out["bytes"] = downloadBytes;
    hub->finishHttpRequest(requestId, true, std::move(out));
  }

  /// 收尾成一条失败结果（失败 / 超时 / 取消都走这里）
  void fail(std::string_view code, std::string_view message) {
    if (finished) {
      return;
    }
    finished = true;
    stopTimer();
    // 把库里的协程拆掉（连接随请求一起关）
    if (cancel) {
      cancel->emit(asio::cancellation_type::terminal);
    }
    Json out = errorJson(code, message);
    out["url"] = url;
    out["redirects"] = redirects;
    out["elapsedMs"] = nowMs() - startedAtMs;
    hub->finishHttpRequest(requestId, false, std::move(out));
  }

  /// 库只给错误串，这里按其中的关键字还原成插件面熟的错误码
  void failFromLibrary(const std::string &message) {
    const std::string lower = lowerAscii(message);
    const auto has = [&lower](std::string_view needle) {
      return lower.find(needle) != std::string::npos;
    };
    std::string_view code = "read_failed";
    if (has("invalid url")) {
      code = "bad_url";
    } else if (has("cannot open file") || has("write file") || has("no such file")) {
      code = "write_failed";
    } else if (has("resolve") || has("host not found") || has("name or service")) {
      code = "resolve_failed";
    } else if (has("certificate") || has("cert ") || has("verify failed")) {
      code = "tls_cert_invalid";
    } else if (has("ssl") || has("tls") || has("handshake")) {
      code = "tls_handshake_failed";
    } else if (has("connect") || has("refused") || has("unreachable")) {
      code = "connect_failed";
    } else if (has("truncated") || has("partial")) {
      code = "incomplete";
    } else if (has("timeout") || has("timed out")) {
      code = "timeout";
    }
    fail(code, message);
  }

  void stopTimer() {
    if (!timer) {
      return;
    }
    AsioErrorCode ignored;
    timer->cancel();
  }

  static Json headersJsonOf(const utilxx::HeaderMap &map) {
    Json out = Json::object();
    for (const auto &item : map.data) {
      // 重复头（Set-Cookie 等）用换行拼起来，与旧实现一致
      std::string joined;
      for (const auto &value : item.second) {
        if (!joined.empty()) {
          joined += '\n';
        }
        joined += toSafeText(value);
      }
      out[lowerAscii(toSafeText(item.first))] = joined;
    }
    return out;
  }

  static int64_t contentLengthOf(const utilxx::HeaderMap &map) {
    const std::string_view text = map.getSingle("content-length");
    if (text.empty()) {
      return -1;
    }
    int64_t value = 0;
    const auto parsed = std::from_chars(text.data(), text.data() + text.size(), value);
    if (parsed.ec != std::errc{} || value < 0) {
      return -1;
    }
    return value;
  }

  static int64_t nowMs() {
    return static_cast<int64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch())
            .count());
  }
};

/* ==================== HTTP 客户端: 中心侧入口 ==================== */

bool PluginNetHub::Impl::startHttpRequest(const std::string &plugin,
                                          int64_t requestId, const Json &args,
                                          DoneFn done, Json &out,
                                          int32_t mode) {
  if (!args.is_object()) {
    out = errorJson("bad_args", "参数必须是对象");
    return false;
  }
  const std::string url = args.value("url", std::string{});
  if (url.empty()) {
    out = errorJson("bad_args", "缺少 url");
    return false;
  }
  size_t active = 0;
  for (const auto &item : httpWaits) {
    if (item.second.plugin == plugin) {
      ++active;
    }
  }
  if (active >= kMaxHttpClientsPerPlugin) {
    out = errorJson("too_many_requests", "同时在进行的 HTTP 请求过多");
    return false;
  }

  auto client = std::make_shared<HttpRequestTask>();
  client->hub = shared_from_this();
  client->plugin = plugin;
  client->requestId = requestId;
  client->url = url;
  client->mode = static_cast<HttpMode>(mode);
  client->method = args.value("method", std::string{"GET"});
  for (char &c : client->method) {
    if (c >= 'a' && c <= 'z') {
      c = static_cast<char>(c - 'a' + 'A');
    }
  }
  if (args["headers"].is_object()) {
    client->headers = args["headers"];
  }
  const std::string bodyBase64 = args.value("bodyBase64", std::string{});
  if (!bodyBase64.empty()) {
    const auto decoded = utilxx_base::base64Decode(bodyBase64);
    if (!decoded.has_value()) {
      out = errorJson("bad_base64", "bodyBase64 解不开");
      return false;
    }
    client->body = *decoded;
  } else {
    const std::string body = args.value("body", std::string{});
    if (!body.empty()) {
      client->body = body;
    } else if (args.contains("json")) {
      client->body = args["json"].dump();
      if (!client->headers.contains("Content-Type")) {
        client->headers["Content-Type"] = "application/json";
      }
    }
  }
  const int64_t timeoutMs = args.value("timeoutMs", int64_t{kDefaultHttpTimeoutMs});
  // 超时不再夹区间: `<= 0` = 不设超时
  client->timeoutMs = timeoutMs <= 0 ? int64_t{0} : timeoutMs;
  // 正文上限不再夹区间: `<= 0` = 不限制（插件自己控制内存）
  client->maxBytes = args.value("maxBytes", int64_t{0});
  client->followRedirects = args.value("followRedirects", true);
  client->maxRedirects = static_cast<int32_t>(
      (std::max)(int64_t{0}, (std::min)(args.value("maxRedirects", int64_t{3}),
                                        int64_t{5})));

  // TLS 选项 (https 才用得到)
  parseTlsOptions(args, client->tls);

  // 结果形态
  if (client->mode == HttpMode::Fetch) {
    const std::string responseType = args.value("responseType", std::string{"text"});
    client->wantBase64 = responseType == "bytes";
  } else if (client->mode == HttpMode::Download) {
    // 下载只做 GET 落盘 (与 `http.download` 的参数/行为一致)
    if (client->method != "GET") {
      out = errorJson("bad_args", "下载只支持 GET");
      return false;
    }
    if (dataDir.empty()) {
      out = errorJson("no_data_dir",
                      "插件数据目录未就绪 (host_config.data_dir 为空), 不能下载到本地");
      return false;
    }
    const std::string fileName =
        downloadFileNameOf(args.value("fileName", std::string{}), url);
    client->downloadDir = dataDir + "/" + plugin + "/data/downloads";
    client->downloadFileName = fileName;
    // 目录先建出来; 建不出来就让调用方拿到可读原因
    std::error_code dirEc;
    std::filesystem::create_directories(client->downloadDir, dirEc);
    if (dirEc) {
      out = errorJson("write_failed", "下载目录建不出来: " + client->downloadDir +
                                          " (" + errorTextOf(dirEc) + ")");
      return false;
    }
  }

  HttpWait wait;
  wait.plugin = plugin;
  wait.done = std::move(done);
  wait.client = client;
  httpWaits[requestId] = std::move(wait);

  out = Json::object();
  out["ok"] = true;
  out["requestId"] = requestId;
  client->begin();
  return true;
}

void PluginNetHub::Impl::finishHttpRequest(int64_t requestId, bool ok,
                                           Json payload) {
  const auto it = httpWaits.find(requestId);
  if (it == httpWaits.end()) {
    return;
  }
  HttpWait wait = std::move(it->second);
  httpWaits.erase(it);
  payload["requestId"] = requestId;
  const std::string text = payload.dump();
  if (wait.done) {
    DoneFn done = wait.done;
    postToFramework([done, ok, text] {
      if (done) {
        done(ok ? NetDoneStatus::Ok : NetDoneStatus::Failed, text);
      }
    });
  }
  payload["kind"] = "http.response";
  payload["ok"] = payload.value("ok", ok);
  emit(wait.plugin, std::move(payload));
}

void PluginNetHub::Impl::cancelHttpRequest(const std::string &plugin,
                                           int64_t requestId, Json &out) {
  const auto it = httpWaits.find(requestId);
  if (it == httpWaits.end() || it->second.plugin != plugin) {
    out = errorJson("not_found", "没有这个进行中的请求");
    return;
  }
  auto client = it->second.client;
  if (client) {
    client->fail("cancelled", "请求已取消");
  }
  out = Json::object();
  out["ok"] = true;
  out["requestId"] = requestId;
}

} // namespace utilxx

namespace utilxx {

/* ==================== TCP 客户端连接 ==================== */

void TcpStream::connectTo(std::string host, uint16_t port, int32_t timeoutMs) {
  connecting = true;
  utilxx::TcpConfig config;
  config.connectTimeout =
      std::chrono::milliseconds{(std::max)(timeoutMs, 1000)};
  // 长连接: 不设单次读写期限（空闲多久都不算错）
  config.ioTimeout = std::chrono::milliseconds{0};
  auto self = std::static_pointer_cast<TcpStream>(shared_from_this());
  auto executor = hub->io.get_executor();
  asio::co_spawn(
      executor,
      [self, executor, host, port, config]() -> asio::awaitable<void> {
        std::expected<std::unique_ptr<utilxx::TcpConnection>, std::string>
            connected = std::unexpected{std::string{"connect failed"}};
        try {
          connected = co_await utilxx::TcpConnection::connect(executor, host,
                                                              port, config);
        } catch (const std::exception &e) {
          connected = std::unexpected{std::string{e.what()}};
        } catch (...) {
          connected = std::unexpected{std::string{"connect failed"}};
        }
        if (self->closing) {
          co_return;
        }
        if (!connected) {
          self->closeStream("connect_failed", connected.error());
          co_return;
        }
        self->tcpConn =
            std::shared_ptr<utilxx::TcpConnection>(std::move(*connected));
        self->onConnected();
      },
      asio::detached
  );
}

void TcpStream::onConnected() {
  connecting = false;
  if (tcpConn) {
    remote = tcpConn->peerAddress();
    local = tcpConn->localAddress();
  }
  Json event;
  event["kind"] = "socket.connected";
  event["id"] = id;
  event["remote"] = remote;
  event["local"] = local;
  hub->emit(plugin, std::move(event));
  start();
}

/* ==================== TCP 服务端连接 ==================== */

asio::awaitable<void> PluginNetHub::Impl::onTcpAccepted(
    const std::shared_ptr<Server> &server,
    std::shared_ptr<utilxx::TcpConnection> conn) {
  auto self = shared_from_this();
  if (!conn || !server) {
    co_return;
  }
  if (server->conns.size() >= static_cast<size_t>(server->maxConnections) ||
      connectionCountOf(server->plugin) >= kMaxConnectionsPerPlugin) {
    conn->abort();
    co_return;
  }
  const int64_t seq = nextConnSeq.fetch_add(1, std::memory_order_relaxed);
  auto tcp = std::make_shared<TcpStream>(self);
  tcp->tcpConn = std::move(conn);
  tcp->plugin = server->plugin;
  tcp->serverId = server->id;
  tcp->id = server->id + "#" + std::to_string(seq);
  tcp->server = server;
  tcp->remote = tcp->tcpConn->peerAddress();
  tcp->local = tcp->tcpConn->localAddress();
  if (!registerStream(tcp)) {
    tcp->closeStream("error", "too_many");
    co_return;
  }
  Json event;
  event["kind"] = "socket.accepted";
  event["serverId"] = server->id;
  event["id"] = tcp->id;
  event["remote"] = tcp->remote;
  event["local"] = tcp->local;
  emit(server->plugin, std::move(event));
  tcp->start();
  // 这条协程就是连接的生命周期: 连接关掉（或服务停止）才返回
  co_await tcp->waitClosed();
}

/* ==================== WebSocket ==================== */

struct WsStream : Stream {
  explicit WsStream(std::shared_ptr<PluginNetHub::Impl> hubRef,
                    asio::ip::tcp::socket socketRef)
      : Stream(std::move(hubRef), std::move(socketRef)) {}

  bool roleClient = true;
  std::shared_ptr<PluginNetHub::Impl::Server> server;

  // 客户端参数
  std::string url;
  std::string clientKey;
  Json extraHeaders = Json::object();
  std::vector<std::string> subprotocols;
  int32_t connectTimeoutMs = 8000;
  TlsClientOptions tlsOptions; ///< wss 时由 ws.connect 的参数填好

  // 双方共用
  std::string subprotocol;
  int64_t maxMessage = kMaxWsMessage;
  bool open = false;
  bool closeSent = false;
  std::string handshakeIn;
  std::string in;
  std::string messageAccum;
  int32_t messageOpcode = 0;
  std::string closeBy; ///< remote / local / error / plugin_unloaded
  int32_t closeCode = 0;
  std::string closeReason;

  std::unique_ptr<asio::ip::tcp::resolver> resolver;
  std::unique_ptr<asio::steady_timer> timer;

  const char *kind() const override { return "ws"; }

  /* ---------- 读 ---------- */

  void onBytes(const char *data, size_t size) override {
    if (!open) {
      handshakeIn.append(data, size);
      if (roleClient) {
        handleClientHandshake();
      } else {
        handleServerHandshake();
      }
      return;
    }
    in.append(data, size);
    drainFrames();
  }

  void onClosed(std::string_view reason, std::string_view error) override {
    if (timer) {
      AsioErrorCode ignored;
      timer->cancel();
    }
    Json event;
    event["kind"] = "ws.close";
    event["id"] = id;
    if (!serverId.empty()) {
      event["serverId"] = serverId;
    }
    if (closeBy.empty()) {
      // closeStream 的原因串直接映射成"谁关的"
      if (reason == "local_close") {
        closeBy = "local";
      } else if (reason == "remote_closed") {
        closeBy = "remote";
      } else if (reason == "plugin_unloaded") {
        closeBy = "plugin";
      } else {
        closeBy = "error";
      }
    }
    event["by"] = closeBy;
    if (closeCode != 0) {
      event["code"] = closeCode;
    }
    if (!closeReason.empty()) {
      event["reason"] = toSafeText(closeReason);
    }
    if (!error.empty()) {
      event["error"] = std::string{error};
    }
    hub->emit(plugin, std::move(event));
  }

  /* ---------- 客户端: 连接 + 握手 ---------- */

  void startClient() {
    ParsedUrl target = parseUrl(url);
    if (!target.ok) {
      closeBy = "error";
      closeStream("error", target.error);
      return;
    }
    const bool secure = target.scheme == "wss";
    if (target.scheme != "ws" && !secure) {
      closeBy = "error";
      closeStream("error", "WebSocket 地址只支持 ws:// 或 wss://");
      return;
    }
    tlsOptions.enable = secure;
    tlsOptions.host = target.host;
    armTimer(connectTimeoutMs);
    resolver = std::make_unique<asio::ip::tcp::resolver>(hub->io);
    auto self = std::static_pointer_cast<WsStream>(shared_from_this());
    resolver->async_resolve(
        target.host, std::to_string(target.port),
        [self, target](AsioErrorCode ec,
                       asio::ip::tcp::resolver::results_type results) {
          if (ec) {
            self->closeBy = "error";
            self->closeStream("connect_failed", "解析失败: " + errorTextOf(ec));
            return;
          }
          asio::async_connect(
              self->io->lowest_layer(), results,
              [self, target](AsioErrorCode connectEc,
                             const asio::ip::tcp::endpoint &) {
                if (connectEc) {
                  self->closeBy = "error";
                  self->closeStream("connect_failed",
                                    "连接失败: " + errorTextOf(connectEc));
                  return;
                }
                AsioErrorCode ignored;
                self->remote = endpointText(
                    self->io->lowest_layer().remote_endpoint(ignored));
                self->local = endpointText(
                    self->io->lowest_layer().local_endpoint(ignored));
                if (!self->tlsOptions.enable) {
                  self->sendClientHandshake(target);
                  return;
                }
                // wss: 先完成 TLS 握手, 再在上面跑 WebSocket 握手
                self->io->asyncStartTls(
                    self->tlsOptions,
                    [self, target](AsioErrorCode tlsEc, std::string code,
                                   std::string message) {
                      if (self->closing) {
                        return;
                      }
                      if (tlsEc) {
                        self->closeBy = "error";
                        self->closeStream(code.empty() ? "tls_failed" : code,
                                          message);
                        return;
                      }
                      self->sendClientHandshake(target);
                    });
              });
        });
  }

  void sendClientHandshake(const ParsedUrl &target) {
    clientKey = wsClientKey();
    std::string request = "GET " + target.target + " HTTP/1.1\r\n";
    request += "Host: " + hostHeaderOf(target) + "\r\n";
    request += "Upgrade: websocket\r\n";
    request += "Connection: Upgrade\r\n";
    request += "Sec-WebSocket-Key: " + clientKey + "\r\n";
    request += "Sec-WebSocket-Version: 13\r\n";
    if (!subprotocols.empty()) {
      request += "Sec-WebSocket-Protocol: ";
      for (size_t i = 0; i < subprotocols.size(); ++i) {
        if (i > 0) {
          request += ", ";
        }
        request += subprotocols[i];
      }
      request += "\r\n";
    }
    if (extraHeaders.is_object()) {
      for (const auto &item : extraHeaders.items()) {
        const std::string name{item.first};
        if (iequals(name, "host") || iequals(name, "upgrade") ||
            iequals(name, "connection") || iequals(name, "sec-websocket-key") ||
            iequals(name, "sec-websocket-version") ||
            iequals(name, "sec-websocket-protocol")) {
          continue;
        }
        request += name + ": " + toSafeText(jsonTextOf(item.second)) + "\r\n";
      }
    }
    request += "\r\n";
    armTimer(connectTimeoutMs);
    std::string err;
    send(std::move(request), err);
    if (!err.empty()) {
      closeBy = "error";
      closeStream("error", err);
      return;
    }
    start(); ///< 读循环 (等 101)
  }

  void handleClientHandshake() {
    const size_t headEnd = handshakeIn.find("\r\n\r\n");
    if (headEnd == std::string::npos) {
      if (handshakeIn.size() > kMaxHeadBytes) {
        failHandshake("握手响应头过大");
      }
      return;
    }
    HttpHead head;
    const std::string headText = handshakeIn.substr(0, headEnd);
    handshakeIn.erase(0, headEnd + 4);
    if (!parseHttpHead(headText, false, head) || head.status != 101) {
      failHandshake("握手被拒绝 (状态 " + std::to_string(head.status) + ")");
      return;
    }
    const std::string accept = head.header("sec-websocket-accept");
    if (accept != wsAcceptKey(clientKey)) {
      failHandshake("Sec-WebSocket-Accept 不匹配");
      return;
    }
    subprotocol = head.header("sec-websocket-protocol");
    open = true;
    if (timer) {
      AsioErrorCode ignored;
      timer->cancel();
    }
    Json event;
    event["kind"] = "ws.open";
    event["id"] = id;
    event["url"] = url;
    event["remote"] = remote;
    event["headers"] = head.headersJson();
    if (!subprotocol.empty()) {
      event["subprotocol"] = subprotocol;
    }
    hub->emit(plugin, std::move(event));
    if (!handshakeIn.empty()) {
      in = std::move(handshakeIn);
      handshakeIn.clear();
      drainFrames();
    }
  }

  /* ---------- 服务端: 握手 ---------- */

  void handleServerHandshake() {
    const size_t headEnd = handshakeIn.find("\r\n\r\n");
    if (headEnd == std::string::npos) {
      if (handshakeIn.size() > kMaxHeadBytes) {
        failHandshake("握手请求头过大");
      }
      return;
    }
    HttpHead head;
    const std::string headText = handshakeIn.substr(0, headEnd);
    handshakeIn.erase(0, headEnd + 4);
    if (!parseHttpHead(headText, true, head)) {
      failHandshake("握手请求头解析失败");
      return;
    }
    const std::string key = head.header("sec-websocket-key");
    const std::string upgrade = lowerAscii(head.header("upgrade"));
    const std::string connection = lowerAscii(head.header("connection"));
    if (key.empty() || upgrade.find("websocket") == std::string::npos ||
        connection.find("upgrade") == std::string::npos) {
      failHandshake("不是合法的 WebSocket 握手");
      return;
    }
    std::string path;
    std::string query;
    splitTarget(head.target, path, query);
    if (server && !server->pathPrefix.empty() &&
        !startsWith(path, server->pathPrefix)) {
      std::string err;
      send("HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
           err);
      closeBy = "error";
      closeStream("handshake_rejected", "路径不匹配");
      return;
    }
    std::string response =
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
        "Connection: Upgrade\r\nSec-WebSocket-Accept: " +
        wsAcceptKey(key) + "\r\n";
    const std::string wanted = head.header("sec-websocket-protocol");
    if (!wanted.empty()) {
      // 服务端不声明子协议: 原样回第一个是常见做法, 但更安全的是不回
      // (客户端会按"没选"处理); 这里保持不回。
    }
    response += "\r\n";
    std::string err;
    send(std::move(response), err);
    if (!err.empty()) {
      closeBy = "error";
      closeStream("error", err);
      return;
    }
    open = true;
    Json event;
    event["kind"] = "ws.open";
    event["id"] = id;
    if (!serverId.empty()) {
      event["serverId"] = serverId;
    }
    event["path"] = toSafeText(path);
    event["query"] = toSafeText(query);
    event["remote"] = remote;
    event["headers"] = head.headersJson();
    hub->emit(plugin, std::move(event));
    if (!handshakeIn.empty()) {
      in = std::move(handshakeIn);
      handshakeIn.clear();
      drainFrames();
    }
  }

  void failHandshake(std::string_view message) {
    closeBy = "error";
    // 服务端: 给对端一个可读的拒绝响应 (客户端: 直接关)
    if (!roleClient && !closing) {
      std::string err;
      send("HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
           err);
    }
    closeStream("handshake_failed", message);
  }

  void armTimer(int32_t timeoutMs) {
    if (!timer) {
      timer = std::make_unique<asio::steady_timer>(hub->io);
    }
    AsioErrorCode ignored;
    timer->cancel();
    timer->expires_after(
        std::chrono::milliseconds{(std::max)(timeoutMs, 1000)});
    auto self = std::static_pointer_cast<WsStream>(shared_from_this());
    timer->async_wait([self](AsioErrorCode ec) {
      if (!ec && !self->open) {
        self->closeBy = "error";
        self->closeStream("timeout", "握手超时");
      }
    });
  }

  /* ---------- 帧 ---------- */

  void drainFrames() {
    while (open && !closing) {
      if (in.size() < 2) {
        return;
      }
      const auto b0 = static_cast<unsigned char>(in[0]);
      const auto b1 = static_cast<unsigned char>(in[1]);
      const bool fin = (b0 & 0x80) != 0;
      const int32_t opcode = b0 & 0x0F;
      const bool masked = (b1 & 0x80) != 0;
      if ((b0 & 0x70) != 0) {
        protocolError(1002, "保留位不为 0");
        return;
      }
      uint64_t length = b1 & 0x7F;
      size_t offset = 2;
      if (length == 126) {
        if (in.size() < 4) {
          return;
        }
        length = (static_cast<uint64_t>(static_cast<unsigned char>(in[2])) << 8) |
                 static_cast<unsigned char>(in[3]);
        offset = 4;
      } else if (length == 127) {
        if (in.size() < 10) {
          return;
        }
        uint64_t value = 0;
        for (size_t i = 2; i < 10; ++i) {
          value = (value << 8) | static_cast<unsigned char>(in[i]);
        }
        if ((value & 0x8000000000000000ull) != 0) {
          protocolError(1002, "帧长度最高位为 1");
          return;
        }
        length = value;
        offset = 10;
      }
      if (length > static_cast<uint64_t>(maxMessage)) {
        protocolError(1009, "消息超过上限");
        return;
      }
      if (!roleClient && !masked) {
        protocolError(1002, "客户端发来的帧必须带掩码");
        return;
      }
      if (roleClient && masked) {
        protocolError(1002, "服务端发来的帧不能带掩码");
        return;
      }
      const size_t maskLength = masked ? 4 : 0;
      if (in.size() < offset + maskLength + length) {
        return;
      }
      std::string payload = in.substr(offset + maskLength, length);
      if (masked) {
        const unsigned char *mask =
            reinterpret_cast<const unsigned char *>(in.data() + offset);
        for (size_t i = 0; i < payload.size(); ++i) {
          payload[i] = static_cast<char>(
              static_cast<unsigned char>(payload[i]) ^ mask[i % 4]);
        }
      }
      in.erase(0, offset + maskLength + length);
      handleFrame(fin, opcode, std::move(payload));
    }
  }

  void handleFrame(bool fin, int32_t opcode, std::string payload) {
    switch (opcode) {
    case 0x0: { // 分片续帧
      if (messageOpcode == 0) {
        protocolError(1002, "没有开始的分片");
        return;
      }
      appendFragment(std::move(payload), fin);
      return;
    }
    case 0x1:
    case 0x2: { // 文本 / 二进制
      if (messageOpcode != 0) {
        protocolError(1002, "上一条分片消息还没结束");
        return;
      }
      if (!fin) {
        messageOpcode = opcode;
        messageAccum = std::move(payload);
        if (static_cast<int64_t>(messageAccum.size()) > maxMessage) {
          protocolError(1009, "消息超过上限");
        }
        return;
      }
      deliverMessage(opcode, payload);
      return;
    }
    case 0x8:
      handleCloseFrame(payload);
      return;
    case 0x9: { // ping → pong
      std::string err;
      sendFrame(0xA, payload, err);
      return;
    }
    case 0xA: { // pong
      Json event;
      event["kind"] = "ws.pong";
      event["id"] = id;
      if (!serverId.empty()) {
        event["serverId"] = serverId;
      }
      event["bytes"] = static_cast<int64_t>(payload.size());
      hub->emit(plugin, std::move(event));
      return;
    }
    default:
      protocolError(1002, "未知帧类型");
      return;
    }
  }

  void appendFragment(std::string payload, bool fin) {
    messageAccum += payload;
    if (static_cast<int64_t>(messageAccum.size()) > maxMessage) {
      protocolError(1009, "消息超过上限");
      return;
    }
    if (fin) {
      const int32_t opcode = messageOpcode;
      std::string full = std::move(messageAccum);
      messageOpcode = 0;
      messageAccum.clear();
      deliverMessage(opcode, full);
    }
  }

  void deliverMessage(int32_t opcode, const std::string &payload) {
    Json event;
    event["kind"] = "ws.message";
    event["id"] = id;
    if (!serverId.empty()) {
      event["serverId"] = serverId;
    }
    event["binary"] = opcode == 0x2;
    event["dataBase64"] = utilxx_base::base64Encode(payload);
    if (opcode == 0x1) {
      event["text"] = payload;
    }
    event["bytes"] = static_cast<int64_t>(payload.size());
    hub->emit(plugin, std::move(event));
  }

  void handleCloseFrame(const std::string &payload) {
    closeBy = "remote";
    if (payload.size() >= 2) {
      closeCode = (static_cast<unsigned char>(payload[0]) << 8) |
                  static_cast<unsigned char>(payload[1]);
      closeReason = payload.substr(2);
    } else {
      closeCode = 1005; ///< 没有状态码
    }
    if (!closeSent) {
      std::string echo;
      if (payload.size() >= 2) {
        echo = payload.substr(0, 2);
      }
      std::string err;
      sendFrame(0x8, echo, err);
      closeSent = true;
    }
    flushThenClose();
  }

  void protocolError(int32_t code, std::string_view message) {
    closeBy = "error";
    if (!closeSent) {
      std::string err;
      sendFrame(0x8, closePayload(code, std::string{message}), err);
      closeSent = true;
    }
    closeStream("protocol_error", message);
  }

  static std::string closePayload(int32_t code, const std::string &reason) {
    std::string payload;
    payload.push_back(static_cast<char>((code >> 8) & 0xFF));
    payload.push_back(static_cast<char>(code & 0xFF));
    payload += reason.substr(0, 120);
    return payload;
  }

  void sendFrame(int32_t opcode, std::string_view payload, std::string &err) {
    if (!open || closing) {
      err = "not_open";
      return;
    }
    std::string frame;
    frame.reserve(payload.size() + 14);
    frame.push_back(static_cast<char>(0x80 | (opcode & 0x0F)));
    const bool mask = roleClient;
    const uint64_t size = payload.size();
    if (size < 126) {
      frame.push_back(static_cast<char>((mask ? 0x80 : 0x00) | size));
    } else if (size <= 0xFFFF) {
      frame.push_back(static_cast<char>((mask ? 0x80 : 0x00) | 126));
      frame.push_back(static_cast<char>((size >> 8) & 0xFF));
      frame.push_back(static_cast<char>(size & 0xFF));
    } else {
      frame.push_back(static_cast<char>((mask ? 0x80 : 0x00) | 127));
      for (int i = 7; i >= 0; --i) {
        frame.push_back(static_cast<char>((size >> (8 * i)) & 0xFF));
      }
    }
    if (mask) {
      const auto key = randomBytes(4);
      frame.append(reinterpret_cast<const char *>(key.data()), 4);
      const size_t start = frame.size();
      frame.append(payload);
      for (size_t i = 0; i < size; ++i) {
        frame[start + i] = static_cast<char>(
            static_cast<unsigned char>(frame[start + i]) ^ key[i % 4]);
      }
    } else {
      frame.append(payload);
    }
    send(std::move(frame), err);
  }

  /// 插件主动关闭 (`ws.close` / `socket.close`)
  void closeByPlugin(int32_t code, const std::string &reason) {
    if (closeBy.empty()) {
      closeBy = "local";
    }
    closeCode = code;
    closeReason = reason;
    if (!closeSent && open) {
      std::string err;
      sendFrame(0x8, closePayload(code, reason), err);
      closeSent = true;
    }
    flushThenClose();
  }
};

/* ==================== 接受连接 (需要各种 Stream 已定义) ==================== */

void PluginNetHub::Impl::onAccepted(const std::shared_ptr<Server> &server,
                                    asio::ip::tcp::socket socket) {
  if (!server || server->conns.size() >=
                     static_cast<size_t>(server->maxConnections) ||
      connectionCountOf(server->plugin) >= kMaxConnectionsPerPlugin) {
    AsioErrorCode ignored;
    socket.close(ignored);
    return;
  }
  const int64_t seq = nextConnSeq.fetch_add(1, std::memory_order_relaxed);
  const std::string connId = server->id + "#" + std::to_string(seq);

  std::shared_ptr<Stream> stream;
  if (server->kind == "ws") {
    auto ws = std::make_shared<WsStream>(shared_from_this(), std::move(socket));
    ws->server = server;
    ws->roleClient = false;
    // 握手要有上界: 连上不发 (或发坏的) 握手不能一直占着连接
    ws->armTimer(10000);
    stream = ws;
  } else {
    // 其它类型（tcp 现在走库的 TcpServer，不会进到这里）: 直接关掉
    AsioErrorCode ignored;
    socket.close(ignored);
    return;
  }
  stream->plugin = server->plugin;
  stream->serverId = server->id;
  stream->id = connId;
  if (!registerStream(stream)) {
    stream->io->close();
    return;
  }
  if (auto tcp = std::dynamic_pointer_cast<TcpStream>(stream)) {
    Json event;
    event["kind"] = "socket.accepted";
    event["serverId"] = server->id;
    event["id"] = stream->id;
    event["remote"] = stream->remote;
    event["local"] = stream->local;
    emit(server->plugin, std::move(event));
  }
  stream->start();
}

/* ==================== UDP 通道 ==================== */

/// 一个 UDP 通道: 绑定一个本地端口收发数据报
///
/// 广播与组播都走它:
/// - 建通道时就打开 `SO_BROADCAST`, 所以 `udp.send` 可以直接发给 `255.255.255.255`
///   或子网广播地址（例如 `192.168.1.255`）;
/// - 组播地址在 `udp.open` 的 `multicast` 里声明, 也可以用 `udp.join` / `udp.leave` 动态增删;
/// - 收到的包以 `udp.message` 事件交给插件（`dataBase64` 恒有, 合法文本包额外带 `text` / `data`）;
/// - 通道跟着插件实例: 停用 / 卸载 / 关『拟声++』/ 插件框架停机时一起关掉。
struct UdpChannel : std::enable_shared_from_this<UdpChannel> {
  std::shared_ptr<PluginNetHub::Impl> hub;
  std::string plugin;
  std::string id;
  std::string host; ///< 绑定地址
  uint16_t port = 0; ///< 绑定端口（0 = 系统分配, 绑定后回填实际端口）
  /// 底层 socket 交给库（`utilxx::UdpSocket`）: 这里只管记账与事件
  std::unique_ptr<utilxx::UdpSocket> socket;
  std::set<std::string> groups;   ///< 已加入的组播组地址
  bool reading = false;
  bool closing = false;
  int64_t recvPackets = 0;
  int64_t recvBytes = 0;
  int64_t sentPackets = 0;
  int64_t sentBytes = 0;

  void startRead();
  asio::awaitable<void> readLoop();
};

void UdpChannel::startRead() {
  if (closing || reading || !socket || !socket->isOpen()) {
    return;
  }
  reading = true;
  auto self = shared_from_this();
  asio::co_spawn(
      hub->io, self->readLoop(), [self](std::exception_ptr ep) {
        self->reading = false;
        if (!ep) {
          return;
        }
        try {
          std::rethrow_exception(ep);
        } catch (const std::exception &e) {
          XX_LOGW("[utilxx] 插件 `{}` 的 UDP 通道 `{}` 收包循环退出: {}",
                  self->plugin, self->id, e.what());
        } catch (...) {
          XX_LOGW("[utilxx] 插件 `{}` 的 UDP 通道 `{}` 收包循环异常退出",
                  self->plugin, self->id);
        }
      });
}

asio::awaitable<void> UdpChannel::readLoop() {
  auto self = shared_from_this();
  int  failures = 0;
  while (!closing && socket && socket->isOpen()) {
    auto got = co_await socket->recv();
    if (closing) {
      co_return;
    }
    if (!got) {
      // 收包出错不关通道: 继续收（最常见的是 Windows 上对方端口不可达的 ICMP 回执）
      if (!socket->isOpen()) {
        co_return;
      }
      if (++failures >= 8) {
        XX_LOGW("[utilxx] 插件 `{}` 的 UDP 通道 `{}` 连续收包失败: {}", plugin,
                id, got.error());
        co_return;
      }
      continue;
    }
    failures = 0;
    const std::string &payload = got->data;
    ++recvPackets;
    recvBytes += static_cast<int64_t>(payload.size());
    if (!hub) {
      continue;
    }
    Json event;
    event["kind"] = "udp.message";
    event["id"] = id;
    event["host"] = got->fromAddress;
    event["port"] = static_cast<int64_t>(got->fromPort);
    event["bytes"] = static_cast<int64_t>(payload.size());
    const std::string_view view{payload};
    event["dataBase64"] = utilxx_base::base64Encode(view);
    if (isValidUtf8(view)) {
      event["text"] = std::string{view};
      event["data"] = std::string{view};
    }
    hub->emit(plugin, std::move(event));
  }
}

/* ==================== UDP: 操作实现 ==================== */

namespace {

/// 关掉一个还没登记进表、也没发过 `udp.open` 的通道（建通道中途失败时用）
void closeUnannouncedUdp(const std::shared_ptr<UdpChannel> &channel) {
  if (!channel) {
    return;
  }
  channel->closing = true;
  if (channel->socket) {
    channel->socket->abort();
  }
}

} // namespace

void PluginNetHub::Impl::shutdownUdp(
    const std::shared_ptr<UdpChannel> &channel, const char *reason) {
  if (!channel || channel->closing) {
    return;
  }
  channel->closing = true;
  if (channel->socket) {
    channel->socket->abort();
  }
  Json event;
  event["kind"] = "udp.closed";
  event["id"] = channel->id;
  event["reason"] = std::string{reason ? reason : "local_close"};
  emit(channel->plugin, std::move(event));
}

void PluginNetHub::Impl::closeUdpOf(const std::string &plugin,
                                    bool allPlugins) {  std::vector<std::shared_ptr<UdpChannel>> closing;
  for (auto it = udpChannels.begin(); it != udpChannels.end();) {
    if (!it->second || (allPlugins ? true : it->second->plugin == plugin)) {
      closing.push_back(it->second);
      it = udpChannels.erase(it);
    } else {
      ++it;
    }
  }
  for (const auto &channel : closing) {
    shutdownUdp(channel, "plugin_unloaded");
  }
}

bool PluginNetHub::Impl::openUdp(const std::string &plugin, const Json &args,
                                  Json &out) {
  const std::string wantedId{trimAscii(args.value("id", std::string{}))};
  if (!wantedId.empty() && !isValidId(wantedId)) {
    out = errorJson("bad_args",
                    "id 只能包含字母数字与 . _ -（长度 1~64）: " + wantedId);
    return false;
  }
  size_t count = 0;
  for (const auto &item : udpChannels) {
    if (item.second && item.second->plugin == plugin) {
      ++count;
    }
  }
  if (count >= kMaxUdpChannelsPerPlugin) {
    out = errorJson("too_many", "UDP 通道已达上限 (" +
                                      std::to_string(kMaxUdpChannelsPerPlugin) +
                                      " 条)");
    return false;
  }
  std::string id = wantedId;
  if (id.empty()) {
    do {
      id = "udp" + std::to_string(nextConnSeq.fetch_add(1));
    } while (udpChannels.find(connKeyOf(plugin, id)) != udpChannels.end());
  } else if (udpChannels.find(connKeyOf(plugin, id)) != udpChannels.end()) {
    out = errorJson("exists", "已有同 id 的 UDP 通道: " + id);
    return false;
  }

  std::string host{trimAscii(args.value("host", std::string{"0.0.0.0"}))};
  if (host.empty()) {
    host = "0.0.0.0";
  }
  if (host == "localhost") {
    host = "127.0.0.1";
  }
  AsioErrorCode ec;
  const auto address = asio::ip::make_address(host, ec);
  if (ec) {
    out = errorJson("bad_host", "绑定地址不是合法的 IP: " + host);
    return false;
  }
  const int64_t rawPort = args.value("port", int64_t{0});
  if (rawPort < 0 || rawPort > 65535) {
    out = errorJson("bad_port", "端口超出范围");
    return false;
  }

  auto channel = std::make_shared<UdpChannel>();
  channel->hub = shared_from_this();
  channel->plugin = plugin;
  channel->id = id;
  channel->host = address.to_string();
  channel->port = static_cast<uint16_t>(rawPort);
  utilxx::UdpConfig socketConfig;
  socketConfig.address = channel->host;
  socketConfig.port = channel->port;
  // 广播: 建通道时就开, 这样插件不必先"声明要广播"才能发给 255.255.255.255; 地址重用
  // （组播 / 多实例监听同一端口要用）缺省开, 插件可以写 reuseAddress: false 关掉
  socketConfig.broadcast = true;
  socketConfig.reuseAddress = args.value("reuseAddress", true);
  auto opened = utilxx::UdpSocket::openSync(io.get_executor(), socketConfig);
  if (!opened) {
    out = errorJson("bind_failed", "绑定 " + channel->host + ":" +
                                       std::to_string(channel->port) +
                                       " 失败: " + opened.error());
    return false;
  }
  channel->socket = std::move(*opened);
  channel->port = channel->socket->info().port;

  // 建通道时一次声明的组播组: 字符串或数组都认（`multicast` / `groups` 两种写法）
  std::vector<std::string> groups;
  const Json &rawGroups =
      args.contains("multicast") ? args["multicast"] : args["groups"];
  if (rawGroups.is_string()) {
    groups.push_back(rawGroups.get<std::string>());
  } else if (rawGroups.is_array()) {
    for (const auto &item : rawGroups) {
      if (item.is_string()) {
        groups.push_back(item.get<std::string>());
      }
    }
  }
  for (const auto &group : groups) {
    AsioErrorCode joinEc;
    const auto groupAddress = asio::ip::make_address(trimAscii(group), joinEc);
    if (joinEc || !groupAddress.is_multicast() || !groupAddress.is_v4()) {
      closeUnannouncedUdp(channel);
      out = errorJson("bad_group", "不是合法的组播地址 (只支持 IPv4 组播): " + group);
      return false;
    }
    const auto joined = channel->socket->joinMulticast(groupAddress.to_string());
    if (!joined) {
      closeUnannouncedUdp(channel);
      out = errorJson("join_failed",
                      "加入组播组 " + group + " 失败: " + joined.error());
      return false;
    }
    channel->groups.insert(groupAddress.to_string());
  }

  udpChannels[connKeyOf(plugin, id)] = channel;
  channel->startRead();

  Json event;
  event["kind"] = "udp.open";
  event["id"] = id;
  event["host"] = channel->host;
  event["port"] = static_cast<int64_t>(channel->port);
  emit(plugin, event);

  out = Json::object();
  out["ok"] = true;
  out["id"] = id;
  out["host"] = channel->host;
  out["port"] = static_cast<int64_t>(channel->port);
  out["multicast"] = [&channel] {
    Json list = Json::array();
    for (const auto &group : channel->groups) {
      list.push_back(group);
    }
    return list;
  }();
  return true;
}

bool PluginNetHub::Impl::groupUdp(const std::string &plugin, const Json &args,
                                   bool join, Json &out) {
  const std::string id{trimAscii(args.value("id", std::string{}))};
  const auto it = udpChannels.find(connKeyOf(plugin, id));
  if (it == udpChannels.end() || !it->second) {
    out = errorJson("not_found", "没有这个 UDP 通道: " + id);
    return false;
  }
  const auto channel = it->second;
  const std::string raw{trimAscii(args.value("group", args.value("address",
                                                    std::string{})))};
  AsioErrorCode ec;
  const auto groupAddress = asio::ip::make_address(raw, ec);
  if (ec || !groupAddress.is_multicast() || !groupAddress.is_v4()) {
    out = errorJson("bad_group", "不是合法的组播地址 (只支持 IPv4 组播): " + raw);
    return false;
  }
  const auto applied = join
                           ? channel->socket->joinMulticast(groupAddress.to_string())
                           : channel->socket->leaveMulticast(groupAddress.to_string());
  if (applied) {
    if (join) {
      channel->groups.insert(groupAddress.to_string());
    } else {
      channel->groups.erase(groupAddress.to_string());
    }
  }
  out = Json::object();
  if (!applied) {
    out["ok"] = false;
    out["error"] = join ? "join_failed" : "leave_failed";
    out["message"] = applied.error();
    return false;
  }
  out["ok"] = true;
  out["id"] = channel->id;
  out["group"] = groupAddress.to_string();
  out["multicast"] = [&channel] {
    Json list = Json::array();
    for (const auto &item : channel->groups) {
      list.push_back(item);
    }
    return list;
  }();
  return true;
}

void PluginNetHub::Impl::sendUdp(const std::string &plugin, const Json &args,
                                 Json &out) {
  const std::string id{trimAscii(args.value("id", std::string{}))};
  const auto it = udpChannels.find(connKeyOf(plugin, id));
  if (it == udpChannels.end() || !it->second) {
    out = errorJson("not_found", "没有这个 UDP 通道: " + id);
    return;
  }
  const auto channel = it->second;
  if (channel->closing) {
    out = errorJson("closed", "这条 UDP 通道已关闭");
    return;
  }

  // 目标：host / address / to 三种写法都认；缺省端口 = 通道自己的端口
  // （发给自己的广播 / 组播常用这个缺省）
  std::string host{trimAscii(args.value(
      "host", args.value("address", args.value("to", std::string{}))))};
  if (host.empty()) {
    out = errorJson("bad_args", "缺少目标 host（广播写 255.255.255.255 或子网广播地址）");
    return;
  }
  if (host == "localhost") {
    host = "127.0.0.1";
  }
  const int64_t rawPort = args.value("port", int64_t{channel->port});
  if (rawPort <= 0 || rawPort > 65535) {
    out = errorJson("bad_port", "目标端口超出范围");
    return;
  }

  std::string payload;
  const std::string base64 = args.value("dataBase64", std::string{});
  if (!base64.empty()) {
    const auto decoded = utilxx_base::base64Decode(base64);
    if (!decoded.has_value()) {
      out = errorJson("bad_base64", "dataBase64 解不开");
      return;
    }
    payload = *decoded;
  } else {
    payload = args.value("data", std::string{});
    if (payload.empty()) {
      payload = args.value("text", std::string{});
    }
  }
  if (payload.empty()) {
    out = errorJson("bad_args", "没有要发送的内容 (data / text / dataBase64)");
    return;
  }

  // 发送与域名解析都交给库（同步形态：这次调用本来就在等结果）
  const auto sent = channel->socket->sendToSync(
      payload, host, static_cast<uint16_t>(rawPort));
  if (!sent) {
    const std::string &reason = sent.error();
    const bool looksResolve = reason.find("resolve") != std::string::npos ||
                              reason.find("Host not found") != std::string::npos ||
                              reason.find("Name or service") != std::string::npos;
    out = errorJson(looksResolve ? "resolve_failed" : "send_failed",
                    (looksResolve ? "解析目标地址失败: " : "发送失败: ") +
                        host + " (" + reason + ")");
    return;
  }
  ++channel->sentPackets;
  channel->sentBytes += static_cast<int64_t>(payload.size());
  out = Json::object();
  out["ok"] = true;
  out["id"] = channel->id;
  out["host"] = host;
  out["port"] = static_cast<int64_t>(rawPort);
  out["bytes"] = static_cast<int64_t>(payload.size());
}

void PluginNetHub::Impl::closeUdp(const std::string &plugin,
                                  const std::string &id, Json &out) {
  const auto it = udpChannels.find(connKeyOf(plugin, id));
  if (it == udpChannels.end() || !it->second) {
    out = errorJson("not_found", "没有这个 UDP 通道: " + id);
    return;
  }
  const auto channel = it->second;
  udpChannels.erase(it);
  shutdownUdp(channel, "local_close");
  out = Json::object();
  out["ok"] = true;
  out["id"] = id;
}

Json PluginNetHub::Impl::udpInfoJson(const std::string &plugin,
                                     bool allPlugins) const {
  Json rows = Json::array();
  for (const auto &item : udpChannels) {
    const auto &channel = item.second;
    if (!channel || (!allPlugins && channel->plugin != plugin)) {
      continue;
    }
    Json row = Json::object();
    row["plugin"] = channel->plugin;
    row["id"] = channel->id;
    row["host"] = channel->host;
    row["port"] = static_cast<int64_t>(channel->port);
    Json groups = Json::array();
    for (const auto &group : channel->groups) {
      groups.push_back(group);
    }
    row["multicast"] = std::move(groups);
    row["receivedPackets"] = channel->recvPackets;
    row["receivedBytes"] = channel->recvBytes;
    row["sentPackets"] = channel->sentPackets;
    row["sentBytes"] = channel->sentBytes;
    rows.push_back(std::move(row));
  }
  return rows;
}

/* ==================== 操作分发 ==================== */

void PluginNetHub::Impl::stopServers(const std::string &plugin,
                                     const std::string &kind,
                                     const std::string &id, Json &out) {
  std::vector<std::shared_ptr<Server>> closing;
  for (auto it = servers.begin(); it != servers.end();) {
    if (it->second && it->second->plugin == plugin &&
        (id.empty() || it->second->id == id)) {
      closing.push_back(it->second);
      it = servers.erase(it);
    } else {
      ++it;
    }
  }
  int32_t stopped = 0;
  for (const auto &server : closing) {
    ++stopped;
    if (server->http) {
      server->http->stop();
      wakePendingOfServer(
          serverKeyOf(server->plugin, server->kind, server->id));
    }
    if (server->tcp) {
      server->tcp->stop();
    }
    if (server->acceptor) {
      AsioErrorCode ignored;
      server->acceptor->close(ignored);
    }
    std::vector<std::string> connIds(server->conns.begin(), server->conns.end());
    for (const auto &connId : connIds) {
      const auto stream = findConn(plugin, connId);
      if (stream) {
        stream->closeStream("server_stopped", {});
      }
    }
    Json event;
    event["kind"] = kind == "http" ? "http.serverClosed"
                      : kind == "ws" ? "ws.serverClosed"
                                     : "socket.serverClosed";
    event["id"] = server->id;
    emit(plugin, std::move(event));
  }
  out = Json::object();
  out["ok"] = true;
  out["stopped"] = stopped;
}

void PluginNetHub::Impl::closeConn(const std::string &plugin,
                                   const std::string &id, Json &out) {
  const auto stream = findConn(plugin, id);
  if (!stream) {
    out = errorJson("not_found", "没有这条连接");
    return;
  }
  if (auto ws = std::dynamic_pointer_cast<WsStream>(stream)) {
    ws->closeByPlugin(1000, {});
  } else {
    stream->closeStream("local_close", {});
  }
  out = Json::object();
  out["ok"] = true;
  out["id"] = id;
}

void PluginNetHub::Impl::sendConn(const std::string &plugin, const Json &args,
                                  Json &out) {
  const std::string id = args.value("id", std::string{});
  if (id.empty()) {
    out = errorJson("bad_args", "缺少连接 id");
    return;
  }
  const auto stream = findConn(plugin, id);
  if (!stream) {
    out = errorJson("not_found", "没有这条连接");
    return;
  }
  if (std::string_view{stream->kind()} != "tcp") {
    out = errorJson("wrong_kind", "这条连接不是 socket 连接 (WS 连接用 ws.send)");
    return;
  }
  if (auto tcp = std::dynamic_pointer_cast<TcpStream>(stream)) {
    if (tcp->connecting) {
      out = errorJson("not_connected", "连接还在建立中 (等 socket.connected 再发)");
      return;
    }
  }
  std::string payload;
  const std::string base64 = args.value("dataBase64", std::string{});
  if (!base64.empty()) {
    const auto decoded = utilxx_base::base64Decode(base64);
    if (!decoded.has_value()) {
      out = errorJson("bad_base64", "dataBase64 解不开");
      return;
    }
    payload = *decoded;
  } else {
    payload = args.value("data", std::string{});
    if (payload.empty()) {
      payload = args.value("text", std::string{});
    }
  }
  if (payload.empty()) {
    out = errorJson("bad_args", "没有要发送的内容 (data / dataBase64)");
    return;
  }
  std::string err;
  stream->send(std::move(payload), err);
  if (!err.empty()) {
    out = errorJson(err, "发送失败");
    return;
  }
  out = Json::object();
  out["ok"] = true;
  out["id"] = id;
  // 发送队列里还没写出去的字节数: 插件用它判断要不要先暂停上游 (背压)
  out["queuedBytes"] = static_cast<int64_t>(stream->outBytes);
}

std::string PluginNetHub::Impl::staticBaseUrl(const Server &server) const {
  if (server.url.empty()) {
    return server.url;
  }
  const std::string &prefix = server.pathPrefix;
  if (!prefix.empty() && server.url.size() >= prefix.size() &&
      server.url.compare(server.url.size() - prefix.size(), prefix.size(),
                         prefix) == 0) {
    return server.url.substr(0, server.url.size() - prefix.size());
  }
  return server.url;
}

Json PluginNetHub::Impl::staticRoutesJson(const Server &server) const {
  Json rows = Json::array();
  for (const auto &route : server.routes) {
    if (!route) {
      continue;
    }
    Json row = Json::object();
    row["path"] = route->path;
    row["url"] = staticBaseUrl(server) + route->path;
    row["size"] = route->size;
    row["contentType"] = route->contentType;
    row["fileName"] = route->fileName;
    if (!route->file.empty()) {
      row["file"] = route->file;
    }
    row["mtimeMs"] = route->mtimeMs;
    rows.push_back(std::move(row));
  }
  return rows;
}

std::string PluginNetHub::Impl::infoJsonOnThread(const std::string &plugin,
                                                 bool allPlugins) {
  Json out = Json::object();
  out["ok"] = true;
  out["running"] = running.load(std::memory_order_acquire);
  // 客户端 TLS: https / wss 恒可用 (TLS 是必备能力, 服务端仍然只有 http / ws)
  out["tls"] = true;
  out["tlsProvider"] = ::OpenSSL_version(OPENSSL_VERSION);
  out["schemes"] = [] {
    Json schemes = Json::array();
    schemes.push_back("http");
    schemes.push_back("https");
    schemes.push_back("ws");
    schemes.push_back("wss");
    return schemes;
  }();
  Json serversJson = Json::array();
  for (const auto &item : servers) {
    const auto &server = item.second;
    if (!server || (!allPlugins && server->plugin != plugin)) {
      continue;
    }
    Json row = Json::object();
    row["plugin"] = server->plugin;
    row["kind"] = server->kind;
    row["id"] = server->id;
    row["host"] = server->host;
    row["port"] = static_cast<int64_t>(server->port);
    if (!server->url.empty()) {
      row["url"] = server->url;
    }
    if (!server->pathPrefix.empty()) {
      row["path"] = server->pathPrefix;
    }
    row["connections"] = server->http
                             ? static_cast<int64_t>(server->http->activeConnections())
                             : static_cast<int64_t>(server->conns.size());
    row["pending"] = static_cast<int64_t>(server->pending);
    if (server->staticOnly) {
      row["staticOnly"] = true;
    }
    if (!server->routes.empty()) {
      row["routes"] = staticRoutesJson(*server);
    }
    serversJson.push_back(std::move(row));
  }
  out["servers"] = std::move(serversJson);
  Json connsJson = Json::array();
  for (const auto &item : conns) {
    const auto &stream = item.second;
    if (!stream || (!allPlugins && stream->plugin != plugin)) {
      continue;
    }
    Json row = Json::object();
    row["plugin"] = stream->plugin;
    row["id"] = stream->id;
    row["kind"] = stream->kind();
    if (!stream->serverId.empty()) {
      row["serverId"] = stream->serverId;
    }
    row["remote"] = stream->remote;
    row["local"] = stream->local;
    row["secure"] = stream->io && stream->io->usingTls();
    row["queuedBytes"] = static_cast<int64_t>(stream->outBytes);
    connsJson.push_back(std::move(row));
  }
  out["connections"] = std::move(connsJson);
  size_t httpClients = 0;
  for (const auto &item : httpWaits) {
    if (allPlugins || item.second.plugin == plugin) {
      ++httpClients;
    }
  }
  out["httpClients"] = static_cast<int64_t>(httpClients);
  out["udp"] = udpInfoJson(plugin, allPlugins);
  Json limits = Json::object();
  limits["maxServersPerKind"] = kMaxServersPerKind;
  limits["maxConnectionsPerPlugin"] =
      static_cast<int64_t>(kMaxConnectionsPerPlugin);
  limits["maxHttpClientsPerPlugin"] =
      static_cast<int64_t>(kMaxHttpClientsPerPlugin);
  limits["maxHttpPendingPerServer"] =
      static_cast<int64_t>(kMaxHttpPendingPerServer);
  limits["maxHttpBodyBytes"] = kMaxHttpBody;
  limits["maxWsMessageBytes"] = kMaxWsMessage;
  limits["maxOutQueueBytes"] = static_cast<int64_t>(kMaxOutQueue);
  limits["maxUdpChannelsPerPlugin"] =
      static_cast<int64_t>(kMaxUdpChannelsPerPlugin);
  out["limits"] = std::move(limits);
  return out.dump();
}

int32_t PluginNetHub::Impl::handleCall(const std::string &plugin,
                                       const std::string &op, const Json &args,
                                       Json &out) {
  if (!args.is_object()) {
    out = errorJson("bad_args", "参数必须是对象");
    return PLUGINXX_NET_OK;
  }

  /* ---------- 通用 ---------- */
  if (op == "net.info") {
    out = parseJsonSafe(infoJsonOnThread(plugin, false));
    return PLUGINXX_NET_OK;
  }

  /* ---------- HTTP 客户端 (同步形态: 只受理, 结果经事件) ---------- */
  if (op == "http.request" || op == "http.fetch" || op == "http.download") {
    const int32_t mode =
        (op == "http.fetch") ? 1 : ((op == "http.download") ? 2 : 0);
    const int64_t requestId = allocateRequestId();
    if (!startHttpRequest(plugin, requestId, args, DoneFn{}, out, mode)) {
      return PLUGINXX_NET_OK; ///< out 里已经是错误对象
    }
    return PLUGINXX_NET_OK;
  }
  if (op == "http.cancel") {
    cancelHttpRequest(plugin, args.value("requestId", int64_t{0}), out);
    return PLUGINXX_NET_OK;
  }

  /* ---------- HTTP 服务端 ---------- */
  if (op == "http.serve") {
    std::string id = args.value("id", std::string{});
    if (!id.empty() && !isValidId(id)) {
      out = errorJson("bad_id", "id 只能包含字母数字与 . _ -");
      return PLUGINXX_NET_OK;
    }
    if (id.empty()) {
      id = nextServerId(plugin, "http");
    }
    if (findServer(plugin, "http", id)) {
      out = errorJson("exists", "同名的 HTTP 服务已经存在");
      return PLUGINXX_NET_OK;
    }
    auto server = std::make_shared<Server>();
    server->plugin = plugin;
    server->kind = "http";
    server->id = id;
    server->host = args.value("host", std::string{"127.0.0.1"});
    const int64_t port = args.value("port", int64_t{0});
    if (port < 0 || port > 65535) {
      out = errorJson("bad_port", "端口超出范围");
      return PLUGINXX_NET_OK;
    }
    server->port = static_cast<uint16_t>(port);
    server->pathPrefix = args.value("path", std::string{});
    server->staticOnly = args.value("staticOnly", false);
    server->maxBody = args.value("maxBodyBytes", int64_t{kMaxHttpBody});
    server->requestTimeoutMs = static_cast<int32_t>(
        args.value("requestTimeoutMs", int64_t{30000}));
    server->maxConnections = static_cast<int32_t>(
        args.value("maxConnections", int64_t{32}));
    if (server->maxConnections <= 0) {
      server->maxConnections = 32;
    }
    // 静态内容: 监听之前先全部校验一遍, 有一条不合法就整条 serve 失败
    std::vector<std::shared_ptr<Server::StaticRoute>> routes;
    if (args.contains("static")) {
      if (!args["static"].is_array()) {
        out = errorJson("bad_args", "static 必须是数组");
        return PLUGINXX_NET_OK;
      }
      for (const auto &item : args["static"]) {
        if (routes.size() >= kMaxStaticRoutes) {
          out = errorJson("too_many", "static 条数超过上限 (" +
                                         std::to_string(kMaxStaticRoutes) +
                                         " 条)");
          return PLUGINXX_NET_OK;
        }
        auto route = std::make_shared<Server::StaticRoute>();
        std::string routeErr;
        if (!buildStaticRoute(*server, item, route, routeErr)) {
          out = errorJson("bad_args", "static 里有一条不合法: " + routeErr);
          return PLUGINXX_NET_OK;
        }
        routes.push_back(std::move(route));
      }
    }
    server->routes = routes;
    std::string err;
    if (!listenServer(server, err)) {
      out = errorJson("listen_failed", err);
      return PLUGINXX_NET_OK;
    }
    out = Json::object();
    out["ok"] = true;
    out["id"] = server->id;
    out["host"] = server->host;
    out["port"] = static_cast<int64_t>(server->port);
    out["url"] = server->url;
    if (!server->routes.empty()) {
      out["routes"] = staticRoutesJson(*server);
    }
    Json event;
    event["kind"] = "http.listening";
    event["id"] = server->id;
    event["host"] = server->host;
    event["port"] = static_cast<int64_t>(server->port);
    event["url"] = server->url;
    emit(plugin, std::move(event));
    return PLUGINXX_NET_OK;
  }
  if (op == "http.route" || op == "http.unroute") {
    const std::string serverId =
        args.value("serverId", args.value("id", std::string{}));
    if (serverId.empty()) {
      out = errorJson("bad_args", "要给 serverId");
      return PLUGINXX_NET_OK;
    }
    auto server = findServer(plugin, "http", serverId);
    if (!server) {
      out = errorJson("not_found", "HTTP 服务不存在: " + serverId);
      return PLUGINXX_NET_OK;
    }
    if (op == "http.unroute") {
      const std::string path{trimAscii(args.value("path", std::string{}))};
      if (path.empty()) {
        out = errorJson("bad_args", "要给 path");
        return PLUGINXX_NET_OK;
      }
      out = Json::object();
      out["ok"] = true;
      out["serverId"] = server->id;
      out["path"] = path;
      out["removed"] = removeStaticRoute(server, path);
      out["routes"] = staticRoutesJson(*server);
      return PLUGINXX_NET_OK;
    }
    addStaticRoute(server, args, out);
    return PLUGINXX_NET_OK;
  }
  if (op == "http.respond") {
    const int64_t requestId = args.value("requestId", int64_t{0});
    std::string owner;
    const auto wait = takePendingHttp(requestId, &owner);
    if (!wait || owner != plugin) {
      out = errorJson("not_found", "没有这条等待回答的请求");
      return PLUGINXX_NET_OK;
    }
    wait->payload = args;
    wait->answered = true;
    if (wait->timer) {
      wait->timer->cancel();
    }
    out = Json::object();
    out["ok"] = true;
    out["requestId"] = requestId;
    return PLUGINXX_NET_OK;
  }
  if (op == "http.stop") {
    stopServers(plugin, "http", args.value("id", std::string{}), out);
    return PLUGINXX_NET_OK;
  }
  if (op == "http.info") {
    out = parseJsonSafe(infoJsonOnThread(plugin, false));
    return PLUGINXX_NET_OK;
  }

  /* ---------- TCP 客户端 ---------- */
  if (op == "socket.connect") {
    const std::string host = args.value("host", std::string{});
    const int64_t port = args.value("port", int64_t{0});
    if (host.empty() || port <= 0 || port > 65535) {
      out = errorJson("bad_args", "host / port 不合法");
      return PLUGINXX_NET_OK;
    }
    std::string id = args.value("id", std::string{});
    if (!id.empty() && !isValidId(id)) {
      out = errorJson("bad_id", "id 只能包含字母数字与 . _ -");
      return PLUGINXX_NET_OK;
    }
    if (id.empty()) {
      id = nextConnId(plugin, "c");
    }
    if (findConn(plugin, id)) {
      out = errorJson("exists", "同名的连接已经存在");
      return PLUGINXX_NET_OK;
    }
    auto stream = std::make_shared<TcpStream>(shared_from_this());
    stream->plugin = plugin;
    stream->id = id;
    if (!registerStream(stream)) {
      out = errorJson("too_many", "连接数已达上限");
      return PLUGINXX_NET_OK;
    }
    out = Json::object();
    out["ok"] = true;
    out["id"] = id;
    out["state"] = "connecting";
    const int32_t timeoutMs =
        static_cast<int32_t>(args.value("timeoutMs", int64_t{8000}));
    stream->connectTo(host, static_cast<uint16_t>(port), timeoutMs);
    return PLUGINXX_NET_OK;
  }

  /* ---------- TCP 服务 ---------- */
  if (op == "socket.listen") {
    std::string id = args.value("id", std::string{});
    if (!id.empty() && !isValidId(id)) {
      out = errorJson("bad_id", "id 只能包含字母数字与 . _ -");
      return PLUGINXX_NET_OK;
    }
    if (id.empty()) {
      id = nextServerId(plugin, "tcp");
    }
    if (findServer(plugin, "tcp", id)) {
      out = errorJson("exists", "同名的服务已经存在");
      return PLUGINXX_NET_OK;
    }
    auto server = std::make_shared<Server>();
    server->plugin = plugin;
    server->kind = "tcp";
    server->id = id;
    server->host = args.value("host", std::string{"127.0.0.1"});
    const int64_t port = args.value("port", int64_t{0});
    if (port < 0 || port > 65535) {
      out = errorJson("bad_port", "端口超出范围");
      return PLUGINXX_NET_OK;
    }
    server->port = static_cast<uint16_t>(port);
    server->maxConnections = static_cast<int32_t>(
        args.value("maxConnections", int64_t{32}));
    if (server->maxConnections <= 0) {
      server->maxConnections = 32;
    }
    std::string err;
    if (!listenServer(server, err)) {
      out = errorJson("listen_failed", err);
      return PLUGINXX_NET_OK;
    }
    out = Json::object();
    out["ok"] = true;
    out["id"] = server->id;
    out["host"] = server->host;
    out["port"] = static_cast<int64_t>(server->port);
    Json event;
    event["kind"] = "socket.listening";
    event["id"] = server->id;
    event["host"] = server->host;
    event["port"] = static_cast<int64_t>(server->port);
    emit(plugin, std::move(event));
    return PLUGINXX_NET_OK;
  }

  /* ---------- 连接收发 (TCP 服务端连接同一套) ---------- */
  if (op == "socket.send") {
    sendConn(plugin, args, out);
    return PLUGINXX_NET_OK;
  }
  if (op == "socket.pause") {
    const std::string id = args.value("id", std::string{});
    const auto stream = findConn(plugin, id);
    if (!stream) {
      out = errorJson("not_found", "没有这条连接");
      return PLUGINXX_NET_OK;
    }
    const bool paused = args.value("paused", true);
    stream->setPaused(paused);
    out = Json::object();
    out["ok"] = true;
    out["id"] = id;
    out["paused"] = paused;
    return PLUGINXX_NET_OK;
  }
  if (op == "socket.close") {
    closeConn(plugin, args.value("id", std::string{}), out);
    return PLUGINXX_NET_OK;
  }
  if (op == "socket.serverStop") {
    stopServers(plugin, "tcp", args.value("id", std::string{}), out);
    return PLUGINXX_NET_OK;
  }
  if (op == "socket.info") {
    out = parseJsonSafe(infoJsonOnThread(plugin, false));
    return PLUGINXX_NET_OK;
  }

  /* ---------- WebSocket 客户端 ---------- */
  if (op == "ws.connect") {
    std::string url = args.value("url", std::string{});
    if (url.empty()) {
      // 也接受 host / port / path 的拆开写法
      const std::string host = args.value("host", std::string{});
      const int64_t port = args.value("port", int64_t{0});
      if (!host.empty()) {
        std::string path = args.value("path", std::string{"/"});
        if (path.empty() || path.front() != '/') {
          path = "/" + path;
        }
        url = "ws://" + host + (port > 0 ? ":" + std::to_string(port) : "") + path;
      }
    }
    if (url.empty()) {
      out = errorJson("bad_args", "缺少 url");
      return PLUGINXX_NET_OK;
    }
    const ParsedUrl target = parseUrl(url);
    if (!target.ok) {
      out = errorJson("bad_url", target.error);
      return PLUGINXX_NET_OK;
    }
    if (target.scheme != "ws" && target.scheme != "wss") {
      out = errorJson("unsupported_scheme", "WebSocket 地址只支持 ws:// 或 wss://");
      return PLUGINXX_NET_OK;
    }
    std::string id = args.value("id", std::string{});
    if (!id.empty() && !isValidId(id)) {
      out = errorJson("bad_id", "id 只能包含字母数字与 . _ -");
      return PLUGINXX_NET_OK;
    }
    if (id.empty()) {
      id = nextConnId(plugin, "w");
    }
    if (findConn(plugin, id)) {
      out = errorJson("exists", "同名的连接已经存在");
      return PLUGINXX_NET_OK;
    }
    auto ws = std::make_shared<WsStream>(shared_from_this(),
                                         asio::ip::tcp::socket(io));
    ws->plugin = plugin;
    ws->id = id;
    ws->roleClient = true;
    ws->url = url;
    ws->connectTimeoutMs =
        static_cast<int32_t>(args.value("timeoutMs", int64_t{8000}));
    ws->maxMessage = (std::max)(
        int64_t{1024},
        (std::min)(args.value("maxMessageBytes", int64_t{kMaxWsMessage}),
                   int64_t{16 * 1024 * 1024}));
    parseTlsOptions(args, ws->tlsOptions);
    if (args["headers"].is_object()) {
      ws->extraHeaders = args["headers"];
    }
    if (args["subprotocols"].is_array()) {
      for (const auto &item : args["subprotocols"]) {
        if (item.is_string()) {
          ws->subprotocols.push_back(item.get<std::string>());
        }
      }
    }
    if (!registerStream(ws)) {
      out = errorJson("too_many", "连接数已达上限");
      return PLUGINXX_NET_OK;
    }
    out = Json::object();
    out["ok"] = true;
    out["id"] = id;
    out["state"] = "connecting";
    ws->startClient();
    return PLUGINXX_NET_OK;
  }

  /* ---------- WebSocket 服务 ---------- */
  if (op == "ws.listen") {
    std::string id = args.value("id", std::string{});
    if (!id.empty() && !isValidId(id)) {
      out = errorJson("bad_id", "id 只能包含字母数字与 . _ -");
      return PLUGINXX_NET_OK;
    }
    if (id.empty()) {
      id = nextServerId(plugin, "ws");
    }
    if (findServer(plugin, "ws", id)) {
      out = errorJson("exists", "同名的服务已经存在");
      return PLUGINXX_NET_OK;
    }
    auto server = std::make_shared<Server>();
    server->plugin = plugin;
    server->kind = "ws";
    server->id = id;
    server->host = args.value("host", std::string{"127.0.0.1"});
    const int64_t port = args.value("port", int64_t{0});
    if (port < 0 || port > 65535) {
      out = errorJson("bad_port", "端口超出范围");
      return PLUGINXX_NET_OK;
    }
    server->port = static_cast<uint16_t>(port);
    server->pathPrefix = args.value("path", std::string{});
    server->maxConnections = static_cast<int32_t>(
        args.value("maxConnections", int64_t{32}));
    if (server->maxConnections <= 0) {
      server->maxConnections = 32;
    }
    std::string err;
    if (!listenServer(server, err)) {
      out = errorJson("listen_failed", err);
      return PLUGINXX_NET_OK;
    }
    out = Json::object();
    out["ok"] = true;
    out["id"] = server->id;
    out["host"] = server->host;
    out["port"] = static_cast<int64_t>(server->port);
    out["url"] = server->url;
    Json event;
    event["kind"] = "ws.listening";
    event["id"] = server->id;
    event["host"] = server->host;
    event["port"] = static_cast<int64_t>(server->port);
    event["url"] = server->url;
    emit(plugin, std::move(event));
    return PLUGINXX_NET_OK;
  }
  if (op == "ws.send") {
    const std::string id = args.value("id", std::string{});
    const auto stream = findConn(plugin, id);
    if (!stream) {
      out = errorJson("not_found", "没有这条连接");
      return PLUGINXX_NET_OK;
    }
    const auto ws = std::dynamic_pointer_cast<WsStream>(stream);
    if (!ws) {
      out = errorJson("wrong_kind", "这条连接不是 WebSocket 连接");
      return PLUGINXX_NET_OK;
    }
    int32_t opcode = 1;
    std::string payload;
    const std::string base64 = args.value("dataBase64", std::string{});
    if (!base64.empty()) {
      const auto decoded = utilxx_base::base64Decode(base64);
      if (!decoded.has_value()) {
        out = errorJson("bad_base64", "dataBase64 解不开");
        return PLUGINXX_NET_OK;
      }
      payload = *decoded;
      opcode = 2;
    } else {
      payload = args.value("text", std::string{});
      if (payload.empty()) {
        payload = args.value("data", std::string{});
      }
      if (payload.empty()) {
        out = errorJson("bad_args", "没有要发送的内容 (text / data / dataBase64)");
        return PLUGINXX_NET_OK;
      }
    }
    std::string err;
    ws->sendFrame(opcode, payload, err);
    if (!err.empty()) {
      out = errorJson(err, "发送失败 (连接可能还没握手完成)");
      return PLUGINXX_NET_OK;
    }
    out = Json::object();
    out["ok"] = true;
    out["id"] = id;
    return PLUGINXX_NET_OK;
  }
  if (op == "ws.ping") {
    const std::string id = args.value("id", std::string{});
    const auto stream = findConn(plugin, id);
    const auto ws = std::dynamic_pointer_cast<WsStream>(stream);
    if (!ws) {
      out = errorJson("not_found", "没有这条连接");
      return PLUGINXX_NET_OK;
    }
    std::string err;
    ws->sendFrame(0x9, args.value("text", std::string{}), err);
    out = err.empty() ? Json::object() : errorJson(err, "发送失败");
    out["ok"] = err.empty();
    return PLUGINXX_NET_OK;
  }
  if (op == "ws.close") {
    const std::string id = args.value("id", std::string{});
    const auto stream = findConn(plugin, id);
    const auto ws = std::dynamic_pointer_cast<WsStream>(stream);
    if (!ws) {
      out = errorJson("not_found", "没有这条 WebSocket 连接");
      return PLUGINXX_NET_OK;
    }
    const int32_t code =
        static_cast<int32_t>(args.value("code", int64_t{1000}));
    ws->closeByPlugin(code <= 0 ? 1000 : code,
                      args.value("reason", std::string{}));
    out = Json::object();
    out["ok"] = true;
    out["id"] = id;
    return PLUGINXX_NET_OK;
  }
  if (op == "ws.serverStop") {
    stopServers(plugin, "ws", args.value("id", std::string{}), out);
    return PLUGINXX_NET_OK;
  }
  if (op == "ws.info") {
    out = parseJsonSafe(infoJsonOnThread(plugin, false));
    return PLUGINXX_NET_OK;
  }

  /* ---------- UDP 通道 (广播 / 组播 / 单播) ---------- */
  if (op == "udp.open") {
    openUdp(plugin, args, out);
    return PLUGINXX_NET_OK;
  }
  if (op == "udp.send") {
    sendUdp(plugin, args, out);
    return PLUGINXX_NET_OK;
  }
  if (op == "udp.close") {
    closeUdp(plugin,
             std::string{trimAscii(args.value("id", std::string{}))}, out);
    return PLUGINXX_NET_OK;
  }
  if (op == "udp.join" || op == "udp.leave") {
    groupUdp(plugin, args, op == "udp.join", out);
    return PLUGINXX_NET_OK;
  }
  if (op == "udp.info") {
    out = Json::object();
    out["ok"] = true;
    out["channels"] = udpInfoJson(plugin, false);
    return PLUGINXX_NET_OK;
  }

  return PLUGINXX_NET_ERR_ARG;
}

void PluginNetHub::Impl::startThread() {
  if (running.exchange(true, std::memory_order_acq_rel)) {
    return;
  }
  io.restart();
  guard = std::make_unique<asio::executor_work_guard<asio::io_context::executor_type>>(
      asio::make_work_guard(io));
  auto self = shared_from_this();
  thread = std::thread([self] {
    try {
      self->io.run();
    } catch (const std::exception &e) {
      XX_LOGE("[utilxx] 插件网络线程退出: {}", e.what());
    }
  });
  XX_LOGI("[utilxx] 插件网络线程已启动");
}

void PluginNetHub::Impl::stopThread() {
  if (!running.exchange(false, std::memory_order_acq_rel)) {
    if (thread.joinable()) {
      thread.join();
    }
    return;
  }
  auto slot = std::make_shared<SyncSlot>();
  auto self = shared_from_this();
  asio::post(io, [self, slot] {
    self->closeAllOf({}, true, nullptr);
    slot->set();
  });
  slot->wait(5000);
  guard.reset();
  io.stop();
  if (thread.joinable()) {
    thread.join();
  }
  XX_LOGI("[utilxx] 插件网络线程已停止");
}

/* ==================== 对外入口 ==================== */

PluginNetHub::PluginNetHub(std::shared_ptr<Impl> impl) : impl_(std::move(impl)) {}

PluginNetHub::~PluginNetHub() { stop(); }

std::shared_ptr<PluginNetHub> PluginNetHub::create(PublishFn publish,
                                                   PostFn postToFramework) {
  auto impl = std::make_shared<Impl>();
  impl->publish = std::move(publish);
  impl->postToFramework = std::move(postToFramework);
  return std::shared_ptr<PluginNetHub>(new PluginNetHub(std::move(impl)));
}

void PluginNetHub::start() { impl_->startThread(); }

void PluginNetHub::setDataDir(const std::string &dir) {
  // 在 start() 之前设好 (主程序在 host 配置里给)
  impl_->dataDir = dir;
}

void PluginNetHub::stop() { impl_->stopThread(); }

bool PluginNetHub::running() const {
  return impl_->running.load(std::memory_order_acquire);
}

int32_t PluginNetHub::call(const std::string &pluginId, const std::string &op,
                           const std::string &argsJson, std::string &outJson) {
  if (!running()) {
    return PLUGINXX_NET_ERR_STATE;
  }
  bool parsed = false;
  Json args = parseJsonSafe(argsJson, &parsed);
  if (!parsed) {
    return PLUGINXX_NET_ERR_JSON;
  }
  auto result = std::make_shared<Json>(Json::object());
  auto code = std::make_shared<int32_t>(PLUGINXX_NET_ERR_INTERNAL);
  const bool waited = impl_->runSync([impl = impl_, pluginId, op, args, result,
                                      code] {
    *code = impl->handleCall(pluginId, op, args, *result);
  });
  if (!waited) {
    return PLUGINXX_NET_ERR_TIMEOUT;
  }
  if (*code != PLUGINXX_NET_OK) {
    return *code;
  }
  outJson = result->dump();
  return PLUGINXX_NET_OK;
}

int32_t PluginNetHub::callAsync(const std::string &pluginId,
                                const std::string &op,
                                const std::string &argsJson, DoneFn done,
                                std::string &outJson, int64_t *outRequestId) {
  if (!running()) {
    outJson = errorJson("not_running", "插件网络线程没有运行").dump();
    return PLUGINXX_NET_ERR_STATE;
  }
  if (op != "http.request" && op != "http.fetch" && op != "http.download") {
    outJson = errorJson("unsupported_op", "这个操作没有异步形态").dump();
    return PLUGINXX_NET_ERR_ARG;
  }
  const int32_t mode =
      (op == "http.fetch") ? 1 : ((op == "http.download") ? 2 : 0);
  bool parsed = false;
  Json args = parseJsonSafe(argsJson, &parsed);
  if (!parsed) {
    outJson = errorJson("bad_json", "参数不是合法 JSON").dump();
    return PLUGINXX_NET_ERR_JSON;
  }
  const int64_t requestId = impl_->allocateRequestId();
  auto result = std::make_shared<Json>(Json::object());
  auto started = std::make_shared<bool>(false);
  const bool waited = impl_->runSync(
      [impl = impl_, pluginId, requestId, args, done = std::move(done), result,
       started, mode]() mutable {
        *started = impl->startHttpRequest(pluginId, requestId, args,
                                          std::move(done), *result, mode);
      });
  if (!waited) {
    outJson = errorJson("timeout", "网络线程没有及时受理").dump();
    return PLUGINXX_NET_ERR_TIMEOUT;
  }
  outJson = result->dump();
  if (!*started) {
    return PLUGINXX_NET_ERR_ARG;
  }
  if (outRequestId) {
    *outRequestId = requestId;
  }
  return PLUGINXX_NET_OK;
}

int32_t PluginNetHub::cancel(const std::string &pluginId, int64_t requestId,
                             std::string &outJson) {
  if (!running()) {
    return PLUGINXX_NET_ERR_STATE;
  }
  auto result = std::make_shared<Json>(Json::object());
  const bool waited = impl_->runSync(
      [impl = impl_, pluginId, requestId, result] {
        impl->cancelHttpRequest(pluginId, requestId, *result);
      });
  if (!waited) {
    return PLUGINXX_NET_ERR_TIMEOUT;
  }
  outJson = result->dump();
  return PLUGINXX_NET_OK;
}

std::vector<PluginNetHub::DoneFn>
PluginNetHub::shutdownPlugin(const std::string &pluginId) {
  auto cancelled = std::make_shared<std::vector<DoneFn>>();
  impl_->runSync(
      [impl = impl_, pluginId, cancelled] {
        impl->closeAllOf(pluginId, false, cancelled.get());
      },
      5000);
  return std::move(*cancelled);
}

std::string PluginNetHub::infoJson(const std::string &pluginId) {
  if (!running()) {
    return errorJson("not_running", "插件网络线程没有运行").dump();
  }
  auto out = std::make_shared<std::string>(
      errorJson("timeout", "网络线程没有及时回答").dump());
  impl_->runSync([impl = impl_, pluginId, out] {
    *out = impl->infoJsonOnThread(pluginId, pluginId.empty());
  }, 5000);
  return *out;
}

} // namespace utilxx


