#pragma once

// 网络段返回码（-100 ~ -199）
//
// 只有一份定义：`cxx_pluginxx` 的 `pluginxx/api/result.h` 会把它们转出来给插件用，
// 应用层的 Dart 通过 `musicxx_extern_plugin_result_name()` 查名称。
//
// 约定：
// - 网络段只放「网络操作本身失败」的码；参数 / 状态 / 超时这类任何表都可能返回的码在通用段
//   （`pluginxx/api/result.h`，-1 ~ -99），别往这里塞；
// - 每个码都要有返回点，没有生产者的码不加；
// - 名称是对外契约（JSON 里的 `error`、插件的判断都按它），改名等于改协议。

#include <cstdint>

#define UTILXX_NET_ERR_INVALID_URL (-100)
#define UTILXX_NET_ERR_INVALID_HOST (-101)
#define UTILXX_NET_ERR_INVALID_PORT (-102)
#define UTILXX_NET_ERR_INVALID_ID (-103)
#define UTILXX_NET_ERR_EXISTS (-104)
#define UTILXX_NET_ERR_NOT_CONNECTED (-105)
#define UTILXX_NET_ERR_WRONG_KIND (-106)
#define UTILXX_NET_ERR_BIND_FAILED (-107)
#define UTILXX_NET_ERR_WRITE_FAILED (-108)
#define UTILXX_NET_ERR_UNSUPPORTED_OP (-109)
#define UTILXX_NET_ERR_CANCELED (-110)

namespace utilxx {
namespace net_error {

/// 网络段的名称（不属于这一段时返回 nullptr）
///
/// `inline`：头文件即用，不引入额外目标文件；各库/插件各编译一份字面量，值相同。
inline const char* nameOf(int32_t code) {
  switch (code) {
    case UTILXX_NET_ERR_INVALID_URL: return "invalid_url";
    case UTILXX_NET_ERR_INVALID_HOST: return "invalid_host";
    case UTILXX_NET_ERR_INVALID_PORT: return "invalid_port";
    case UTILXX_NET_ERR_INVALID_ID: return "invalid_id";
    case UTILXX_NET_ERR_EXISTS: return "exists";
    case UTILXX_NET_ERR_NOT_CONNECTED: return "not_connected";
    case UTILXX_NET_ERR_WRONG_KIND: return "wrong_kind";
    case UTILXX_NET_ERR_BIND_FAILED: return "bind_failed";
    case UTILXX_NET_ERR_WRITE_FAILED: return "write_failed";
    case UTILXX_NET_ERR_UNSUPPORTED_OP: return "unsupported_op";
    case UTILXX_NET_ERR_CANCELED: return "canceled";
    default: return nullptr;
  }
}

}  // namespace net_error
}  // namespace utilxx
