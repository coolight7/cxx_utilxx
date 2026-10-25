/// HTTP 错误类型 (utilxx::RateLimitError)
///
/// - 从业务引擎自带的限流错误类型中拆分出来: util 层不依赖任何引擎头,
///   限流语义由本库自有类型表达
/// - 与调用方使用的引擎/框架二进制无关, 仅按消息 + retry-after 秒数传递
#pragma once

#include <stdexcept>
#include <string>

#include "utilxx/export.h"

namespace utilxx {

/// 上游 API 返回 HTTP 429 (限流) 时抛出
///
/// - `retry_after_seconds()`: 上游 `Retry-After` 头秒数, 无可用值时为 -1
///   (调用方优先采用正值, 否则用自身默认退避)
class UTILXX_API RateLimitError : public std::runtime_error {
public:

    explicit RateLimitError(const std::string& message, int retry_after_seconds = -1) :
        std::runtime_error(message),
        retry_after_seconds_(retry_after_seconds) {}

    int retry_after_seconds() const noexcept {
        return retry_after_seconds_;
    }

private:

    int retry_after_seconds_ = -1;
};

} // namespace utilxx
