#pragma once

#include "utilxx_base/asio_error.h"
#include "utilxx/export.h"
#include "utilxx_base/log.h"
#include "utilxx_base/string_util.h"
#include "asio/awaitable.hpp"
#include "asio/cancel_after.hpp"
#include "asio/ip/tcp.hpp"
#include "asio/ssl/context.hpp"
#include "asio/ssl/stream.hpp"
#include "asio/steady_timer.hpp"
#include "asio/use_awaitable.hpp"
#include <boost/beast/core.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/beast/websocket.hpp>
#include <boost/beast/websocket/ssl.hpp>
#include <chrono>
#include <expected>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace utilxx {

struct UTILXX_API WsMessage {
    enum class Type : uint8_t {
        Text,
        Binary,
        Close,
    };

    Type        type = Type::Text;
    std::string payload;
    uint16_t    closeCode = 0;
    /// 对端 close 帧携带的原因 (仅 Type::Close 时有意义, 可能为空)
    std::string closeReason;
};

struct WsClientConfig {
    inline static constexpr size_t kTimeoutChunkBytes = 64 * 1024;

    std::chrono::milliseconds connectTimeout = std::chrono::seconds{16};
    /// 接收超时: 两次 async_read_some 之间的最大间隔 (per-chunk 语义)。
    /// 只要数据持续到达, 大消息的总接收时间可以远超此值。
    /// 超时不会关闭连接 (连接仍健康), 仅当次 recv() 返回错误。
    std::chrono::milliseconds recvTimeout = std::chrono::seconds{60};
    /// 发送超时: 两次 async_write_some 之间的最大间隔 (per-chunk 语义)。
    std::chrono::milliseconds sendTimeout    = std::chrono::seconds{60};
    bool                      sslVerify      = false;
    size_t                    maxMessageSize = 16 * 1024 * 1024;
};

/// WebSocket 客户端
/// - 收发接口不外抛异常: 失败一律以 `std::expected` 的错误串返回 (取消类异常仍抛出)
/// - **析构安全**: 挂起中的 send/recv 各自持有实现体的强引用, 所以
///   `abort()` 之后立即析构本对象不会让协程读到已释放的内存 (abort 只是关闭
///   socket, 挂起操作的完成回调要等线程回到 io_context 才会执行)
/// - `payload` 是视图: 挂起期间调用方的缓冲必须有效; 已发送完的分块不再引用它
class UTILXX_API WsClient {
public:

    struct Impl;

    ~WsClient();
    WsClient(const WsClient&)            = delete;
    WsClient& operator=(const WsClient&) = delete;
    WsClient(WsClient&&) noexcept;
    WsClient& operator=(WsClient&&) noexcept;

    explicit WsClient(std::unique_ptr<Impl> impl);

    asio::awaitable<std::expected<void, std::string>> sendText(std::string_view payload);

    asio::awaitable<std::expected<void, std::string>> sendBinary(std::string_view payload);

    asio::awaitable<std::expected<void, std::string>> sendPing(std::string_view payload = "");

    asio::awaitable<std::expected<void, std::string>>
        sendClose(uint16_t code = 1000, std::string_view reason = "");

    asio::awaitable<std::expected<WsMessage, std::string>> recv();

    bool isOpen() const noexcept;

    void setRecvTimeout(std::chrono::seconds timeout) noexcept;

    /// 关闭底层 socket, 使挂起的 recv/send 以错误返回
    /// - 须在 WsClient 绑定的 executor 上调用 (与 recv/send 同线程)
    /// - 关闭后挂起的操作**不会当场返回**: 它们的完成回调同样要经 io_context 派发,
    ///   因此可以紧接 `abort()` 就析构 WsClient (实现体由挂起的协程各自持有)
    void abort() noexcept;

private:

    /// 实现体 (按强引用持有)
    ///
    /// 收发协程在**调用当刻**就把这份引用复制进协程帧, 因此
    /// `abort()` + 析构 WsClient 之后, 挂起中的协程仍然可以安全收尾 (见 ws_client.cpp)
    std::shared_ptr<Impl> impl_;
};

asio::awaitable<std::expected<std::unique_ptr<WsClient>, std::string>> UTILXX_API wsConnect(
    asio::any_io_executor                            executor,
    std::string_view                                 url,
    std::vector<std::pair<std::string, std::string>> headers = {},
    WsClientConfig                                   config  = {}
);

/// 从已 accept 的服务端 WS stream 创建 WsClient (供 AgentServer 使用)
UTILXX_API std::unique_ptr<WsClient> wrapAcceptedWs(
    asio::any_io_executor                                     ex,
    boost::beast::websocket::stream<boost::beast::tcp_stream> ws,
    WsClientConfig                                            config = {}
);

} // namespace utilxx
