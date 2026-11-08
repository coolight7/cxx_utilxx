/// 裸 TCP（客户端连接 + 监听服务）
///
/// 定位: 给"插件自己收发字节"这类需求用（局域网协议、私有协议、按行/按帧自定）。
/// 本头只做**字节流**，不做分帧、不做文本解码：一次 `recv` 返回内核这次给到的字节数
/// （与对端怎么写、什么时候 flush 无关），上层自己攒包。HTTP / WebSocket 请用
/// `utilxx/http_client.h` / `utilxx/http_server.h` / `utilxx/ws_client.h`。
///
/// 约定:
/// - 全部操作都是 `asio::awaitable`，必须在**绑定的 executor** 上调用；收发各自串行
///   （同一个连接上并发 `send` 会排队，不会把两条消息的字节交织在一起）；
/// - 不发异常：失败一律以 `std::expected` 的错误串返回（取消类异常仍抛出）；
/// - `abort()` 可以在别的线程调用，挂起的收发会以错误返回；`TcpConnection` 的收发协程
///   各自持有实现体的强引用，所以 `abort()` 之后立刻析构本对象是安全的。
#ifndef UTILXX_TCP_H
#define UTILXX_TCP_H

#include "utilxx/export.h"

// 本库统一用 Boost.Asio: 先引本头拿到 `namespace asio = ::boost::asio` 别名
// (与 ws_client.h / http_server.h 同一套写法)
#include "utilxx_base/asio_error.h"

#include "asio/any_io_executor.hpp"
#include "asio/awaitable.hpp"
#include "asio/ip/tcp.hpp"

#include <chrono>
#include <cstdint>
#include <expected>
#include <functional>
#include <memory>
#include <string>
#include <string_view>

namespace utilxx {

/// 一次连接 / 读写的参数
struct UTILXX_API TcpConfig {
    /// DNS 解析 + TCP 连接的总期限
    std::chrono::milliseconds connectTimeout = std::chrono::seconds{10};
    /// 单次读 / 写的期限（`0` = 不限；不是"整个连接的空闲超时"）
    std::chrono::milliseconds ioTimeout = std::chrono::seconds{30};
    /// 一次 `recv` 最多取多少字节（默认 16 KiB，与内核缓冲一次给出的量级一致）
    size_t recvChunk = 16 * 1024;
};

/// 一次 `recv` 的结果
struct UTILXX_API TcpRead {
    /// 对端关闭（本次没有数据）
    bool        eof = false;
    std::string data;
};

/// 一条已建立的 TCP 连接（客户端连上的，或服务端 accept 到的）
class UTILXX_API TcpConnection {
public:

    struct Impl;

    ~TcpConnection();
    TcpConnection(const TcpConnection&)            = delete;
    TcpConnection& operator=(const TcpConnection&) = delete;

    /// 发送整段数据（多次调用按调用顺序串行）
    asio::awaitable<std::expected<void, std::string>> send(std::string_view data);

    /// 收一段数据；没有数据时挂起等待，对端关闭返回 `eof = true`
    asio::awaitable<std::expected<TcpRead, std::string>> recv();

    /// 对端地址，形如 `127.0.0.1:52341`
    std::string peerAddress() const;

    /// 本端地址，形如 `127.0.0.1:52341`（服务端用它告诉插件实际分配到的端口）
    std::string localAddress() const;

    bool isOpen() const noexcept;

    /// 关闭底层 socket，使挂起的收发以错误返回（可在任意线程调用）
    void abort() noexcept;

    /// 从一条已建立的 socket 创建连接对象（给 `TcpServer` 用；一般不需要手工调）
    static std::shared_ptr<TcpConnection>
        adopt(asio::ip::tcp::socket socket, TcpConfig config = {});

    /// 连一条 TCP（`host` 可以是域名或 IP 字面量；IPv6 直接写地址，不带方括号）
    static asio::awaitable<std::expected<std::unique_ptr<TcpConnection>, std::string>>
        connect(
            asio::any_io_executor executor,
            std::string_view      host,
            uint16_t              port,
            TcpConfig             config = {}
        );

    /// 置 / 取消 keepalive（长连接防 NAT 静默丢弃；best-effort）
    void setKeepAlive(bool enable) noexcept;

private:

    explicit TcpConnection(std::shared_ptr<Impl> impl);

    std::shared_ptr<Impl> impl_;
};

/// TCP 监听服务
///
/// - `startAsync(ex)` 在给定 executor 上起 accept 循环，**不自建线程**（调用方负责运行
///   io_context）；`start()` 会阻塞调用线程直到 `stop()`，适合"自己一个服务占一条线程"的场景；
/// - 每条连接交给 `onConnection` 协程处理；协程返回即视为这条连接结束（socket 随对象析构关闭）；
/// - `maxConnections` 到上限时不再 accept（新连接排队在内核 backlog），不无界建对象。
class UTILXX_API TcpServer {
public:

    struct Config {
        std::string address        = "127.0.0.1";
        uint16_t    port           = 0; // 0 = 由系统分配, 起来后读 port()
        size_t      maxConnections = 64;
        int         backlog        = 64;
        TcpConfig   connection; // 每条连接的读写参数
    };

    /// 处理一条连接；返回时这条连接被关闭
    using Handler = std::function<asio::awaitable<void>(std::shared_ptr<TcpConnection>)>;

    TcpServer(Config config, Handler handler);
    ~TcpServer();

    TcpServer(const TcpServer&)            = delete;
    TcpServer& operator=(const TcpServer&) = delete;

    /// 在 `executor` 上起 accept 循环（不阻塞、不建线程）
    /// - 地址被占用等错误通过返回值给出，失败时服务不会起来
    std::expected<void, std::string> startAsync(asio::any_io_executor executor);

    /// 阻塞调用线程直到 `stop()`（内部自建 io_context 与工作线程）
    std::expected<void, std::string> start();

    /// 停止监听并关掉已接受的连接（任意线程可调用）
    void stop();

    /// 实际监听端口（`port = 0` 时是系统分配的值）
    uint16_t port() const noexcept;

    /// 实际监听地址
    std::string address() const;

    size_t activeConnections() const noexcept;

    bool isStopped() const noexcept;

    /// 实现细节 (给 tcp.cpp 里的 accept 循环用; 不要从外部引用)
    struct Impl;

private:

    std::shared_ptr<Impl> impl_;
};

} // namespace utilxx

#endif /* UTILXX_TCP_H */
