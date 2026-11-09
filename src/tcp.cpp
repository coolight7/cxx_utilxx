#include "utilxx/tcp.h"

#include "utilxx/http_client.h"

#include "utilxx_base/asio_error.h"
#include "utilxx_base/async_mutex.h"
#include "utilxx_base/log.h"

#include "asio/cancel_after.hpp"
#include "asio/co_spawn.hpp"
#include "asio/connect.hpp"
#include "asio/detached.hpp"
#include "asio/ip/tcp.hpp"
#include "asio/post.hpp"
#include "asio/read.hpp"
#include "asio/redirect_error.hpp"
#include "asio/steady_timer.hpp"
#include "asio/use_awaitable.hpp"
#include "asio/write.hpp"

#include <algorithm>
#include <atomic>
#include <mutex>
#include <optional>
#include <thread>
#include <vector>

namespace utilxx {

namespace {

using utilxx_base::AsioErrorCode;

/// 对端正常关闭的那些错误码: 按"读到结尾"处理, 不当作失败
bool isClosedError(const AsioErrorCode& ec) noexcept {
    return ec == asio::error::eof || ec == asio::error::connection_reset
        || ec == asio::error::connection_aborted || ec == asio::error::broken_pipe
        || ec == asio::error::operation_aborted;
}

/// 地址 → "ip:port" 文本 (失败返回空串)
template<typename Endpoint>
std::string endpointText(const Endpoint& ep) {
    const auto addr = ep.address();
    if (addr.is_v6()) {
        return "[" + addr.to_string() + "]:" + std::to_string(ep.port());
    }
    return addr.to_string() + ":" + std::to_string(ep.port());
}

} // namespace

/* ==================== TcpConnection ==================== */

struct TcpConnection::Impl {
    asio::ip::tcp::socket socket;
    TcpConfig              config;
    /// 发送 / 接收各自串行: 并发 send 不会把两段字节交织在一起
    utilxx_base::AsyncMutex sendMutex;
    utilxx_base::AsyncMutex recvMutex;
    std::atomic<bool>       closed{false};
    std::atomic<uint64_t>   sentBytes{0};
    std::atomic<uint64_t>   receivedBytes{0};

    Impl(asio::ip::tcp::socket sock, TcpConfig cfg) :
        socket(std::move(sock)),
        config(std::move(cfg)),
        sendMutex(socket.get_executor()),
        recvMutex(socket.get_executor()) {}
};

TcpConnection::TcpConnection(std::shared_ptr<Impl> impl) :
    impl_(std::move(impl)) {}

std::shared_ptr<TcpConnection> TcpConnection::adopt(
    asio::ip::tcp::socket socket,
    TcpConfig             config
) {
    auto impl = std::make_shared<Impl>(std::move(socket), std::move(config));
    // 构造函数是私有的: 这里用 new 而不是 make_shared
    return std::shared_ptr<TcpConnection>(new TcpConnection(std::move(impl)));
}

TcpConnection::~TcpConnection() {
    abort();
}

asio::awaitable<std::expected<void, std::string>> TcpConnection::send(std::string_view data) {
    auto impl = impl_;
    if (!impl || impl->closed.load(std::memory_order_acquire) || !impl->socket.is_open()) {
        co_return std::unexpected(std::string{"connection closed"});
    }
    auto guard = co_await impl->sendMutex.lock();
    if (impl->closed.load(std::memory_order_acquire)) {
        co_return std::unexpected(std::string{"connection closed"});
    }
    AsioErrorCode ec;
    if (impl->config.ioTimeout.count() > 0) {
        co_await asio::async_write(
            impl->socket,
            asio::buffer(data.data(), data.size()),
            asio::cancel_after(
                impl->config.ioTimeout,
                asio::redirect_error(asio::use_awaitable, ec)
            )
        );
    } else {
        co_await asio::async_write(
            impl->socket,
            asio::buffer(data.data(), data.size()),
            asio::redirect_error(asio::use_awaitable, ec)
        );
    }
    if (ec) {
        // 写失败意味着连接已经不可用: 标记关闭, 让挂起的读也尽快返回
        impl->closed.store(true, std::memory_order_release);
        co_return std::unexpected(ec.message());
    }
    impl->sentBytes.fetch_add(data.size(), std::memory_order_relaxed);
    co_return std::expected<void, std::string>{};
}

asio::awaitable<std::expected<TcpRead, std::string>> TcpConnection::recv() {
    auto impl = impl_;
    if (!impl) {
        co_return std::unexpected(std::string{"connection closed"});
    }
    auto guard = co_await impl->recvMutex.lock();
    if (impl->closed.load(std::memory_order_acquire) || !impl->socket.is_open()) {
        co_return TcpRead{.eof = true, .data = {}};
    }
    std::string buf(impl->config.recvChunk > 0 ? impl->config.recvChunk : 16 * 1024, '\0');
    AsioErrorCode ec;
    size_t        n = 0;
    if (impl->config.ioTimeout.count() > 0) {
        n = co_await impl->socket.async_read_some(
            asio::buffer(buf.data(), buf.size()),
            asio::cancel_after(
                impl->config.ioTimeout,
                asio::redirect_error(asio::use_awaitable, ec)
            )
        );
    } else {
        n = co_await impl->socket.async_read_some(
            asio::buffer(buf.data(), buf.size()),
            asio::redirect_error(asio::use_awaitable, ec)
        );
    }
    if (ec) {
        if (isClosedError(ec)) {
            impl->closed.store(true, std::memory_order_release);
            co_return TcpRead{.eof = true, .data = {}};
        }
        co_return std::unexpected(ec.message());
    }
    buf.resize(n);
    impl->receivedBytes.fetch_add(n, std::memory_order_relaxed);
    co_return TcpRead{.eof = false, .data = std::move(buf)};
}

std::string TcpConnection::peerAddress() const {
    if (!impl_) {
        return {};
    }
    AsioErrorCode ec;
    const auto    ep = impl_->socket.remote_endpoint(ec);
    return ec ? std::string{} : endpointText(ep);
}

std::string TcpConnection::localAddress() const {
    if (!impl_) {
        return {};
    }
    AsioErrorCode ec;
    const auto    ep = impl_->socket.local_endpoint(ec);
    return ec ? std::string{} : endpointText(ep);
}

bool TcpConnection::isOpen() const noexcept {
    return impl_ && !impl_->closed.load(std::memory_order_acquire) && impl_->socket.is_open();
}

void TcpConnection::abort() noexcept {
    if (!impl_) {
        return;
    }
    if (impl_->closed.exchange(true, std::memory_order_acq_rel)) {
        return;
    }
    // 先取消挂起的收发再关：Windows 上带挂起读的 closesocket 会把连接重置，
    // 已经写进发送缓冲的数据会被丢掉（表现为客户端少收一截）
    AsioErrorCode ec;
    impl_->socket.cancel(ec);
    impl_->socket.close(ec);
}

void TcpConnection::setKeepAlive(bool enable) noexcept {
    if (!impl_) {
        return;
    }
    AsioErrorCode ec;
    impl_->socket.set_option(asio::socket_base::keep_alive(enable), ec);
}

/* ==================== TcpConnection::connect ==================== */

asio::awaitable<std::expected<std::unique_ptr<TcpConnection>, std::string>>
    TcpConnection::connect(
        asio::any_io_executor executor,
        std::string_view      host,
        uint16_t              port,
        TcpConfig             config
    ) {
    if (host.empty() || port == 0) {
        co_return std::unexpected(std::string{"invalid endpoint"});
    }
    const auto    deadline = std::chrono::steady_clock::now() + config.connectTimeout;
    AsioErrorCode ec;
    asio::ip::tcp::resolver::results_type results;
    // DNS 解析统一走 HttpClient 的"带期限 + 可取消"实现: getaddrinfo 本身无法中断,
    // 直接调用会让黑洞 DNS 把网络线程挂死
    try {
        results = co_await HttpClient::asyncResolveWithDeadline(
            host,
            std::to_string(port),
            deadline,
            config.connectTimeout
        );
    } catch (const std::exception& e) {
        co_return std::unexpected(std::string{e.what()});
    }
    asio::ip::tcp::socket socket(executor);
    co_await asio::async_connect(
        socket,
        results,
        asio::cancel_after(
            config.connectTimeout,
            asio::redirect_error(asio::use_awaitable, ec)
        )
    );
    if (ec) {
        AsioErrorCode ignored;
        socket.close(ignored);
        co_return std::unexpected(ec.message());
    }
    AsioErrorCode optEc;
    socket.set_option(asio::ip::tcp::no_delay(true), optEc);
    auto impl = std::make_shared<TcpConnection::Impl>(std::move(socket), std::move(config));
    // 构造函数是私有的: 这里用 new 而不是 make_unique (make_unique 没有访问权)
    co_return std::unique_ptr<TcpConnection>(new TcpConnection(std::move(impl)));
}

/* ==================== TcpServer ==================== */

struct TcpServer::Impl : std::enable_shared_from_this<TcpServer::Impl> {
    Config                config;
    Handler               handler;
    asio::any_io_executor executor;
    /// 监听器要到 startAsync 拿到 executor 后才能建 (asio 的 acceptor 没有默认构造)
    std::optional<asio::ip::tcp::acceptor> acceptor;
    std::atomic<bool>     stopped{false};
    std::atomic<size_t>   active{0};
    uint16_t              boundPort = 0;
    std::string           boundAddress;

    /// 已接受的连接 (stop 时逐个 abort); 用 public 类型, 不碰 TcpConnection::Impl
    std::mutex                                 connMutex;
    std::vector<std::shared_ptr<TcpConnection>> conns;

    /// start() 自建的 io_context (startAsync 调用方自己跑)
    std::unique_ptr<asio::io_context> ownedIo;
    std::unique_ptr<std::thread>      ownedThread;

    /// 反注册一条已结束的连接
    void forget(const std::shared_ptr<TcpConnection>& conn) {
        {
            std::lock_guard<std::mutex> lock{connMutex};
            conns.erase(
                std::remove(conns.begin(), conns.end(), conn),
                conns.end()
            );
        }
        active.fetch_sub(1, std::memory_order_relaxed);
    }

    /// 停掉监听与全部连接 (必须在 executor 线程执行)
    void doStop() {
        if (stopped.exchange(true, std::memory_order_acq_rel)) {
            return;
        }
        AsioErrorCode ec;
        if (acceptor) {
            acceptor->close(ec);
        }
        std::vector<std::shared_ptr<TcpConnection>> snapshot;
        {
            std::lock_guard<std::mutex> lock{connMutex};
            snapshot = conns;
        }
        for (auto& conn : snapshot) {
            if (conn) {
                conn->abort();
            }
        }
    }
};

namespace {

/// accept 循环: 每条连接起一个协程跑 handler, handler 返回即关连接
asio::awaitable<void> acceptLoop(std::shared_ptr<TcpServer::Impl> impl) {
    while (!impl->stopped.load(std::memory_order_acquire)) {
        asio::ip::tcp::socket socket(impl->executor);
        utilxx_base::AsioErrorCode ec;
        co_await impl->acceptor->async_accept(
            socket,
            asio::redirect_error(asio::use_awaitable, ec)
        );
        if (impl->stopped.load(std::memory_order_acquire)) {
            utilxx_base::AsioErrorCode ignored;
            socket.close(ignored);
            break;
        }
        if (ec) {
            // operation_aborted = 正在停; 其它错误记一条日志后继续监听
            if (ec == asio::error::operation_aborted) {
                break;
            }
            XX_LOGW("[tcp] accept 失败: {}", ec.message());
            continue;
        }
        if (impl->handler == nullptr) {
            utilxx_base::AsioErrorCode ignored;
            socket.close(ignored);
            continue;
        }
        if (impl->active.load(std::memory_order_relaxed) >= impl->config.maxConnections) {
            // 到上限就不建对象: 直接关掉这条, 由客户端决定是否重试
            XX_LOGW("[tcp] 连接数已到上限 {}, 拒绝新连接", impl->config.maxConnections);
            utilxx_base::AsioErrorCode ignored;
            socket.close(ignored);
            continue;
        }
        utilxx_base::AsioErrorCode optEc;
        socket.set_option(asio::ip::tcp::no_delay(true), optEc);
        auto conn = TcpConnection::adopt(std::move(socket), impl->config.connection);
        {
            std::lock_guard<std::mutex> lock{impl->connMutex};
            impl->conns.push_back(conn);
        }
        impl->active.fetch_add(1, std::memory_order_relaxed);
        // handler 自己决定怎么读: 返回即关连接
        asio::co_spawn(
            impl->executor,
            [keep = impl, conn]() -> asio::awaitable<void> {
                try {
                    co_await keep->handler(conn);
                } catch (const std::exception& e) {
                    XX_LOGW("[tcp] 连接处理异常: {}", e.what());
                } catch (...) {
                    XX_LOGW("[tcp] 连接处理未知异常");
                }
                conn->abort();
                keep->forget(conn);
                co_return;
            }(),
            asio::detached
        );
    }
    co_return;
}

} // namespace

TcpServer::TcpServer(Config config, Handler handler) :
    impl_(std::make_shared<Impl>()) {
    impl_->config  = std::move(config);
    impl_->handler = std::move(handler);
}

TcpServer::~TcpServer() {
    stop();
    if (impl_ && impl_->ownedIo) {
        if (impl_->ownedThread && impl_->ownedThread->joinable()) {
            impl_->ownedThread->join();
        }
    }
}

std::expected<void, std::string> TcpServer::startAsync(asio::any_io_executor executor) {
    if (!impl_ || impl_->executor) {
        return std::unexpected(std::string{"server already started"});
    }
    impl_->executor = std::move(executor);
    AsioErrorCode ec;
    auto          address = asio::ip::make_address(impl_->config.address, ec);
    if (ec) {
        return std::unexpected("invalid listen address: " + ec.message());
    }
    impl_->acceptor = asio::ip::tcp::acceptor(impl_->executor);
    impl_->acceptor->open(asio::ip::tcp::v4(), ec);
    if (ec) {
        return std::unexpected(ec.message());
    }
    impl_->acceptor->set_option(asio::socket_base::reuse_address(true), ec);
    impl_->acceptor->bind(asio::ip::tcp::endpoint(address, impl_->config.port), ec);
    if (ec) {
        return std::unexpected(ec.message());
    }
    impl_->acceptor->listen(impl_->config.backlog, ec);
    if (ec) {
        return std::unexpected(ec.message());
    }
    AsioErrorCode epEc;
    const auto    ep = impl_->acceptor->local_endpoint(epEc);
    if (!epEc) {
        impl_->boundPort    = ep.port();
        impl_->boundAddress = ep.address().to_string();
    }
    asio::co_spawn(impl_->executor, acceptLoop(impl_), asio::detached);
    return std::expected<void, std::string>{};
}

std::expected<void, std::string> TcpServer::start() {
    if (!impl_) {
        return std::unexpected(std::string{"server released"});
    }
    impl_->ownedIo = std::make_unique<asio::io_context>();
    auto started   = startAsync(impl_->ownedIo->get_executor());
    if (!started) {
        impl_->ownedIo.reset();
        return started;
    }
    // accept 循环是 co_spawn 出来的: 有它在, run() 就一直活着, 直到 stop() 关掉 acceptor
    impl_->ownedThread = std::make_unique<std::thread>([this]() {
        impl_->ownedIo->run();
    });
    return std::expected<void, std::string>{};
}

void TcpServer::stop() {
    auto impl = impl_;
    if (!impl) {
        return;
    }
    if (impl->executor) {
        // 跨线程: 投递到 executor 上关 acceptor / 断连接
        asio::post(impl->executor, [impl]() {
            impl->doStop();
        });
        return;
    }
    impl->doStop();
}

uint16_t TcpServer::port() const noexcept {
    return impl_ ? impl_->boundPort : 0;
}

std::string TcpServer::address() const {
    return impl_ ? impl_->boundAddress : std::string{};
}

size_t TcpServer::activeConnections() const noexcept {
    return impl_ ? impl_->active.load(std::memory_order_relaxed) : 0;
}

bool TcpServer::isStopped() const noexcept {
    return impl_ ? impl_->stopped.load(std::memory_order_acquire) : true;
}

} // namespace utilxx
