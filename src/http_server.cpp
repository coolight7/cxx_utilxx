#include "utilxx/http_server.h"
#include "utilxx_base/asio_error.h"
#include "utilxx/http_client.h"
#include <algorithm>
#include <array>

namespace utilxx {

int httpMethodIndex(boost::beast::http::verb v) noexcept {
    switch (v) {
        case boost::beast::http::verb::get:
            return 0;
        case boost::beast::http::verb::head:
            return 1;
        case boost::beast::http::verb::post:
            return 2;
        case boost::beast::http::verb::put:
            return 3;
        case boost::beast::http::verb::delete_:
            return 4;
        case boost::beast::http::verb::connect:
            return 5;
        case boost::beast::http::verb::options:
            return 6;
        case boost::beast::http::verb::trace:
            return 7;
        case boost::beast::http::verb::patch:
            return 8;
        default:
            return -1;
    }
}

std::string_view httpMethodName(int methodIdx) noexcept {
    static constexpr std::array<std::string_view, 9>
        names{"GET", "HEAD", "POST", "PUT", "DELETE", "CONNECT", "OPTIONS", "TRACE", "PATCH"};
    if (methodIdx < 0 || methodIdx >= static_cast<int>(names.size())) {
        return "UNKNOWN";
    }
    return names[static_cast<size_t>(methodIdx)];
}

std::string_view requestPath(std::string_view target) noexcept {
    // 兼容 absolute-form 请求 (代理风格, RFC 7230 §5.3.2):
    // "GET http://host:port/path?q=1 HTTP/1.1" → "/path"
    if (target.starts_with("http://") || target.starts_with("https://")) {
        auto schemeEnd = target.find("://");
        auto pathStart = target.find('/', schemeEnd + 3);
        if (pathStart == std::string_view::npos) {
            return "/";
        }
        target = target.substr(pathStart);
    }
    // 去除 query string; 容忍非法携带的 fragment (请求目标中不应出现 '#', 但防御性处理)
    auto q = target.find_first_of("?#");
    return q == std::string_view::npos ? target : target.substr(0, q);
}

std::string formatHttpDate(std::time_t t) noexcept {
    char buf[64];
#if XX_IS_WIN_D
    std::tm tm;
    gmtime_s(&tm, &t);
    std::strftime(buf, sizeof(buf), "%a, %d %b %Y %H:%M:%S GMT", &tm);
#else
    std::tm tm;
    gmtime_r(&t, &tm);
    std::strftime(buf, sizeof(buf), "%a, %d %b %Y %H:%M:%S GMT", &tm);
#endif
    return buf;
}

namespace {

/// 解析监听地址: 优先按 IP 字面量解析; 主机名 (如 "localhost") 走 DNS 解析取首个结果,
/// 避免 make_address 直接抛异常导致服务无法启动
asio::ip::address resolveBindAddress(const std::string& address) {
    utilxx_base::AsioErrorCode ec;
    auto                     addr = asio::ip::make_address(address, ec);
    if (!ec) {
        return addr;
    }
    asio::io_context         ctx;
    asio::ip::tcp::resolver  resolver(ctx);
    utilxx_base::AsioErrorCode resolveEc;
    auto                     results = resolver.resolve(address, "0", resolveEc);
    if (resolveEc || results.empty()) {
        throw std::runtime_error{
            fmt::format("[server] invalid bind address: {} ({})", address, resolveEc.message())
        };
    }
    return results.begin()->endpoint().address();
}

/// 按扩展名猜 Content-Type (只看最后一段扩展名, 大小写不敏感)
///
/// 只收录本库实际会遇到的常见类型; 猜不到给空串 (调用方回 octet-stream)。
std::string_view guessContentType(std::string_view filePath) {
    const auto dot = filePath.rfind('.');
    if (dot == std::string_view::npos) {
        return {};
    }
    auto ext = filePath.substr(dot + 1);
    std::string lower;
    lower.reserve(ext.size());
    for (const char ch : ext) {
        lower.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(ch))));
    }
    if (lower == "mp3") return "audio/mpeg";
    if (lower == "flac") return "audio/flac";
    if (lower == "m4a" || lower == "mp4") return "audio/mp4";
    if (lower == "aac") return "audio/aac";
    if (lower == "wav") return "audio/wav";
    if (lower == "ogg" || lower == "opus") return "audio/ogg";
    if (lower == "webm") return "video/webm";
    if (lower == "mkv") return "video/x-matroska";
    if (lower == "ts") return "video/mp2t";
    if (lower == "m3u8") return "application/vnd.apple.mpegurl";
    if (lower == "jpg" || lower == "jpeg") return "image/jpeg";
    if (lower == "png") return "image/png";
    if (lower == "gif") return "image/gif";
    if (lower == "webp") return "image/webp";
    if (lower == "svg") return "image/svg+xml";
    if (lower == "json") return "application/json";
    if (lower == "html" || lower == "htm") return "text/html; charset=utf-8";
    if (lower == "css") return "text/css; charset=utf-8";
    if (lower == "js") return "text/javascript; charset=utf-8";
    if (lower == "md") return "text/markdown; charset=utf-8";
    if (lower == "txt" || lower == "lrc" || lower == "srt" || lower == "ass") {
        return "text/plain; charset=utf-8";
    }
    return {};
}

} // namespace

HttpServer::HttpServer(Config config) :
    config_(std::move(config)) {
    router_ = std::make_unique<Router>();
}

HttpServer::~HttpServer() {
    stop();
    // 挂在 io_context 上的协程帧在 `~io_context` 时才销毁, 而它们的清理回调
    // (`serveTcp` 的 `Untracker`) 会回调 `untrackConnection` 去碰 `connMutex_` /
    // `trackedConns_`。这两个成员声明在 `workers_` 之后, 默认析构会先把它们拆掉,
    // 于是回调去用一个已释放的 mutex/vector (debug STL 报 "vector erase iterator
    // outside range", release 下是未定义行为)。
    //
    // 所以在这里先把 acceptor 与 workers_ 释放掉: 协程帧在这一步销毁完成, 其余成员
    // 仍然存活。前提与停止服务相同 —— 持有 `start()` 的线程必须先返回 (与 stop() 的
    // 调用者承担同样的责任)。
    acceptor_.reset();
    workers_.clear();
}

uint16_t HttpServer::port() const noexcept {
    if (acceptor_ && acceptor_->is_open()) {
        utilxx_base::AsioErrorCode ec;
        auto                     ep = acceptor_->local_endpoint(ec);
        if (!ec) {
            return ep.port();
        }
    }
    return 0;
}

void HttpServer::start() {
    if (stopped_) {
        return;
    }
    stopped_ = false;

    using tcp = asio::ip::tcp;

    // Create workers (each has its own io_context — zero-lock isolation)
    unsigned threadCount = config_.ioThreads;
    if (threadCount == 0) {
        threadCount = std::thread::hardware_concurrency();
    }
    if (threadCount == 0) {
        threadCount = 1;
    }

    workers_.reserve(threadCount);
    for (unsigned i = 0; i < threadCount; ++i) {
        auto w = std::make_unique<Worker>();
        w->workGuard.emplace(asio::make_work_guard(w->ioCtx));
        workers_.push_back(std::move(w));
    }

    auto& mainCtx = workers_[0]->ioCtx;

    // Acceptor — runs on the first worker's io_context
    auto const    address = resolveBindAddress(config_.address);
    tcp::endpoint endpoint(address, config_.port);
    acceptor_ = std::make_unique<tcp::acceptor>(mainCtx);
    acceptor_->open(endpoint.protocol());
    acceptor_->set_option(tcp::acceptor::reuse_address(true));
    acceptor_->bind(endpoint);
    acceptor_->listen(asio::socket_base::max_listen_connections);

    // Spawn listener coroutine on first worker's io_context
    asio::co_spawn(mainCtx, acceptLoop(), asio::detached);

    XX_OUT("[server] Listening on {}:{}", config_.address, port());

    // Start worker threads — each runs its own io_context
    for (unsigned i = 0; i < threadCount; ++i) {
        workers_[i]->thread = std::thread([this, i]() {
            workers_[i]->ioCtx.run();
        });
    }

    // Block until all threads finish
    for (auto& w : workers_) {
        if (w->thread.joinable()) {
            w->thread.join();
        }
    }
}

void HttpServer::stop() {
    bool expected = false;
    if (!stopped_.compare_exchange_strong(expected, true)) {
        return;
    }
    utilxx_base::AsioErrorCode ec;
    if (acceptor_ && acceptor_->is_open()) {
        acceptor_->cancel(ec);
        acceptor_->close(ec);
    }
    // 已建立的连接也要关：客户端会复用同一条 socket，只关 acceptor 的话
    // 正在等下一个请求的会话还能继续回答（服务“停不掉”）
    closeTrackedConnections();
    // Release work guards so io_context::run() can return
    for (auto& w : workers_) {
        if (w->workGuard) {
            w->workGuard->reset();
        }
    }
    // Stop all worker io_contexts — pending async operations are canceled,
    // serve() loops catch operation_aborted and exit cleanly.
    for (auto& w : workers_) {
        w->ioCtx.stop();
    }
    // Wait for all active connections to drain (coroutines finishing cleanup)
    for (int i = 0; i < 500 && activeConnections_.load(std::memory_order_relaxed) > 0; ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(2));
    }
}

void HttpServer::addSseRoute(
    std::string_view                                                           path,
    std::function<asio::awaitable<void>(Request&, std::shared_ptr<SseWriter>)> handler
) {
    sseRoutes_[std::string{path}] = std::move(handler);
}

void HttpServer::addSsePostRoute(
    std::string_view                                                           path,
    std::function<asio::awaitable<void>(Request&, std::shared_ptr<SseWriter>)> handler
) {
    ssePostRoutes_[std::string{path}] = std::move(handler);
}

void HttpServer::enableWebSocket(std::string_view path, WsHandler handler) {
    wsRoutes_[std::string{path}] = std::move(handler);
}

void HttpServer::enableFileRoute(
    std::string_view path,
    std::string_view filePath,
    std::string_view contentType
) {
    FileRouteEntry entry;
    entry.path        = std::string{path};
    entry.filePath    = std::string{filePath};
    entry.contentType = contentType.empty()
                            ? std::string{guessContentType(filePath)}
                            : std::string{contentType};
    // 同一路径重复注册: 后来的覆盖前面的 (与 wsRoutes_ 的行为一致)
    for (auto& existing : fileRoutes_) {
        if (existing.path == entry.path) {
            existing = std::move(entry);
            return;
        }
    }
    fileRoutes_.push_back(std::move(entry));
}

void HttpServer::clearFileRoutes() {
    fileRoutes_.clear();
}

void HttpServer::setFallbackHandler(FallbackHandler handler) {
    if (!handler) {
        fallback_.reset();
        return;
    }
    fallback_ = std::make_shared<FallbackHandler>(std::move(handler));
}

void HttpServer::enableWebSocketAny(WsRequestHandler handler) {
    if (!handler) {
        wsAny_.reset();
        return;
    }
    wsAny_ = std::make_shared<WsRequestHandler>(std::move(handler));
}

void HttpServer::startAsync(asio::any_io_executor executor) {
    if (stopped_) {
        return;
    }
    stopped_   = false;
    asyncMode_ = true;

    using tcp = asio::ip::tcp;

    auto const    address = resolveBindAddress(config_.address);
    tcp::endpoint endpoint(address, config_.port);
    acceptor_ = std::make_unique<tcp::acceptor>(executor);
    acceptor_->open(endpoint.protocol());
    acceptor_->set_option(tcp::acceptor::reuse_address(true));
    acceptor_->bind(endpoint);
    acceptor_->listen(asio::socket_base::max_listen_connections);

    asio::co_spawn(executor, acceptLoopAsync(), asio::detached);

    XX_OUT("[server] Listening on {}:{} (async mode)", config_.address, port());
}

void HttpServer::trackConnection(const std::shared_ptr<boost::beast::tcp_stream>& stream) {
    std::lock_guard<std::mutex> lock{connMutex_};
    // 顺手清掉已经结束的项: 连接表只会随 accept 增长，不清理会一直变大
    trackedConns_.erase(
        std::remove_if(
            trackedConns_.begin(),
            trackedConns_.end(),
            [](const std::weak_ptr<boost::beast::tcp_stream>& item) { return item.expired(); }
        ),
        trackedConns_.end()
    );
    trackedConns_.push_back(stream);
}

void HttpServer::untrackConnection(const std::shared_ptr<boost::beast::tcp_stream>& stream) {
    std::lock_guard<std::mutex> lock{connMutex_};
    trackedConns_.erase(
        std::remove_if(
            trackedConns_.begin(),
            trackedConns_.end(),
            [&](const std::weak_ptr<boost::beast::tcp_stream>& item) {
                const auto locked = item.lock();
                return !locked || locked == stream;
            }
        ),
        trackedConns_.end()
    );
}

void HttpServer::closeTrackedConnections() {
    std::vector<std::shared_ptr<boost::beast::tcp_stream>> closing;
    {
        std::lock_guard<std::mutex> lock{connMutex_};
        closing.reserve(trackedConns_.size());
        for (const auto& item : trackedConns_) {
            if (auto locked = item.lock()) {
                closing.push_back(std::move(locked));
            }
        }
        trackedConns_.clear();
    }
    for (const auto& stream : closing) {
        utilxx_base::AsioErrorCode ec;
        auto&                     socket = boost::beast::get_lowest_layer(*stream).socket();
        // 先取消挂起的收发再关（与 TcpConnection::abort 同理：带挂起读的 close
        // 在 Windows 上会把连接重置，已写出的数据可能与客户端无缘）
        socket.cancel(ec);
        socket.close(ec);
    }
}

asio::awaitable<void> HttpServer::serveTcp(std::shared_ptr<boost::beast::tcp_stream> stream) {
    ConnectionGuard guard{activeConnections_};
    // stop() 会关掉这条连接的 socket，协程随之苏醒；此时服务对象可能已被销毁，
    // 所以整条连接期间要抱住它（栈上构造的对象拿不到，保持原行为）。
    const std::shared_ptr<HttpServer> keepAlive = weak_from_this().lock();
    (void)keepAlive;
    trackConnection(stream);
    // 协程无论怎么退出都要从跟踪表里去掉，否则表会越积越多
    struct Untracker {
        HttpServer*                              server;
        std::shared_ptr<boost::beast::tcp_stream> stream;
        ~Untracker() {
            server->untrackConnection(stream);
        }
    } untracker{this, stream};
    // 接受完就 stop() 的边角情况: 不要再处理请求
    if (stopped_) {
        co_return;
    }
    // 捕获异常, 避免客户端在读写期间断开时异常逃逸 detached 协程 → terminate;
    // 取消/中断是预期行为 (见 utilxx::CanceledException 与主程序注册的控制流
    // 异常识别 utilxx_base::setExtraExceptionClassifier), 静默返回
    try {
        co_await serve(*stream);
    } catch (const utilxx::CanceledException&) {
        // 取消: 连接终止是预期行为, 静默返回
    } catch (const utilxx_base::AsioSystemError& e) {
        if (e.code() != asio::error::operation_aborted) {
            XX_LOGE("[server] TCP error: {}", utilxx_base::autoTryConvertToUtf8(e.what()));
        }
    } catch (...) {
        // 其余异常: 经统一分类器判定控制流 (取消/中断) 与错误;
        // 控制流属预期行为静默返回, 其余记录
        auto info = utilxx_base::classifyCurrentException();
        if (!info.isControlFlow) {
            XX_LOGE("[server] TCP serve error: {}", info.errInfo);
        }
    }
}

asio::awaitable<void> HttpServer::acceptLoop() {
    using tcp     = asio::ip::tcp;
    const std::shared_ptr<HttpServer> keepAlive = weak_from_this().lock();
    (void)keepAlive;
    auto executor = co_await asio::this_coro::executor;
    while (!stopped_) {
        utilxx_base::AsioErrorCode ec;
        tcp::socket              socket
            = co_await acceptor_->async_accept(asio::redirect_error(asio::use_awaitable, ec));
        if (ec) {
            if (ec == asio::error::operation_aborted || ec == asio::error::connection_aborted) {
                co_return;
            }
            if (ec == asio::error::no_descriptors) {
                XX_LOGW("[server] Accept: too many open files, retrying in 100ms");
                asio::steady_timer timer(executor, std::chrono::milliseconds(100));
                co_await timer.async_wait(asio::redirect_error(asio::use_awaitable, ec));
                continue;
            }
            XX_LOGE("[server] Accept error: {}", ec.message());
            asio::steady_timer timer(executor, std::chrono::milliseconds(10));
            co_await timer.async_wait(asio::redirect_error(asio::use_awaitable, ec));
            if (stopped_) {
                co_return;
            }
            continue;
        }

        utilxx_base::AsioErrorCode tcpEc;
        socket.set_option(asio::ip::tcp::no_delay(true), tcpEc);

        if (activeConnections_.load(std::memory_order_relaxed) >= config_.maxConnections) {
            utilxx_base::AsioErrorCode closeEc;
            socket.shutdown(tcp::socket::shutdown_both, closeEc);
            socket.close(closeEc);
            XX_LOGW("[server] Max connections reached, dropping client");
            continue;
        }

        activeConnections_.fetch_add(1, std::memory_order_relaxed);

        size_t idx          = nextWorker_++ % workers_.size();
        auto&  targetWorker = *workers_[idx];

        // 用 ec 重载: stop() 与本处存在竞态, acceptor 可能已被关闭,
        // 抛异常版本会使异常逃逸 detached 协程导致 terminate
        utilxx_base::AsioErrorCode epEc;
        auto                     localEp = acceptor_->local_endpoint(epEc);
        if (epEc) {
            activeConnections_.fetch_sub(1, std::memory_order_relaxed);
            utilxx_base::AsioErrorCode closeEc;
            socket.shutdown(tcp::socket::shutdown_both, closeEc);
            socket.close(closeEc);
            if (stopped_) {
                co_return;
            }
            continue;
        }
        tcp::socket workerSocket(targetWorker.ioCtx);
        workerSocket.assign(localEp.protocol(), socket.release());

        auto stream = std::make_shared<boost::beast::tcp_stream>(std::move(workerSocket));
        asio::co_spawn(targetWorker.ioCtx, serveTcp(std::move(stream)), asio::detached);
    }
    co_return;
}

asio::awaitable<void> HttpServer::acceptLoopAsync() {
    using tcp     = asio::ip::tcp;
    const std::shared_ptr<HttpServer> keepAlive = weak_from_this().lock();
    (void)keepAlive;
    auto executor = co_await asio::this_coro::executor;
    while (!stopped_) {
        utilxx_base::AsioErrorCode ec;
        tcp::socket              socket
            = co_await acceptor_->async_accept(asio::redirect_error(asio::use_awaitable, ec));
        if (ec) {
            if (ec == asio::error::operation_aborted || ec == asio::error::connection_aborted) {
                co_return;
            }
            if (ec == asio::error::no_descriptors) {
                XX_LOGW("[server] Accept: too many open files, retrying in 100ms");
                asio::steady_timer timer(executor, std::chrono::milliseconds(100));
                co_await timer.async_wait(asio::redirect_error(asio::use_awaitable, ec));
                continue;
            }
            XX_LOGE("[server] Accept error: {}", ec.message());
            asio::steady_timer timer(executor, std::chrono::milliseconds(10));
            co_await timer.async_wait(asio::redirect_error(asio::use_awaitable, ec));
            if (stopped_) {
                co_return;
            }
            continue;
        }

        utilxx_base::AsioErrorCode tcpEc;
        socket.set_option(asio::ip::tcp::no_delay(true), tcpEc);

        if (activeConnections_.load(std::memory_order_relaxed) >= config_.maxConnections) {
            utilxx_base::AsioErrorCode closeEc;
            socket.shutdown(tcp::socket::shutdown_both, closeEc);
            socket.close(closeEc);
            XX_LOGW("[server] Max connections reached, dropping client");
            continue;
        }

        activeConnections_.fetch_add(1, std::memory_order_relaxed);

        auto stream = std::make_shared<boost::beast::tcp_stream>(std::move(socket));
        asio::co_spawn(executor, serveTcp(std::move(stream)), asio::detached);
    }
    co_return;
}

void HttpServer::fillError(
    Response&                  resp,
    unsigned                   version,
    boost::beast::http::status status,
    std::string_view           message
) {
    resp.version(version);
    resp.result(status);
    resp.set(boost::beast::http::field::content_type, "text/plain");
    resp.body() = std::string(message);
    resp.prepare_payload();
    resp.keep_alive(false);
}

} // namespace utilxx
