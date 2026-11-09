#pragma once

#include "utilxx_base/asio_error.h"
#include "utilxx_base/exception.h"
#include "utilxx/export.h"
#include "utilxx_base/log.h"
#include "utilxx/router.h"
#include "utilxx_base/string_util.h"
#include "utilxx_base/version.h"
#include "asio/awaitable.hpp"
#include "asio/cancel_after.hpp"
#include "asio/co_spawn.hpp"
#include "asio/detached.hpp"
#include "asio/redirect_error.hpp"
#include "asio/signal_set.hpp"
#include "asio/use_awaitable.hpp"
#include <atomic>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/version.hpp>
#include <boost/beast/websocket.hpp>
#include <charconv>
#include <chrono>
#include <ctime>
#include <fstream>
#include <functional>
#include <list>
#include <memory>
#include <optional>
#include <string>
#include <thread>
#include <vector>

namespace utilxx {

/// 由 HTTP method 枚举取路由索引 (0-8 对应标准方法)
UTILXX_API int httpMethodIndex(boost::beast::http::verb v) noexcept;

/// 由路由索引取 HTTP method 名称 (0-8); 非法索引返回 "UNKNOWN"
UTILXX_API std::string_view httpMethodName(int methodIdx) noexcept;

/// 去掉请求目标中的 query 部分, 仅返回路径
UTILXX_API std::string_view requestPath(std::string_view target) noexcept;

/// 将 time_point 格式化为 RFC 7231 IMF-fixdate 字符串
/// (如 "Sun, 06 Nov 1994 08:49:37 GMT")
UTILXX_API std::string formatHttpDate(std::time_t t) noexcept;

// ---------------------------------------------------------------------------
// HttpServer —— 异步 HTTP/WebSocket/SSE 服务器
// ---------------------------------------------------------------------------

class UTILXX_API HttpServer {
public:

    using Request  = boost::beast::http::request<boost::beast::http::string_body>;
    using Response = boost::beast::http::response<boost::beast::http::string_body>;
    using Handler
        = std::function<asio::awaitable<void>(Request&, Response&, std::string_view matched_path)>;
    using Router = XXRouter<Handler, 9>;

    using WsStream  = boost::beast::websocket::stream<boost::beast::tcp_stream>;
    using WsHandler = std::function<asio::awaitable<void>(WsStream&)>;

    /// 带握手请求的 WebSocket 处理器（任意路径升级用）
    ///
    /// 比 [WsHandler] 多拿到握手请求：路径、头、子协议都从里面读。
    using WsRequestHandler
        = std::function<asio::awaitable<void>(WsStream&, const Request&)>;

    /// 兜底处理器：路由没命中时调用（插件网络用它把请求交给插件自己回答）
    ///
    /// 参数：请求、响应、去 query 后的路径、对端地址（`1.2.3.4:5678`）。
    /// 置了兜底处理器就不会再回 404 / 405，响应由处理器自己填。
    using FallbackHandler = std::function<asio::awaitable<void>(
        Request&,
        Response&,
        std::string_view path,
        std::string_view peer
    )>;

    /// 流式 SSE 连接 — 初始响应头发送后, handler 可持有本对象持续推送事件
    class SseWriter {
    public:

        virtual ~SseWriter() = default;
        /// 写一条 SSE 事件 (格式化为 "event: ...\ndata: ...\n\n")
        virtual asio::awaitable<bool> writeEvent(std::string_view event, std::string_view data) = 0;
        /// 写原始数据块 (必须是合法 SSE 帧格式)
        virtual asio::awaitable<bool> writeChunk(std::string_view chunk) = 0;
        /// 写一个完整 (非 SSE) HTTP 响应 —— 用于从流式路由返回普通 JSON-RPC
        /// 错误/结果 (如非法的 subscriptions/listen 参数)。调用后不得再使用该 writer。
        virtual asio::awaitable<bool> writeResponse(
            boost::beast::http::status status,
            std::string_view           contentType,
            std::string_view           body
        ) = 0;
        /// 优雅关闭 SSE 流
        virtual asio::awaitable<void> close() = 0;
    };

    struct Config {
        std::string          address   = "0.0.0.0";
        uint16_t             port      = 8080;
        unsigned             ioThreads = 0; // 0 = hardware_concurrency
        std::chrono::seconds requestTimeout{30};

        /// SSE 写入超时: 两次 SSE event 推送之间的最大间隔 (默认 120s, 适应长耗时推送)
        std::chrono::seconds sseWriteTimeout{120};

        size_t maxConnections = 8192;

        /// 单个 keep-alive 连接的最大请求数 (0 = 无限制); 防止恶意客户端永久占用连接
        size_t maxRequestsPerConnection = 1024;

        // DoS 防护: 拒绝超大请求头/请求体的请求
        uint32_t maxHeaderSize  = 8192;            // 默认请求头上限 8 KB
        uint64_t maxRequestBody = 8 * 1024 * 1024; // 默认请求体上限 8 MB

        // 逐请求访问日志 (release 下关闭可静默提升性能)
        bool accessLogEnabled = true;
    };

    explicit HttpServer(Config config);

    HttpServer(const HttpServer&)            = delete;
    HttpServer& operator=(const HttpServer&) = delete;

    ~HttpServer();

    Router& router() {
        return *router_;
    }

    const Config& config() const noexcept {
        return config_;
    }

    uint16_t port() const noexcept;

    size_t activeConnections() const noexcept {
        return activeConnections_.load(std::memory_order_relaxed);
    }

    // -----------------------------------------------------------------------
    // 启动 / 停止
    // -----------------------------------------------------------------------

    /// 阻塞调用线程直到服务停止
    void start();

    /// 通知服务停止; 任意线程可调用
    void stop();

    bool isStopped() const noexcept {
        return stopped_;
    }

    /// 注册流式 SSE 处理器 (GET)。与普通处理器不同, SSE 处理器收到
    /// SseWriter, 可增量推送事件。
    void addSseRoute(
        std::string_view                                                           path,
        std::function<asio::awaitable<void>(Request&, std::shared_ptr<SseWriter>)> handler
    );

    /// 注册 POST 流式 SSE 处理器 (如 MCP `subscriptions/listen`)。
    /// 响应是一个绑定到该请求的长连接 SSE 流, 优先于同路径的普通 router 处理器。
    void addSsePostRoute(
        std::string_view                                                           path,
        std::function<asio::awaitable<void>(Request&, std::shared_ptr<SseWriter>)> handler
    );

    /// 注册 WebSocket 端点。客户端向该路径发送带 Upgrade: websocket 的 GET
    /// 请求时连接被升级, 随后以 websocket 流调用该 handler。
    void enableWebSocket(std::string_view path, WsHandler handler);

    /// 注册任意路径的 WebSocket 升级（没命中 `enableWebSocket` 的路径都交给它）
    ///
    /// 用处：调用方自己按请求里的路径 / 头做分流（插件的 `ws.listen` 就是这样）。
    void enableWebSocketAny(WsRequestHandler handler);

    /// 注册静态文件路由（`GET` / `HEAD`，**精确匹配**路径；已带 query 的请求按去 query 后的路径比）
    ///
    /// - 命中后由服务器直接回 200 / 206（单段 Range）/ 416，**不进 router**；
    /// - body 按 64 KiB 分块从磁盘读，不把文件读进内存（适合音频/视频这类大文件）；
    /// - `contentType` 为空时按扩展名猜（猜不到给 `application/octet-stream`）；
    /// - 响应一律 `Connection: close`：大文件传输中途可能被客户端断开，不复用连接更干净。
    ///
    /// 用处：把播放器打不开的东西变成普通 `http://` 地址（远程数据 / 私有协议 / 转码产物）。
    void enableFileRoute(
        std::string_view path,
        std::string_view filePath,
        std::string_view contentType = {}
    );

    /// 清掉全部静态文件路由
    void clearFileRoutes();

    /// 置兜底处理器（未注册路由时的请求都给它）；传空函数对象 = 取消
    void setFallbackHandler(FallbackHandler handler);

    /// 在指定 executor 上启动 accept 循环而不创建线程。
    /// 调用方负责运行 io_context。适用于单线程服务模式 (如 agent 服务)。
    void startAsync(asio::any_io_executor executor);

private:

    // -----------------------------------------------------------------------
    // SseWriter 实现 (基于 TCP stream)
    // -----------------------------------------------------------------------
    template<typename Stream>
    class SseWriterImpl : public SseWriter {
        Stream&              stream_;
        std::chrono::seconds timeout_;
        bool                 headerSent_   = false;
        bool                 responseSent_ = false; // writeResponse 已发送完整响应

    public:

        explicit SseWriterImpl(Stream& s, std::chrono::seconds t) :
            stream_(s),
            timeout_(t) {}

        asio::awaitable<bool> writeEvent(std::string_view event, std::string_view data) override {
            std::string chunk;
            if (!event.empty()) {
                chunk += fmt::format("event: {}\n", event);
            }
            chunk += fmt::format("data: {}\n\n", data);
            co_return co_await doWrite(chunk);
        }

        asio::awaitable<bool> writeChunk(std::string_view chunk) override {
            co_return co_await doWrite(chunk);
        }

        asio::awaitable<bool> writeResponse(
            boost::beast::http::status status,
            std::string_view           contentType,
            std::string_view           body
        ) override {
            namespace http = boost::beast::http;
            co_return co_await utilxx_base::catchErrorAsync<bool>(
                [&]() -> asio::awaitable<bool> {
                    // 已发送 SSE 头或完整响应后不能再写完整 HTTP 响应:
                    // 会破坏协议 (双响应/流帧错位), 直接返回失败
                    if (headerSent_ || responseSent_) {
                        co_return false;
                    }
                    responseSent_ = true;
                    http::response<http::string_body> resp;
                    resp.version(11);
                    resp.result(status);
                    resp.set(http::field::content_type, contentType);
                    resp.set(http::field::connection, "close");
                    resp.body() = std::string(body);
                    resp.prepare_payload();
                    co_await http::async_write(
                        stream_,
                        resp,
                        asio::cancel_after(timeout_, asio::use_awaitable)
                    );
                    co_return true;
                },
                [&](std::string errinfo) -> asio::awaitable<bool> {
                    XX_LOGE("[sse] write response error: {}", errinfo);
                    co_return false;
                }
                // 不传 onRethrow: 取消类异常保持抛出 (调用方约定),
                // 避免取消被吞掉后 SSE 流无法终止
            );
        }

        asio::awaitable<void> close() override {
            // SSE 流已开始 (header 已发) 且未发送完整响应时, 写 chunked 终止帧,
            // 客户端解析器才能正确结束 (否则 keep-alive 连接会一直挂起)
            if (headerSent_ && !responseSent_) {
                utilxx_base::AsioErrorCode ec;
                co_await asio::async_write(
                    stream_,
                    asio::buffer(std::string_view{"0\r\n\r\n"}),
                    asio::cancel_after(timeout_, asio::redirect_error(asio::use_awaitable, ec))
                );
            }
            utilxx_base::AsioErrorCode ec;
            boost::beast::get_lowest_layer(stream_).socket().shutdown(
                asio::ip::tcp::socket::shutdown_send,
                ec
            );
            co_return;
        }

    private:

        asio::awaitable<bool> doWrite(std::string_view data) {
            co_return co_await utilxx_base::catchErrorAsync<bool>(
                [&]() -> asio::awaitable<bool> {
                    if (!headerSent_) {
                        co_return co_await writeWithHeader(data);
                    }
                    // 已声明 Transfer-Encoding: chunked, 后续数据必须按 chunk 帧格式写:
                    // <hex-size>\r\n<data>\r\n, 否则客户端解析器无法识别
                    std::string frame = fmt::format("{:x}\r\n{}\r\n", data.size(), data);
                    co_await asio::async_write(
                        stream_,
                        asio::buffer(frame),
                        asio::cancel_after(timeout_, asio::use_awaitable)
                    );
                    co_return true;
                },
                [&](std::string errinfo) -> asio::awaitable<bool> {
                    XX_LOGE("[sse] write error: {}", errinfo);
                    co_return false;
                }
                // 不传 onRethrow: 取消类异常保持抛出 (调用方约定)
            );
        }

        asio::awaitable<bool> writeWithHeader(std::string_view data) {
            namespace http = boost::beast::http;
            headerSent_    = true;
            // 只写响应头 (声明 chunked), 不能使用 http::async_write 写完整响应:
            // 它对 chunked 响应会自动追加终止帧 (0\r\n\r\n), 导致首个事件后流即结束,
            // 后续 writeEvent 无法送达客户端
            http::response<http::empty_body> resp;
            resp.version(11);
            resp.result(http::status::ok);
            resp.set(http::field::content_type, "text/event-stream");
            resp.set(http::field::cache_control, "no-cache");
            resp.set(http::field::connection, "keep-alive");
            resp.set("X-Accel-Buffering", "no");
            resp.chunked(true);
            http::response_serializer<http::empty_body> sr{resp};
            co_await http::async_write_header(
                stream_,
                sr,
                asio::cancel_after(timeout_, asio::use_awaitable)
            );
            // 第一个 chunk 帧 (与 doWrite 保持一致)
            std::string frame = fmt::format("{:x}\r\n{}\r\n", data.size(), data);
            co_await asio::async_write(
                stream_,
                asio::buffer(frame),
                asio::cancel_after(timeout_, asio::use_awaitable)
            );
            co_return true;
        }
    };

    // -----------------------------------------------------------------------
    // 活跃连接计数 RAII 守卫 — 即使会话协程抛异常/被取消也保证递减
    // -----------------------------------------------------------------------
    struct ConnectionGuard {
        std::atomic<size_t>& counter;

        explicit ConnectionGuard(std::atomic<size_t>& c) :
            counter(c) {}

        ~ConnectionGuard() {
            counter.fetch_sub(1, std::memory_order_relaxed);
        }

        ConnectionGuard(const ConnectionGuard&)            = delete;
        ConnectionGuard& operator=(const ConnectionGuard&) = delete;
    };

    // -----------------------------------------------------------------------
    // Accept 循环
    // -----------------------------------------------------------------------

    asio::awaitable<void> acceptLoop();

    /// startAsync 模式的 accept 循环 — 所有连接在同一 executor 上服务
    asio::awaitable<void> acceptLoopAsync();

    /// 服务一条 TCP 连接 (成员协程 — 避免悬挂的 lambda 捕获)
    asio::awaitable<void> serveTcp(std::shared_ptr<boost::beast::tcp_stream> stream);

    // -----------------------------------------------------------------------
    // 会话处理器 (模板 — 兼容 tcp_stream)
    // -----------------------------------------------------------------------

    /// 静态文件路由条目 (精确匹配路径)
    struct FileRouteEntry {
        std::string path;
        std::string filePath;
        std::string contentType;
    };

    /// 静态文件路由的实现: 自己写完整响应（头 + 分块 body），返回 true 表示已处理
    ///
    /// - 只支持单段 `Range`（`bytes=a-b` / `bytes=a-`），多段或语法不对时当没有 Range 回 200；
    /// - 起点越界回 416（带 `Content-Range: bytes */总长`）；
    /// - `HEAD` 只写头（Content-Length 保留），不写 body；
    /// - 文件打不开返回 false，调用方继续走 router（最终 404）。
    template<typename Stream>
    asio::awaitable<bool> serveFileRoute(
        Stream&               stream,
        Request&              req,
        Response&             resp,
        const FileRouteEntry& route
    ) {
        namespace http = boost::beast::http;
        std::ifstream file(route.filePath, std::ios::binary);
        if (!file) {
            co_return false;
        }
        file.seekg(0, std::ios::end);
        const auto     endPos = file.tellg();
        const uint64_t total  = endPos > 0 ? static_cast<uint64_t>(endPos) : 0;
        file.seekg(0, std::ios::beg);

        const bool       head   = req.method() == http::verb::head;
        uint64_t         offset = 0;
        uint64_t         length = total;
        http::status     status = http::status::ok;

        auto reply416 = [&]() -> asio::awaitable<bool> {
            resp.version(req.version());
            resp.result(http::status::range_not_satisfiable);
            resp.set(http::field::content_range, fmt::format("bytes */{}", total));
            resp.body().clear();
            resp.keep_alive(false);
            resp.prepare_payload();
            co_await http::async_write(
                stream,
                resp,
                asio::cancel_after(config_.requestTimeout, asio::use_awaitable)
            );
            co_return true;
        };

        const auto rangeHeader = req[http::field::range];
        if (!rangeHeader.empty() && total > 0) {
            std::string_view text{rangeHeader.data(), rangeHeader.size()};
            // 多段 Range 不支持: 按整个文件回 200 (RFC 7233 允许忽略 Range)
            if (text.starts_with("bytes=") && text.find(',') == std::string_view::npos) {
                const auto spec = text.substr(6);
                const auto dash = spec.find('-');
                if (dash != std::string_view::npos) {
                    uint64_t   start = 0;
                    uint64_t   end   = total - 1;
                    const auto head_ = spec.substr(0, dash);
                    bool       ok    = !head_.empty();
                    if (ok) {
                        const auto parsed = std::from_chars(
                            head_.data(),
                            head_.data() + head_.size(),
                            start
                        );
                        ok = parsed.ec == std::errc{};
                    }
                    const auto tail_ = spec.substr(dash + 1);
                    if (ok && !tail_.empty()) {
                        const auto parsed = std::from_chars(
                            tail_.data(),
                            tail_.data() + tail_.size(),
                            end
                        );
                        ok = parsed.ec == std::errc{} && end >= start;
                    }
                    if (ok) {
                        if (start >= total) {
                            co_return co_await reply416();
                        }
                        if (end >= total) {
                            end = total - 1;
                        }
                        offset = start;
                        length = end - start + 1;
                        status = http::status::partial_content;
                    }
                }
            }
        }

        // 记录给调用方 (访问日志 / 统计)
        resp.result(status);

        http::response<http::empty_body> header;
        header.version(req.version());
        header.result(status);
        header.set(http::field::server, utilxx_base::productToken());
        header.set(http::field::date, formatHttpDate(std::time(nullptr)));
        header.set(
            http::field::content_type,
            route.contentType.empty() ? "application/octet-stream" : route.contentType
        );
        header.set(http::field::accept_ranges, "bytes");
        header.set(http::field::content_length, std::to_string(length));
        if (status == http::status::partial_content) {
            header.set(
                http::field::content_range,
                fmt::format("bytes {}-{}/{}", offset, offset + length - 1, total)
            );
        }
        // 大文件传一半客户端跑了很常见: 不复用连接, 免得下次请求解析错位
        header.set(http::field::connection, "close");
        header.keep_alive(false);

        http::response_serializer<http::empty_body> serializer{header};
        co_await http::async_write_header(
            stream,
            serializer,
            asio::cancel_after(config_.requestTimeout, asio::use_awaitable)
        );
        if (head || length == 0) {
            co_return true;
        }

        file.seekg(static_cast<std::streamoff>(offset), std::ios::beg);
        std::vector<char> chunk(64 * 1024);
        uint64_t          remaining = length;
        while (remaining > 0) {
            const auto want = static_cast<std::streamsize>(
                std::min<uint64_t>(remaining, chunk.size())
            );
            file.read(chunk.data(), want);
            const auto got = file.gcount();
            if (got <= 0) {
                break;
            }
            co_await asio::async_write(
                stream,
                asio::buffer(chunk.data(), static_cast<size_t>(got)),
                asio::cancel_after(config_.requestTimeout, asio::use_awaitable)
            );
            remaining -= static_cast<uint64_t>(got);
        }
        co_return true;
    }

    template<typename Stream>
    asio::awaitable<void> serve(Stream stream) {
        namespace http = boost::beast::http;
        utilxx_base::AsioErrorCode ec;

        boost::beast::flat_buffer buffer;
        bool                      keepAlive = false;
        bool                      readError = false;
        std::string               readErrorMsg;
        http::status              readErrorStatus = http::status::bad_request;
        size_t                    requestCount    = 0; // 连接级请求计数 (防永久占用)
        // 对端地址（兜底处理器要告诉调用方请求从哪来）
        std::string peerText;
        {
            utilxx_base::AsioErrorCode peerEc;
            const auto                 endpoint = stream.socket().remote_endpoint(peerEc);
            if (!peerEc) {
                peerText = endpoint.address().to_string() + ":"
                           + std::to_string(endpoint.port());
            }
        }
        // WebSocket 升级后 stream 已被移入 ws stream, 收尾 shutdown 必须跳过
        bool streamMoved = false;

        do {
            // 连接级请求数限制: 防止恶意客户端通过 keep-alive 永久占用连接资源
            if (config_.maxRequestsPerConnection > 0
                && requestCount >= config_.maxRequestsPerConnection) {
                break;
            }
            ++requestCount;

            // 带请求头/请求体大小限制地读取一个请求 (DoS 防护)
            readError = false;
            Request req;
            try {
                http::request_parser<http::string_body> parser;
                parser.header_limit(config_.maxHeaderSize);
                parser.body_limit(config_.maxRequestBody);
                // 先只读头部: 携带 Expect: 100-continue 的客户端 (curl/Go net/http 等)
                // 会等待服务端回复 100 Continue 后才发送 body, 若直接整体读取会阻塞到
                // 客户端超时回退 (甚至永久挂起)
                co_await http::async_read_header(
                    stream,
                    buffer,
                    parser,
                    asio::cancel_after(config_.requestTimeout, asio::use_awaitable)
                );
                auto expectIt = parser.get().find(http::field::expect);
                if (expectIt != parser.get().end()
                    && boost::beast::iequals(expectIt->value(), "100-continue")) {
                    http::response<http::empty_body> continueResp;
                    continueResp.version(parser.get().version());
                    continueResp.result(http::status::continue_);
                    co_await http::async_write(
                        stream,
                        continueResp,
                        asio::cancel_after(std::chrono::seconds{5}, asio::use_awaitable)
                    );
                }
                co_await http::async_read(
                    stream,
                    buffer,
                    parser,
                    asio::cancel_after(config_.requestTimeout, asio::use_awaitable)
                );
                req = parser.release();
            } catch (const utilxx_base::AsioSystemError& e) {
                if (e.code() == http::error::end_of_stream || e.code() == asio::error::eof
                    || e.code() == asio::error::operation_aborted) {
                    break;
                }
                readError    = true;
                readErrorMsg = e.what();
                utilxx_base::autoConvertToUtf8(readErrorMsg);
                if (e.code() == http::error::body_limit) {
                    readErrorStatus = http::status::payload_too_large;
                } else if (e.code() == http::error::header_limit) {
                    readErrorStatus = http::status::request_header_fields_too_large;
                } else {
                    readErrorStatus = http::status::bad_request;
                }
            }

            if (readError) {
                Response errResp;
                errResp.version(11);
                errResp.result(readErrorStatus);
                errResp.set(http::field::content_type, "text/plain");
                errResp.body() = fmt::format("Bad Request: {}", readErrorMsg);
                errResp.prepare_payload();
                errResp.keep_alive(false);
                co_await http::async_write(
                    stream,
                    errResp,
                    asio::cancel_after(std::chrono::seconds(5), asio::use_awaitable)
                );
                break;
            }

            // 构造响应
            Response resp;
            resp.version(req.version());
            // Server 头: `产品名/版本号`, 产品名由使用方经
            // utilxx_base::setProductName 设置 (默认取库名)
            resp.set(http::field::server, utilxx_base::productToken());
            // RFC 7231: 服务器应包含 Date 头
            resp.set(http::field::date, formatHttpDate(std::time(nullptr)));

            // 提取路径 (去掉 query) 并分发
            std::string path(requestPath(req.target()));
            int         methodIdx = httpMethodIndex(req.method());
            std::string matchedPath;
            bool        handled = false;
            // 静态文件路由会自己写完整个响应 (含 body), 置真后跳过后面的统一写入
            bool responseSent = false;

            // 静态文件路由（GET / HEAD）：命中就直接回 200 / 206 / 416, 不进 router
            if (methodIdx == 0 || methodIdx == 1) {
                for (const auto& fileRoute : fileRoutes_) {
                    if (fileRoute.path != path) {
                        continue;
                    }
                    if (co_await serveFileRoute(stream, req, resp, fileRoute)) {
                        handled      = true;
                        responseSent = true;
                        keepAlive    = false;
                    }
                    break;
                }
            }

            // 先检查 SSE 流式路由 (仅 GET)
            if (methodIdx == 0) { // GET
                auto sseIt = sseRoutes_.find(path);
                if (sseIt != sseRoutes_.end()) {
                    // handler 异常统一经 catchErrorAsync 处理: 若尚未发送任何 SSE
                    // 数据, 经 writer 回写 500 响应; 已发送则连接随后关闭。
                    // 取消类异常保持抛出 (无 onRethrow) 终止本连接
                    auto writer
                        = std::make_shared<SseWriterImpl<Stream>>(stream, config_.sseWriteTimeout);
                    auto sseOk = co_await utilxx_base::catchErrorAsync<bool>(
                        [&]() -> asio::awaitable<bool> {
                            co_await sseIt->second(req, writer);
                            co_return true;
                        },
                        [&](std::string errInfo) -> asio::awaitable<bool> {
                            XX_LOGE(
                                "[server] SSE handler error [{} {}]: {}",
                                req.method_string(),
                                req.target(),
                                errInfo
                            );
                            // 已发送 SSE 数据时 writeResponse 返回 false (不破坏协议),
                            // 连接随后关闭; 无论如何标记已处理, 避免回落普通路由
                            co_await writer->writeResponse(
                                http::status::internal_server_error,
                                "text/plain",
                                "Internal Server Error"
                            );
                            co_return true;
                        }
                    );
                    if (sseOk) {
                        handled = true;
                        // SSE 流式请求已处理, 跳过普通响应写入:
                        // 连接由 SseWriter 保持, 但需让 serve() 知道不再继续,
                        // 置标志后跳出循环
                        break;
                    }
                }
            }

            // POST SSE 流式路由 (如 MCP subscriptions/listen) —
            // 长连接响应流, 优先于普通 router handler
            if (methodIdx == 2) { // POST
                auto sseIt = ssePostRoutes_.find(path);
                if (sseIt != ssePostRoutes_.end()) {
                    auto writer
                        = std::make_shared<SseWriterImpl<Stream>>(stream, config_.sseWriteTimeout);
                    auto sseOk = co_await utilxx_base::catchErrorAsync<bool>(
                        [&]() -> asio::awaitable<bool> {
                            co_await sseIt->second(req, writer);
                            co_return true;
                        },
                        [&](std::string errInfo) -> asio::awaitable<bool> {
                            XX_LOGE(
                                "[server] POST SSE handler error [{} {}]: {}",
                                req.method_string(),
                                req.target(),
                                errInfo
                            );
                            // 同 GET SSE: 尚未发送数据时回写 500, 已发送则连接关闭;
                            // 标记已处理避免回落普通路由 (404/405 覆盖)
                            co_await writer->writeResponse(
                                http::status::internal_server_error,
                                "text/plain",
                                "Internal Server Error"
                            );
                            co_return true;
                        }
                    );
                    if (sseOk) {
                        handled = true;
                        break;
                    }
                }
            }

            // 检查 WebSocket 升级 (GET + Upgrade: websocket)
            if (methodIdx == 0 && !handled && (!wsRoutes_.empty() || wsAny_)) {
                auto upgradeIt = req.find(http::field::upgrade);
                if (upgradeIt != req.end()
                    && boost::beast::iequals(upgradeIt->value(), "websocket")) {
                    // WS 升级/处理异常统一经 catchErrorAsync 处理; 升级失败或 handler
                    // 异常时连接已不可用 (ws stream 析构即关闭), 标记已处理避免回落
                    // 普通路由; 取消类异常保持抛出 (无 onRethrow)
                    auto wsOk = co_await utilxx_base::catchErrorAsync<bool>(
                        [&]() -> asio::awaitable<bool> {
                            auto wsIt = wsRoutes_.find(path);
                            const bool exact = wsIt != wsRoutes_.end();
                            if (!exact && !wsAny_) {
                                co_return false;
                            }
                            {
                                streamMoved = true;
                                boost::beast::websocket::stream<boost::beast::tcp_stream> ws(
                                    std::move(stream)
                                );
                                ws.set_option(
                                    boost::beast::websocket::stream_base::timeout::suggested(
                                        boost::beast::role_type::server
                                    )
                                );
                                co_await ws.async_accept(
                                    req,
                                    asio::cancel_after(
                                        std::chrono::seconds{10},
                                        asio::use_awaitable
                                    )
                                );
                                if (exact) {
                                    co_await wsIt->second(ws);
                                } else {
                                    co_await (*wsAny_)(ws, req);
                                }
                                co_return true;
                            }
                            co_return false;
                        },
                        [&](std::string errInfo) -> asio::awaitable<bool> {
                            XX_LOGE("[server] WS upgrade error [{}]: {}", req.target(), errInfo);
                            // 升级/处理失败: 连接已不可用 (流可能已移入 ws stream,
                            // 无法再发送 HTTP 错误响应, 由 ws 析构关闭连接);
                            // 标记已处理, 避免被下方 404/405 覆盖
                            co_return true;
                        }
                    );
                    if (wsOk) {
                        handled = true;
                        break;
                    }
                }
            }

            if (methodIdx >= 0 && !handled) {
                auto handler = router_->get(path, methodIdx, matchedPath);
                // HEAD 兼容: 未注册专用 HEAD handler 时回退到 GET handler
                // (RFC 7231 §4.3.2: HEAD 与 GET 语义相同, 响应 body 在写出时剥离)
                if (!handler && methodIdx == 1) {
                    handler = router_->get(path, 0, matchedPath);
                }
                if (handler && *handler) {
                    // handler 异常统一经 catchErrorAsync 转为 500;
                    // 取消类异常保持抛出 (无 onRethrow)
                    handled = co_await utilxx_base::catchErrorAsync<bool>(
                        [&]() -> asio::awaitable<bool> {
                            co_await (*handler)(req, resp, matchedPath);
                            co_return true;
                        },
                        [&](std::string errInfo) -> asio::awaitable<bool> {
                            XX_LOGE(
                                "[server] Handler error [{} {}]: {}",
                                req.method_string(),
                                req.target(),
                                errInfo
                            );
                            fillError(
                                resp,
                                req.version(),
                                http::status::internal_server_error,
                                "Internal Server Error"
                            );
                            // 已填充 500 响应, 返回 true 表示已处理,
                            // 避免被下方 404/405 分支覆盖
                            co_return true;
                        }
                    );
                }
            }

            if (!handled && fallback_ && *fallback_) {
                handled = co_await utilxx_base::catchErrorAsync<bool>(
                    [&]() -> asio::awaitable<bool> {
                        co_await (*fallback_)(
                            req,
                            resp,
                            std::string_view{path},
                            std::string_view{peerText}
                        );
                        co_return true;
                    },
                    [&](std::string errInfo) -> asio::awaitable<bool> {
                        XX_LOGE(
                            "[server] Fallback error [{} {}]: {}",
                            req.method_string(),
                            req.target(),
                            errInfo
                        );
                        fillError(
                            resp,
                            req.version(),
                            http::status::internal_server_error,
                            "Internal Server Error"
                        );
                        co_return true;
                    }
                );
            }

            if (!handled) {
                std::string dummyPath;
                // RFC 7231 §6.5.5: 405 响应必须携带 Allow 头, 列出该资源实际支持的方法
                std::string allowMethods;
                for (int m = 0; m < 9; ++m) {
                    if (router_->getNocache(path, m, dummyPath)) {
                        if (!allowMethods.empty()) {
                            allowMethods += ", ";
                        }
                        allowMethods += httpMethodName(m);
                    }
                }
                if (!allowMethods.empty()) {
                    fillError(
                        resp,
                        req.version(),
                        http::status::method_not_allowed,
                        "Method Not Allowed"
                    );
                    resp.set(http::field::allow, allowMethods);
                } else {
                    fillError(resp, req.version(), http::status::not_found, "Not Found");
                }
            }

            // 确保设置了 Content-Length: 必须调用 prepare_payload() —
            // payload_size() 对 string_body 返回 body_.size() (空 body 为 0),
            // 若按条件判断跳过会遗漏 Content-Length 头
            if (!responseSent) {
                resp.prepare_payload();
            }

            // 尊重客户端的 Connection 头: 客户端发了 "close" 则不保持连接
            bool clientClose = req.find(http::field::connection) != req.end()
                               && boost::beast::iequals(req[http::field::connection], "close");
            keepAlive = resp.keep_alive();
            if (keepAlive && (stopped_ || clientClose)) {
                keepAlive = false;
            }
            resp.set(http::field::connection, keepAlive ? "keep-alive" : "close");

            // 发送响应（静态文件路由已经自己写过, 不再重复写）
            if (responseSent) {
                if (config_.accessLogEnabled) {
                    XX_LOGI(
                        "{} {} -> {} (file)",
                        req.method_string(),
                        req.target(),
                        resp.result_int()
                    );
                }
                continue;
            }
            if (req.method() == http::verb::head) {
                // HEAD 响应只发送头部 (含 Content-Length), 不发送 body (RFC 7231 §4.3.2);
                // 发送 body 会使 keep-alive 连接上的后续请求解析错位
                http::response<http::empty_body> headResp;
                headResp.version(resp.version());
                headResp.result(resp.result());
                for (auto const& f : resp) {
                    headResp.insert(f.name_string(), f.value());
                }
                co_await http::async_write(
                    stream,
                    headResp,
                    asio::cancel_after(config_.requestTimeout, asio::use_awaitable)
                );
            } else {
                co_await http::async_write(
                    stream,
                    resp,
                    asio::cancel_after(config_.requestTimeout, asio::use_awaitable)
                );
            }

            // 逐请求访问日志 (release 下经 XX_LOGI 编译裁剪)
            if (config_.accessLogEnabled) {
                XX_LOGI(
                    "{} {} -> {} ({})",
                    req.method_string(),
                    req.target(),
                    resp.result_int(),
                    resp.body().size()
                );
            }

        } while (keepAlive && !stopped_);

        // 优雅关闭: 关闭发送侧, 忽略错误
        // (WebSocket 升级后 stream 已被移走, 由 ws stream 负责关闭)
        if (!streamMoved) {
            ec = {};
            boost::beast::get_lowest_layer(stream).socket().shutdown(
                asio::ip::tcp::socket::shutdown_send,
                ec
            );
        }
    }

    // -----------------------------------------------------------------------
    // 工具函数
    // -----------------------------------------------------------------------

    static void fillError(
        Response&                  resp,
        unsigned                   version,
        boost::beast::http::status status,
        std::string_view           message
    );

    // -----------------------------------------------------------------------
    // 每线程 worker: 各持有私有 io_context — 零锁隔离
    // -----------------------------------------------------------------------
    struct Worker {
        asio::io_context                                                          ioCtx;
        std::optional<asio::executor_work_guard<asio::io_context::executor_type>> workGuard;
        std::thread                                                               thread;
    };

    // -----------------------------------------------------------------------
    // 成员
    // -----------------------------------------------------------------------

    Config                                   config_;
    std::vector<std::unique_ptr<Worker>>     workers_;
    std::unique_ptr<Router>                  router_;
    std::unique_ptr<asio::ip::tcp::acceptor> acceptor_;
    std::atomic<bool>                        stopped_{false};
    std::atomic<size_t>                      activeConnections_{0};
    std::atomic<size_t>                      nextWorker_{0};

    /// SSE 流式路由 (仅 GET) — 按路径索引
    std::unordered_map<
        std::string,
        std::function<asio::awaitable<void>(Request&, std::shared_ptr<SseWriter>)>>
        sseRoutes_;

    /// SSE 流式路由 (仅 POST) — 长连接响应流 (如 MCP subscriptions/listen)
    std::unordered_map<
        std::string,
        std::function<asio::awaitable<void>(Request&, std::shared_ptr<SseWriter>)>>
        ssePostRoutes_;

    /// WebSocket 路由 (GET + Upgrade) — 按路径索引
    std::unordered_map<std::string, WsHandler> wsRoutes_;

    /// 任意路径升级的处理器（空 = 没置）
    std::shared_ptr<WsRequestHandler> wsAny_;

    std::vector<FileRouteEntry> fileRoutes_;

    /// 兜底处理器（空 = 没置）
    std::shared_ptr<FallbackHandler> fallback_;

    /// 是否 startAsync 模式 (单 executor, 无 worker 线程)
    bool asyncMode_ = false;
};

} // namespace utilxx
