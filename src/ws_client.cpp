#include <asio/detail/socket_option.hpp>
// 仅提供 TCP_KEEPIDLE/TCP_KEEPINTVL/TCP_KEEPCNT 选项号常量, 设置经由 asio 接口完成
#if XX_IS_WIN_D
#include <windows.h>
// ---
#include <mstcpip.h>
#else
#include <netinet/in.h>
#include <netinet/tcp.h>
#endif

#include "utilxx_base/asio_error.h"
#include "utilxx/ws_client.h"

#include "utilxx_base/exception.h"
#include "utilxx_base/version.h"
#include "utilxx/http_client.h"
#include <algorithm>
#include <cctype>
#include <openssl/ssl.h>

namespace utilxx {

namespace {

/// 启用 TCP keepalive 并缩短探测间隔: WebSocket 长连接在业务空窗期极易被
/// NAT/网关静默丢弃, keepalive 探测包可维持中间设备状态 (best-effort)
template<typename Socket>
void enableWsKeepalive(Socket& sock) noexcept {
    utilxx_base::AsioErrorCode ec;
    sock.set_option(asio::socket_base::keep_alive(true), ec);
#if defined(TCP_KEEPIDLE) && defined(TCP_KEEPINTVL) && defined(TCP_KEEPCNT)
    asio::detail::socket_option::integer<IPPROTO_TCP, TCP_KEEPIDLE>  idle{30};
    asio::detail::socket_option::integer<IPPROTO_TCP, TCP_KEEPINTVL> interval{10};
    asio::detail::socket_option::integer<IPPROTO_TCP, TCP_KEEPCNT>   count{3};
    sock.set_option(idle, ec);
    sock.set_option(interval, ec);
    sock.set_option(count, ec);
#endif
}

} // namespace

struct WsClient::Impl {
    asio::any_io_executor executor;
    WsClientConfig        config;

    using WsStream = boost::beast::websocket::stream<boost::beast::tcp_stream>;
    using WssStream
        = boost::beast::websocket::stream<boost::beast::ssl_stream<boost::beast::tcp_stream>>;

    std::unique_ptr<WsStream>  ws;
    std::unique_ptr<WssStream> wss;
    bool                       isSsl   = false;
    bool                       closed_ = false;

    /// 接收缓冲 (recv 循环复用, 避免每次调用重新分配)
    std::string recvChunk;

    Impl(asio::any_io_executor ex, WsClientConfig cfg) :
        executor(std::move(ex)),
        config(std::move(cfg)) {
        recvChunk.resize(1024 * 16);
    }

    void configureStream() {
        // 禁用 Beast 内部 idle_timeout: 由外部 cancel_after(recvTimeout/sendTimeout) 统一控制,
        // 避免 Beast suggested timeout (默认 30s) 与用户配置的 recvTimeout 冲突
        // 注: 请求头 decorator (UA + 自定义头) 由 wsConnect 统一设置, 避免二次 set_option
        // 覆盖导致自定义头/UA 丢失
        if (isSsl) {
            wss->set_option(boost::beast::websocket::stream_base::timeout{
                .handshake_timeout = std::chrono::seconds{30},
                .idle_timeout      = boost::beast::websocket::stream_base::none(),
                .keep_alive_pings  = false,
            });
            wss->read_message_max(config.maxMessageSize);
        } else {
            ws->set_option(boost::beast::websocket::stream_base::timeout{
                .handshake_timeout = std::chrono::seconds{30},
                .idle_timeout      = boost::beast::websocket::stream_base::none(),
                .keep_alive_pings  = false,
            });
            ws->read_message_max(config.maxMessageSize);
        }
    }
};

namespace {

using WsSendResult = std::expected<void, std::string>;
using WsRecvResult = std::expected<WsMessage, std::string>;

/// 关闭底层 socket (shutdown + close), 让挂起的收发以错误结束
///
/// - `impl` 可为空 (已被 move 走或尚未建立连接的对象)
/// - 只关闭 socket, 不释放实现体: 实现体的生命周期由持有它的强引用决定
void closeTransport(WsClient::Impl* impl) noexcept {
    if (!impl) {
        return;
    }
    impl->closed_ = true;
    utilxx_base::AsioErrorCode ec;
    if (impl->isSsl && impl->wss) {
        auto& lowest = boost::beast::get_lowest_layer(*impl->wss);
        lowest.socket().shutdown(asio::ip::tcp::socket::shutdown_both, ec);
        lowest.socket().close(ec);
    } else if (impl->ws) {
        auto& lowest = boost::beast::get_lowest_layer(*impl->ws);
        lowest.socket().shutdown(asio::ip::tcp::socket::shutdown_both, ec);
        lowest.socket().close(ec);
    }
}

/// 实现体能否收发 (存在, 未关闭, 且底层 stream 已就位)
bool usable(const std::shared_ptr<WsClient::Impl>& impl) {
    if (!impl || impl->closed_) {
        return false;
    }
    return impl->isSsl ? (impl->wss != nullptr) : (impl->ws != nullptr);
}

/// 按块写完一条消息 (每块单独计时, 上限 = `sendTimeout`)
template<typename Stream>
asio::awaitable<WsSendResult> writeMessageLoop(
    Stream&                   stream,
    std::string_view          payload,
    bool                      asText,
    std::chrono::milliseconds timeout
) {
    if (asText) {
        stream.text(true);
    } else {
        stream.binary(true);
    }
    size_t offset = 0;
    do {
        const size_t len = std::min(WsClientConfig::kTimeoutChunkBytes, payload.size() - offset);
        const bool   fin = (offset + len >= payload.size());
        const auto   n   = co_await stream.async_write_some(
            fin,
            asio::buffer(payload.data() + offset, len),
            asio::cancel_after(timeout, asio::use_awaitable)
        );
        offset += n;
    } while (offset < payload.size());
    co_return WsSendResult{};
}

/// 发一条数据帧 (文本 / 二进制)
///
/// - `impl` 是本协程的**参数**: 创建协程时就复制进帧里, 所以调用方
///   随后析构 WsClient 也不会影响这里 (这是本文件所有收发协程的统一做法)
asio::awaitable<WsSendResult>
    sendFrameOnImpl(std::shared_ptr<WsClient::Impl> impl, std::string_view payload, bool asText) {
    if (!usable(impl)) {
        co_return std::unexpected{std::string{"connection closed"}};
    }
    const auto timeout = impl->config.sendTimeout;
    co_return co_await utilxx_base::catchErrorAsync<WsSendResult>(
        [&]() -> asio::awaitable<WsSendResult> {
            if (impl->isSsl) {
                co_return co_await writeMessageLoop(*impl->wss, payload, asText, timeout);
            }
            co_return co_await writeMessageLoop(*impl->ws, payload, asText, timeout);
        },
        [impl](std::string errinfo) -> asio::awaitable<WsSendResult> {
            impl->closed_ = true;
            co_return std::unexpected{std::move(errinfo)};
        }
    );
}

/// 发一条 ping 控制帧
asio::awaitable<WsSendResult>
    pingOnImpl(std::shared_ptr<WsClient::Impl> impl, std::string_view payload) {
    if (!usable(impl)) {
        co_return std::unexpected{std::string{"connection closed"}};
    }
    // RFC 6455 §5.5: 控制帧 payload 最大 125 字节, 超限直接报错避开协议错误
    if (payload.size() > 125) {
        co_return std::unexpected{std::string{"ping payload too large (max 125 bytes)"}};
    }
    const auto timeout = impl->config.sendTimeout;
    co_return co_await utilxx_base::catchErrorAsync<WsSendResult>(
        [&]() -> asio::awaitable<WsSendResult> {
            const boost::beast::websocket::ping_data data{payload};
            if (impl->isSsl) {
                co_await impl->wss->async_ping(
                    data,
                    asio::cancel_after(timeout, asio::use_awaitable)
                );
            } else {
                co_await impl->ws->async_ping(
                    data,
                    asio::cancel_after(timeout, asio::use_awaitable)
                );
            }
            co_return WsSendResult{};
        },
        [impl](std::string errinfo) -> asio::awaitable<WsSendResult> {
            impl->closed_ = true;
            co_return std::unexpected{std::move(errinfo)};
        }
    );
}

/// 发一条 close 控制帧
asio::awaitable<WsSendResult>
    closeOnImpl(std::shared_ptr<WsClient::Impl> impl, uint16_t code, std::string_view reason) {
    if (!usable(impl)) {
        co_return WsSendResult{};
    }
    impl->closed_ = true;
    co_return co_await utilxx_base::catchErrorAsync<WsSendResult>(
        [&]() -> asio::awaitable<WsSendResult> {
            boost::beast::websocket::close_reason cr;
            cr.code = code;
            // RFC 6455 §5.5.1: close reason 最大 123 字节; 超长会令
            // static_string 抛 length_error, 导致 close 帧未发送却被
            // catchErrorAsync 当成功返回, 这里先截断
            cr.reason = std::string(reason.substr(0, 123));
            if (impl->isSsl) {
                co_await impl->wss->async_close(
                    cr,
                    asio::cancel_after(std::chrono::seconds{5}, asio::use_awaitable)
                );
            } else {
                co_await impl->ws->async_close(
                    cr,
                    asio::cancel_after(std::chrono::seconds{5}, asio::use_awaitable)
                );
            }
            co_return WsSendResult{};
        },
        // close 握手失败 (如对端已断开) 不影响关闭语义, 仍视为成功
        [](std::string) -> asio::awaitable<WsSendResult> {
            co_return WsSendResult{};
        }
    );
}

/// 收一条完整消息
asio::awaitable<WsRecvResult> recvOnImpl(std::shared_ptr<WsClient::Impl> impl) {
    if (!usable(impl)) {
        co_return std::unexpected{std::string{"connection closed"}};
    }
    co_return co_await utilxx_base::catchErrorAsync<WsRecvResult>(
        [&]() -> asio::awaitable<WsRecvResult> {
            try {
                std::string payload;
                auto&       chunk = impl->recvChunk; // 复用缓冲, 避免每次调用重新分配

                if (impl->isSsl) {
                    do {
                        auto n = co_await impl->wss->async_read_some(
                            asio::buffer(chunk, chunk.size()),
                            asio::cancel_after(impl->config.recvTimeout, asio::use_awaitable)
                        );
                        payload.append(chunk.data(), n);
                    } while (!impl->wss->is_message_done());
                } else {
                    do {
                        auto n = co_await impl->ws->async_read_some(
                            asio::buffer(chunk, chunk.size()),
                            asio::cancel_after(impl->config.recvTimeout, asio::use_awaitable)
                        );
                        payload.append(chunk.data(), n);
                    } while (!impl->ws->is_message_done());
                }

                WsMessage msg;
                bool      isText = impl->isSsl ? impl->wss->got_text() : impl->ws->got_text();
                msg.type         = isText ? WsMessage::Type::Text : WsMessage::Type::Binary;
                msg.payload      = std::move(payload);
                co_return WsRecvResult{std::move(msg)};
            } catch (const utilxx_base::AsioSystemError& e) {
                // close 帧是协议正常结束而非错误: 转为 Close 消息返回。
                // 需要错误码以读取对端 close code/reason, 因此在此特判,
                // 其余错误交由 catchErrorAsync 统一处理
                if (e.code() == boost::beast::websocket::error::closed) {
                    impl->closed_ = true;
                    // 原样转发对端 close 帧携带的 code/reason (reason() 在 close 处理后可用)
                    auto cr = impl->isSsl ? impl->wss->reason() : impl->ws->reason();
                    WsMessage msg;
                    msg.type        = WsMessage::Type::Close;
                    msg.closeCode   = (cr.code != 0) ? cr.code : 1000;
                    msg.closeReason = std::string(cr.reason);
                    co_return WsRecvResult{std::move(msg)};
                }
                // 接收超时 (空闲超过 recvTimeout): 以专用消息报错。
                // Beast websocket stream 在 async_read_some 被 cancel 后内部状态机
                // (帧缓冲/解压上下文) 不可恢复, 后续操作必然失败, 必须标记 closed,
                // 调用方应重建连接
                if (e.code() == asio::error::operation_aborted) {
                    impl->closed_ = true;
                    co_return std::unexpected{std::string{"recv timeout"}};
                }
                throw;
            }
        },
        [impl](std::string errinfo) -> asio::awaitable<WsRecvResult> {
            // 其它传输错误: 连接状态同样不可恢复, 标记 closed
            impl->closed_ = true;
            co_return std::unexpected{std::move(errinfo)};
        }
    );
}

} // namespace

WsClient::WsClient(std::unique_ptr<Impl> impl) :
    impl_(std::move(impl)) {}

WsClient::~WsClient() {
    // 析构即关闭传输: 挂起的收发协程各自持有实现体, 会以错误收尾后自行释放。
    // 不在这里关闭的话, 调用方丢弃 WsClient 而不 abort() 时连接会一直挂着
    closeTransport(impl_.get());
}

WsClient::WsClient(WsClient&&) noexcept = default;

WsClient& WsClient::operator=(WsClient&& other) noexcept {
    if (this != &other) {
        // 被替换掉的旧传输同样要关闭 (否则它的 socket 会跟着实现体一起被遗弃)
        closeTransport(impl_.get());
        impl_ = std::move(other.impl_);
    }
    return *this;
}

bool WsClient::isOpen() const noexcept {
    return impl_ && !impl_->closed_;
}

void WsClient::setRecvTimeout(std::chrono::seconds timeout) noexcept {
    if (impl_) {
        impl_->config.recvTimeout = timeout;
    }
}

void WsClient::abort() noexcept {
    closeTransport(impl_.get());
}

asio::awaitable<std::expected<void, std::string>> WsClient::sendText(std::string_view payload) {
    // 这里不是协程 (没有 co_await): 调用当刻就把实现体的强引用交给内层协程,
    // 所以调用方随后 abort()/析构本对象时, 已经发起的发送仍能安全收尾
    return sendFrameOnImpl(impl_, payload, true);
}

asio::awaitable<std::expected<void, std::string>> WsClient::sendBinary(std::string_view payload) {
    // 与 sendText 相同: 实现体的强引用在调用当刻就交给内层协程
    return sendFrameOnImpl(impl_, payload, false);
}

asio::awaitable<std::expected<void, std::string>> WsClient::sendPing(std::string_view payload) {
    return pingOnImpl(impl_, payload);
}

asio::awaitable<std::expected<void, std::string>>
    WsClient::sendClose(uint16_t code, std::string_view reason) {
    return closeOnImpl(impl_, code, reason);
}

asio::awaitable<std::expected<WsMessage, std::string>> WsClient::recv() {
    return recvOnImpl(impl_);
}

asio::awaitable<std::expected<std::unique_ptr<WsClient>, std::string>> wsConnect(
    asio::any_io_executor                            executor,
    std::string_view                                 url,
    std::vector<std::pair<std::string, std::string>> headers,
    WsClientConfig                                   config
) {
    namespace beast = boost::beast;
    namespace ws    = beast::websocket;
    using tcp       = asio::ip::tcp;

    std::string urlStr(url);
    bool        isSsl = false;
    std::string host;
    std::string port;
    std::string path;

    if (urlStr.starts_with("wss://")) {
        isSsl  = true;
        urlStr = urlStr.substr(6);
    } else if (urlStr.starts_with("ws://")) {
        urlStr = urlStr.substr(5);
    } else {
        co_return std::unexpected<std::string>{"invalid ws url, must start with ws:// or wss://"};
    }

    auto        pathStart = urlStr.find('/');
    std::string hostPort;
    if (pathStart == std::string::npos) {
        hostPort = urlStr;
        path     = "/";
    } else {
        hostPort = urlStr.substr(0, pathStart);
        path     = urlStr.substr(pathStart);
    }

    // 解析 host[:port]: IPv6 字面量带方括号 (ws://[::1]:8080/),
    // 直接 rfind(':') 会错误切割 IPv6 地址内的冒号
    if (hostPort.starts_with('[')) {
        auto cb = hostPort.find(']');
        if (cb == std::string::npos) {
            co_return std::unexpected<std::string>{"invalid ws url: unclosed '[' in host"};
        }
        host = hostPort.substr(1, cb - 1);
        if (cb + 1 < hostPort.size()) {
            if (hostPort[cb + 1] != ':') {
                co_return std::unexpected<std::string>{"invalid ws url: expected ':' after ']'"};
            }
            port = hostPort.substr(cb + 2);
        }
    } else {
        auto colon = hostPort.rfind(':');
        if (colon != std::string::npos) {
            host = hostPort.substr(0, colon);
            port = hostPort.substr(colon + 1);
        } else {
            // 没写端口 (如 `wss://api.example.com/websocket`): 整段都是 host,
            // 端口按协议取默认值 (下面补齐)。漏掉这条分支会让 host 保持空串,
            // 直接报 "empty host in ws url" —— 只有带端口的地址能用。
            host = hostPort;
        }
    }
    if (port.empty()) {
        port = isSsl ? "443" : "80";
    }

    if (host.empty()) {
        co_return std::unexpected<std::string>{"empty host in ws url"};
    }
    // 端口必须是纯数字, 否则 resolver 会把 "host:abc" 当服务名解析, 报错不可读
    for (char c : port) {
        if (!std::isdigit(static_cast<unsigned char>(c))) {
            co_return std::unexpected<std::string>{fmt::format("invalid port in ws url: {}", port)};
        }
    }

    auto impl   = std::make_unique<WsClient::Impl>(executor, config);
    impl->isSsl = isSsl;

    // connectTimeout 是 DNS + TCP + TLS + WS 握手四个阶段的总上限:
    // 共用同一个 deadline, 避免各阶段各用满导致总耗时成倍放大
    auto connectDeadline = std::chrono::steady_clock::now() + config.connectTimeout;
    auto remainingMs     = [&]() -> std::chrono::milliseconds {
        auto now = std::chrono::steady_clock::now();
        if (now >= connectDeadline) {
            return std::chrono::milliseconds{1};
        }
        return std::chrono::duration_cast<std::chrono::milliseconds>(connectDeadline - now);
    };

    // Host 头: IPv6 字面量必须带方括号, 非默认端口附加 ":port"
    bool        defaultPort = (isSsl && port == "443") || (!isSsl && port == "80");
    std::string hostForHeader
        = (host.find(':') != std::string::npos) ? fmt::format("[{}]", host) : std::string(host);
    std::string hostHeader
        = defaultPort ? hostForHeader : fmt::format("{}:{}", hostForHeader, port);

    // UA + 自定义头统一在一个 decorator 内设置 (set_option(decorator) 是覆盖语义,
    // 分两次设置会丢失先设置的部分)
    // User-Agent 遵循 RFC 9110: product = token ["/" product-version];
    // 默认取产品标识, 调用方传入同名头时在下方循环里覆盖
    auto decorateRequest = [headers](ws::request_type& req) {
        req.set(boost::beast::http::field::user_agent, utilxx_base::productToken());
        for (const auto& [k, v] : headers) {
            req.set(k, v);
        }
    };

    // 连接各阶段错误 (DNS/TCP/TLS/WS 握手超时、系统错误等) 统一经
    // utilxx_base::catchErrorToUnexpectedAsync 转为错误字符串 (含 UTF-8 转换);
    // 取消类异常保持抛出, 不阻断调用方的取消处理
    co_return co_await utilxx_base::catchErrorToUnexpectedAsync<std::unique_ptr<WsClient>>(
        [&]() -> asio::awaitable<std::expected<std::unique_ptr<WsClient>, std::string>> {
            // DNS 解析不能直接 co_await: getaddrinfo 阻塞无法被取消/超时中断,
            // 黑洞 DNS 时会无限挂起。改为后台协程解析 + 轮询, 超时/取消立即
            // 放弃等待 (见 HttpClient::asyncResolveWithDeadline 注释)
            auto endpoints = co_await HttpClient::asyncResolveWithDeadline(
                host,
                port,
                connectDeadline,
                config.connectTimeout
            );

            if (isSsl) {
                auto& sslCtx    = HttpClient::sharedSslCtx(config.sslVerify);
                auto  sslStream = beast::ssl_stream<beast::tcp_stream>(executor, sslCtx);
                // SNI 与证书验证相互独立: 即使关闭验证也必须发送 SNI,
                // 否则 CDN/网关按 SNI 路由时握手直接失败; IP 字面量 (含 ':') 不支持 SNI
                if (host.find(':') == std::string::npos) {
                    ::SSL_set_tlsext_host_name(sslStream.native_handle(), host.c_str());
                }
                if (!config.sslVerify) {
                    ::SSL_set_verify(sslStream.native_handle(), SSL_VERIFY_NONE, nullptr);
                }

                co_await beast::get_lowest_layer(sslStream).async_connect(
                    endpoints,
                    asio::cancel_after(remainingMs(), asio::use_awaitable)
                );

                utilxx_base::AsioErrorCode tcpEc;
                beast::get_lowest_layer(sslStream).socket().set_option(tcp::no_delay(true), tcpEc);
                enableWsKeepalive(beast::get_lowest_layer(sslStream).socket());

                co_await sslStream.async_handshake(
                    asio::ssl::stream_base::client,
                    asio::cancel_after(remainingMs(), asio::use_awaitable)
                );

                impl->wss = std::make_unique<WsClient::Impl::WssStream>(std::move(sslStream));
                impl->configureStream();
                impl->wss->set_option(beast::websocket::stream_base::decorator(decorateRequest));

                co_await impl->wss->async_handshake(
                    hostHeader,
                    path,
                    asio::cancel_after(remainingMs(), asio::use_awaitable)
                );
            } else {
                beast::tcp_stream tcpStream(executor);

                co_await tcpStream.async_connect(
                    endpoints,
                    asio::cancel_after(remainingMs(), asio::use_awaitable)
                );

                utilxx_base::AsioErrorCode tcpEc;
                tcpStream.socket().set_option(tcp::no_delay(true), tcpEc);
                enableWsKeepalive(tcpStream.socket());

                impl->ws = std::make_unique<WsClient::Impl::WsStream>(std::move(tcpStream));
                impl->configureStream();
                impl->ws->set_option(beast::websocket::stream_base::decorator(decorateRequest));

                co_await impl->ws->async_handshake(
                    hostHeader,
                    path,
                    asio::cancel_after(remainingMs(), asio::use_awaitable)
                );
            }

            co_return std::expected<std::unique_ptr<WsClient>, std::string>{
                std::unique_ptr<WsClient>(new WsClient(std::move(impl)))
            };
        }
    );
}

std::unique_ptr<WsClient> wrapAcceptedWs(
    asio::any_io_executor                                     ex,
    boost::beast::websocket::stream<boost::beast::tcp_stream> ws,
    WsClientConfig                                            config
) {
    auto impl   = std::make_unique<WsClient::Impl>(std::move(ex), std::move(config));
    impl->isSsl = false;
    impl->ws    = std::make_unique<WsClient::Impl::WsStream>(std::move(ws));
    // 禁用 Beast 内部 idle_timeout, 由外部 cancel_after 统一控制超时
    impl->ws->set_option(boost::beast::websocket::stream_base::timeout{
        .handshake_timeout = std::chrono::seconds{30},
        .idle_timeout      = boost::beast::websocket::stream_base::none(),
        .keep_alive_pings  = false,
    });
    impl->ws->read_message_max(impl->config.maxMessageSize);
    enableWsKeepalive(boost::beast::get_lowest_layer(*impl->ws).socket());
    return std::unique_ptr<WsClient>(new WsClient(std::move(impl)));
}

} // namespace utilxx
