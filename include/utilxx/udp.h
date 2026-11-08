/// 裸 UDP（绑定端口收发数据报，支持广播与组播）
///
/// 定位: 局域网发现、设备广播、简单的心跳/应答协议。不做重传、不做排序 ——
/// 数据报丢了就是丢了，上层自己决定要不要重发。
///
/// 约定:
/// - 全部网络操作都是 `asio::awaitable`，必须在**绑定的 executor** 上调用；
///   `abort()` 可以在别的线程调用，挂起的 `recv` 会以错误返回；
/// - 不发异常：失败一律以 `std::expected` 的错误串返回；
/// - 广播地址（`255.255.255.255` / 子网广播地址）在 `broadcast = true`（默认）时可直接发送；
/// - 组播（`joinMulticast` / `leaveMulticast`）是本地操作，同步返回；`reuseAddress` 默认开，
///   同一个端口可以被多个实例绑定（组播与多实例监听需要它）；
/// - 单包大小由系统限制（约 64 KiB），本库不拆分。
#ifndef UTILXX_UDP_H
#define UTILXX_UDP_H

#include "utilxx/export.h"

#include "utilxx_base/asio_error.h"

#include "asio/any_io_executor.hpp"
#include "asio/awaitable.hpp"

#include <chrono>
#include <cstdint>
#include <expected>
#include <memory>
#include <string>
#include <string_view>

namespace utilxx {

/// 打开通道的参数
struct UTILXX_API UdpConfig {
    /// 绑定地址（收包用；只发不收可以留 `0.0.0.0`）
    std::string address = "0.0.0.0";
    /// 绑定端口（`0` = 系统分配，起来后读 `info().port`）
    uint16_t port = 0;
    /// 允许发给广播地址（`SO_BROADCAST`）
    bool broadcast = true;
    /// 允许同一端口被多个实例绑定（组播 / 多实例监听）
    bool reuseAddress = true;
    /// 一次 `recv` 的接收缓冲大小（默认 64 KiB，够 UDP 单包上限）
    size_t recvChunk = 64 * 1024;
    /// 单次发送的期限（`0` = 不限）
    std::chrono::milliseconds sendTimeout = std::chrono::seconds{30};
};

/// 收到的一个数据报
struct UTILXX_API UdpDatagram {
    std::string data;
    std::string fromAddress;
    uint16_t    fromPort = 0;
};

/// 通道现状（给 `udp.info` 用）
struct UTILXX_API UdpInfo {
    std::string address;
    uint16_t    port      = 0;
    bool        broadcast = false;
    bool        open      = false;
    uint64_t    sent      = 0; ///< 已发送数据报数
    uint64_t    received  = 0; ///< 已接收数据报数
};

class UTILXX_API UdpSocket {
public:

    struct Impl;

    ~UdpSocket();
    UdpSocket(const UdpSocket&)            = delete;
    UdpSocket& operator=(const UdpSocket&) = delete;

    /// 打开并绑定一个通道（失败返回可读原因）
    static asio::awaitable<std::expected<std::unique_ptr<UdpSocket>, std::string>>
        open(asio::any_io_executor executor, UdpConfig config = {});

    /// 同步打开并绑定一个通道（socket / setsockopt / bind 都在调用线程上完成）
    ///
    /// 给“一次调用等一个结果”的同步接口用（插件 op 分发就是这样），不必为了建一个
    /// socket 起一条协程。绑定的地址族按 `config.address` 选（IPv4 或 IPv6）。
    static std::expected<std::unique_ptr<UdpSocket>, std::string>
        openSync(asio::any_io_executor executor, UdpConfig config = {});

    /// 发一个数据报（`host` 可以是域名或 IP 字面量）
    asio::awaitable<std::expected<void, std::string>>
        sendTo(std::string_view data, std::string_view host, uint16_t port);

    /// 同步发一个数据报（域名解析与发送都在调用线程上完成，不设超时）
    ///
    /// 与 `openSync` 配套，给同步接口用；阻塞时长取决于系统解析与发送。
    std::expected<void, std::string>
        sendToSync(std::string_view data, std::string_view host, uint16_t port);

    /// 收一个数据报；没有数据时挂起等待
    asio::awaitable<std::expected<UdpDatagram, std::string>> recv();

    /// 加入组播组（`iface` 为空 = 由系统选网卡）
    std::expected<void, std::string> joinMulticast(std::string_view group, std::string_view iface = {});

    /// 离开组播组
    std::expected<void, std::string>
        leaveMulticast(std::string_view group, std::string_view iface = {});

    /// 关闭通道，使挂起的 `recv` 以错误返回（任意线程可调用）
    void abort() noexcept;

    bool isOpen() const noexcept;

    UdpInfo info() const;

private:

    explicit UdpSocket(std::shared_ptr<Impl> impl);

    std::shared_ptr<Impl> impl_;
};

} // namespace utilxx

#endif /* UTILXX_UDP_H */
