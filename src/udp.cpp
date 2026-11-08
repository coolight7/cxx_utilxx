#include "utilxx/udp.h"

#include "utilxx_base/async_mutex.h"
#include "utilxx_base/log.h"

#include "asio/cancel_after.hpp"
#include "asio/ip/multicast.hpp"
#include "asio/ip/udp.hpp"
#include "asio/redirect_error.hpp"
#include "asio/use_awaitable.hpp"

#include <atomic>
#include <optional>

namespace utilxx {

namespace {

using utilxx_base::AsioErrorCode;

} // namespace

struct UdpSocket::Impl {
    asio::ip::udp::socket     socket;
    UdpConfig                 config;
    /// 并发 recv 串行（一个通道只有一个读者在等）
    std::optional<utilxx_base::AsyncMutex> recvMutex;
    std::atomic<bool>                      closed{false};
    std::atomic<uint64_t>                  sent{0};
    std::atomic<uint64_t>                  received{0};

    Impl(asio::ip::udp::socket sock, UdpConfig cfg) :
        socket(std::move(sock)),
        config(std::move(cfg)),
        recvMutex(std::in_place, socket.get_executor()) {}
};

UdpSocket::UdpSocket(std::shared_ptr<Impl> impl) :
    impl_(std::move(impl)) {}

UdpSocket::~UdpSocket() {
    abort();
}

asio::awaitable<std::expected<std::unique_ptr<UdpSocket>, std::string>> UdpSocket::open(
    asio::any_io_executor executor,
    UdpConfig             config
) {
    AsioErrorCode ec;
    auto          address = asio::ip::make_address(config.address, ec);
    if (ec) {
        co_return std::unexpected("invalid bind address: " + ec.message());
    }
    asio::ip::udp::socket socket(executor);
    socket.open(asio::ip::udp::v4(), ec);
    if (ec) {
        co_return std::unexpected(ec.message());
    }
    if (config.reuseAddress) {
        socket.set_option(asio::socket_base::reuse_address(true), ec);
    }
    if (config.broadcast) {
        socket.set_option(asio::socket_base::broadcast(true), ec);
    }
    socket.bind(asio::ip::udp::endpoint(address, config.port), ec);
    if (ec) {
        AsioErrorCode ignored;
        socket.close(ignored);
        co_return std::unexpected(ec.message());
    }
    auto impl = std::make_shared<Impl>(std::move(socket), std::move(config));
    co_return std::unique_ptr<UdpSocket>(new UdpSocket(std::move(impl)));
}

asio::awaitable<std::expected<void, std::string>>
    UdpSocket::sendTo(std::string_view data, std::string_view host, uint16_t port) {
    auto impl = impl_;
    if (!impl || impl->closed.load(std::memory_order_acquire) || !impl->socket.is_open()) {
        co_return std::unexpected(std::string{"socket closed"});
    }
    if (host.empty() || port == 0) {
        co_return std::unexpected(std::string{"invalid endpoint"});
    }
    AsioErrorCode   ec;
    asio::ip::address target = asio::ip::make_address(host, ec);
    asio::ip::udp::endpoint endpoint;
    if (ec) {
        // 不是 IP 字面量: 交给系统解析（UDP 建连的代价很小, 不做缓存）
        asio::ip::udp::resolver resolver(impl->socket.get_executor());
        auto results = co_await resolver.async_resolve(
            asio::ip::udp::v4(),
            std::string{host},
            std::to_string(port),
            asio::cancel_after(
                std::chrono::seconds{10},
                asio::redirect_error(asio::use_awaitable, ec)
            )
        );
        if (ec || results.empty()) {
            co_return std::unexpected(ec ? ec.message() : std::string{"resolve failed"});
        }
        endpoint = *results.begin();
    } else {
        endpoint = asio::ip::udp::endpoint(target, port);
    }
    if (impl->config.sendTimeout.count() > 0) {
        co_await impl->socket.async_send_to(
            asio::buffer(data.data(), data.size()),
            endpoint,
            asio::cancel_after(
                impl->config.sendTimeout,
                asio::redirect_error(asio::use_awaitable, ec)
            )
        );
    } else {
        co_await impl->socket.async_send_to(
            asio::buffer(data.data(), data.size()),
            endpoint,
            asio::redirect_error(asio::use_awaitable, ec)
        );
    }
    if (ec) {
        co_return std::unexpected(ec.message());
    }
    impl->sent.fetch_add(1, std::memory_order_relaxed);
    co_return std::expected<void, std::string>{};
}

asio::awaitable<std::expected<UdpDatagram, std::string>> UdpSocket::recv() {
    auto impl = impl_;
    if (!impl) {
        co_return std::unexpected(std::string{"socket released"});
    }
    if (!impl->recvMutex) {
        co_return std::unexpected(std::string{"socket released"});
    }
    auto guard = co_await impl->recvMutex->lock();
    if (impl->closed.load(std::memory_order_acquire) || !impl->socket.is_open()) {
        co_return std::unexpected(std::string{"socket closed"});
    }
    std::string buf(impl->config.recvChunk > 0 ? impl->config.recvChunk : 64 * 1024, '\0');
    asio::ip::udp::endpoint from;
    AsioErrorCode           ec;
    const size_t            n = co_await impl->socket.async_receive_from(
        asio::buffer(buf.data(), buf.size()),
        from,
        asio::redirect_error(asio::use_awaitable, ec)
    );
    if (ec) {
        co_return std::unexpected(ec.message());
    }
    buf.resize(n);
    impl->received.fetch_add(1, std::memory_order_relaxed);
    UdpDatagram datagram;
    datagram.data        = std::move(buf);
    datagram.fromAddress = from.address().to_string();
    datagram.fromPort    = from.port();
    co_return datagram;
}

std::expected<void, std::string>
    UdpSocket::joinMulticast(std::string_view group, std::string_view iface) {
    if (!impl_ || !impl_->socket.is_open()) {
        return std::unexpected(std::string{"socket closed"});
    }
    AsioErrorCode ec;
    // join_group 只接 IPv4 地址类型 (address_v4), 不是通用 address 变体
    const auto     groupV4 = asio::ip::make_address_v4(std::string{group}, ec);
    if (ec) {
        return std::unexpected("invalid multicast group: " + ec.message());
    }
    if (iface.empty()) {
        impl_->socket.set_option(asio::ip::multicast::join_group(groupV4), ec);
    } else {
        const auto ifaceV4 = asio::ip::make_address_v4(std::string{iface}, ec);
        if (ec) {
            return std::unexpected("invalid interface address: " + ec.message());
        }
        impl_->socket.set_option(asio::ip::multicast::join_group(groupV4, ifaceV4), ec);
    }
    if (ec) {
        return std::unexpected(ec.message());
    }
    return std::expected<void, std::string>{};
}

std::expected<void, std::string>
    UdpSocket::leaveMulticast(std::string_view group, std::string_view iface) {
    if (!impl_ || !impl_->socket.is_open()) {
        return std::unexpected(std::string{"socket closed"});
    }
    AsioErrorCode ec;
    const auto     groupV4 = asio::ip::make_address_v4(std::string{group}, ec);
    if (ec) {
        return std::unexpected("invalid multicast group: " + ec.message());
    }
    if (iface.empty()) {
        impl_->socket.set_option(asio::ip::multicast::leave_group(groupV4), ec);
    } else {
        const auto ifaceV4 = asio::ip::make_address_v4(std::string{iface}, ec);
        if (ec) {
            return std::unexpected("invalid interface address: " + ec.message());
        }
        impl_->socket.set_option(asio::ip::multicast::leave_group(groupV4, ifaceV4), ec);
    }
    if (ec) {
        return std::unexpected(ec.message());
    }
    return std::expected<void, std::string>{};
}

void UdpSocket::abort() noexcept {
    if (!impl_) {
        return;
    }
    if (impl_->closed.exchange(true, std::memory_order_acq_rel)) {
        return;
    }
    AsioErrorCode ec;
    impl_->socket.close(ec);
}

bool UdpSocket::isOpen() const noexcept {
    return impl_ && !impl_->closed.load(std::memory_order_acquire) && impl_->socket.is_open();
}

UdpInfo UdpSocket::info() const {
    UdpInfo info;
    if (!impl_) {
        return info;
    }
    AsioErrorCode ec;
    const auto    ep = impl_->socket.local_endpoint(ec);
    if (!ec) {
        info.address = ep.address().to_string();
        info.port    = ep.port();
    }
    info.broadcast = impl_->config.broadcast;
    info.open      = isOpen();
    info.sent      = impl_->sent.load(std::memory_order_relaxed);
    info.received  = impl_->received.load(std::memory_order_relaxed);
    return info;
}

} // namespace utilxx
