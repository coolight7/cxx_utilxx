/// 通用网络服务: HTTP 客户端 / HTTP 服务端 / TCP / WebSocket / UDP
///
/// 定位: 一套"按**属主 id** 划分资源"的网络管理器。属主可以是任何东西 —— 插件实例、
/// 会话、页面、一次任务; 本库只认字符串 id, 不关心上层把它用在哪儿, 也不依赖任何
/// 框架头文件 (纯 `utilxx` + asio/beast/OpenSSL)。
///
/// - HTTP 客户端 (发起请求) 与 HTTP 服务端 (回答请求);
/// - TCP 客户端与服务端 (监听、接受连接、收发字节);
/// - WebSocket 客户端与服务端 (握手、文本/二进制消息、ping/pong、关闭握手);
/// - **UDP 通道**: 绑定端口收发数据报, 支持**广播** (`255.255.255.255` / 子网广播地址) 与
///   **组播** (`udp.open` 的 `multicast` / `udp.join` / `udp.leave`) —— 局域网发现靠它;
/// - 静态内容: HTTP 服务可以挂几条静态路由 (`http.serve` 的 `static` / `http.route`),
///   命中后由这里直接回 200 / 206 / 416, **不问属主** —— "把文件 / 内存内容变成 http 地址"
///   就是它。
///
/// 上层怎么接进来 (与本库无关, 由调用方实现):
/// - `call` / `callAsync` 的 `op` + 参数 JSON → 结果 JSON, 适合直接映射成一张 C 接口表;
/// - 事件经 [NetHub::PublishFn] 发出 (调用方负责投递到自己的线程再分发);
/// - 属主停用 / 卸载时调 [NetHub::shutdownOwner], 拿回需要按"已取消"结算的完成回调。
///
/// 安全边界 (改这里之前先读):
/// - 服务端默认**只监听回环** `127.0.0.1`; 要监听局域网必须显式给 `host: "0.0.0.0"`,
///   文档里写明这意味着同网段可访问;
/// - **客户端**支持 `http://` / `https://` / `ws://` / `wss://` (链了 OpenSSL; 证书链与
///   主机名校验默认开); **服务端只有明文** `http://` / `ws://`;
/// - 静态路由的默认路径带随机 token, 而且服务端**不解析路径** —— 拿到 URL 也读不到别的文件;
/// - 连接数、服务数、单条消息大小、等待队列都有上限 (见实现里的常量),
///   超限按可读错误返回, 不做无界排队;
/// - UDP 通道建好就开了 `SO_BROADCAST` (所以能直接发给广播地址), 并默认 `reuse_address`
///   (组播 / 多实例监听同一端口要用); 单包超过 UDP 上限 (约 64 KiB) 由系统报错, 不拆分。
/// - 资源跟着**属主**: 调 [NetHub::shutdownOwner] 时, 该属主的全部服务与连接一起关掉
///   (端口释放)。
///
/// 线程模型:
/// - 全部 socket 状态归**一条独立的网络线程** (自己的 `asio::io_context`), 与调用方线程分开;
/// - `call` / `callAsync` / `cancel` 可在任意线程调用: 内部投递到网络线程,
///   需要结果时**有界等待** (网络线程不会反过来等调用方线程, 因此不会互锁);
/// - 事件经 `PublishFn` 发出 (调用方实现成"投递到自己的线程再分发"),
///   异步完成回调经 `PostFn` 投递回调用方线程后执行 —— 属主代码只在自己的线程跑。
#pragma once

#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <vector>

namespace utilxx {

/// 结果码 (与"业务结论"分开: 结果 JSON 里的 `ok` 才是业务结论)
///
/// 约定: 0 表示**操作执行完毕**, 负值表示参数/状态层面失败 (此时不写 outJson)。
namespace net {

inline constexpr int32_t Ok            = 0;  ///< 操作执行完毕 (业务结论看结果 JSON)
inline constexpr int32_t ErrArg        = -1; ///< 参数非法 (缺字段 / 类型不对)
inline constexpr int32_t ErrState      = -2; ///< 当前状态不允许 (网络服务没启动)
inline constexpr int32_t ErrJson       = -3; ///< 参数不是合法 JSON
inline constexpr int32_t ErrNotFound   = -4; ///< 请求 / 连接 / 服务不存在
inline constexpr int32_t ErrTimeout    = -5; ///< 等网络线程超时
inline constexpr int32_t ErrPermission = -6; ///< 没有权限 (例如落盘路径越界)
inline constexpr int32_t ErrQueueFull  = -7; ///< 排队已满 (服务 / 连接 / 请求上限)
inline constexpr int32_t ErrNoMemory   = -8; ///< 内存不足
inline constexpr int32_t ErrInternal   = -99; ///< 实现内部错误

} // namespace net

/// 异步操作的完成状态
///
/// 数值固定为 0 成功 / 1 已取消 / 2 失败; 调用方对外映射时按自己的枚举逐项转换,
/// 不要直接强转。
enum class NetDoneStatus : int32_t { Ok = 0, Canceled = 1, Failed = 2 };

/// 网络服务的中心 (进程内一个; 由调用方持有)
class NetHub {
public:
  /// 发一条网络事件 (`payloadJson` 里已带 `kind` 字段)
  ///
  /// 调用方必须把它投递到自己的线程再分发, 不要在网络线程上直接调属主代码。
  using PublishFn = std::function<void(const std::string &owner,
                                       const std::string &payloadJson)>;

  /// 把一个函数投递到调用方线程执行 (异步完成回调用)
  using PostFn = std::function<void(std::function<void()>)>;

  /// 异步操作的完成回调
  ///
  /// - [NetDoneStatus.Ok] 时 `payloadJson` 是结果 JSON;
  /// - [NetDoneStatus.Failed] 时 `payloadJson` 是错误 JSON (`{ok:false,error,message}`);
  /// - 取消 (属主停用 / 停机) 用 [NetDoneStatus.Canceled] + 空载荷。
  using DoneFn = std::function<void(NetDoneStatus status, const std::string &payloadJson)>;

  static std::shared_ptr<NetHub> create(PublishFn publish, PostFn postToCaller);
  ~NetHub();
  NetHub(const NetHub &) = delete;
  NetHub &operator=(const NetHub &) = delete;

  /// 起网络线程 (幂等)
  void start();

  /// 停掉全部服务与连接并释放网络线程 (幂等)
  void stop();

  bool running() const;

  /// 同步操作 (`op` 与参数见实现的 op 派发表)
  ///
  /// 返回 [net::Ok] 表示"操作执行完毕"(结果里的 `ok` 才是业务结论);
  /// 参数非法/未启动等返回负错误码 (不写 outJson)。
  int32_t call(const std::string &owner, const std::string &op,
               const std::string &argsJson, std::string &outJson);

  /// 属主私有数据根目录 (`http.download` 落盘到 `<dataDir>/<属主 id>/data/downloads/`)
  ///
  /// 要在 `start()` 之前设好; 不设时 `http.download` 返回 `no_data_dir`。
  void setDataDir(const std::string &dir);

  /// 异步操作 (目前是 `http.request` / `http.fetch` / `http.download`);
  /// 其它 op 返回参数错误
  ///
  /// - 受理成功写出 `outRequestId` 与受理结果 `outJson` (`{ok:true,requestId:N}`),
  ///   结果**恰好一次**经 `done` 给出 (调用方线程);
  /// - 受理失败返回负错误码, `outJson` 里是可读原因, **不回调 `done`**
  ///   (与"受理失败不推事件"同一约定)。
  int32_t callAsync(const std::string &owner, const std::string &op,
                    const std::string &argsJson, DoneFn done,
                    std::string &outJson, int64_t *outRequestId);

  /// 取消一个进行中的异步请求 (不存在/已完成返回 [net::ErrNotFound])
  int32_t cancel(const std::string &owner, int64_t requestId,
                 std::string &outJson);

  /// 关掉某个属主的全部服务、连接与未完成请求 (属主停用 / 卸载 / 停机)
  ///
  /// 返回需要按"已取消"结算的完成回调 —— **调用方要在自己的线程上逐个调用**
  /// (网络线程不能执行属主代码)。
  std::vector<DoneFn> shutdownOwner(const std::string &owner);

  /// 网络现状 (`net.info` 的数据源; owner 为空 = 全部属主)
  std::string infoJson(const std::string &owner);

  /// 实现细节 (仅供 net_hub.cpp 里的连接类使用; 不要从外部引用)
  struct Impl;

private:
  explicit NetHub(std::shared_ptr<Impl> impl);

  std::shared_ptr<Impl> impl_;
};

} // namespace utilxx
