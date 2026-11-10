# cxx_utilxx

重依赖工具库 (网络 / 存储 / 正则 / 进程 / 散列)。

## 定位

- **用途**: HTTP 客户端与服务端 (Boost.Beast + OpenSSL)、WebSocket 客户端、
  通用网络服务 (HTTP / TCP / WebSocket / UDP 的客户端与服务端 + 按属主 id 隔离,
  `utilxx/net_hub.h`)、正则 (HyperScan 或 std::regex)、Aho-Corasick、路由、
  文本差异、MD5/设备标识
- **依赖**: `cxx_utilxx_base` (基础件与取消抽象)、Boost (beast/asio, 仅头文件)、
  OpenSSL、fmt、html2md; 可选 HyperScan (正则加速, 导出接口以库名
  `PkgConfig::hyperscan` + `hs_runtime` 声明, 具体库由使用方解析)。
  不依赖任何插件/框架头文件 —— `net_hub` 只认属主 id 字符串, 插件面适配留在主程序。
  文件异步 I/O 的 io_uring 依赖属 `cxx_utilxx_base` (其 `system.cpp` 使用), 经本库
  的链接接口间接传递
- **命名空间**: `utilxx` (与 `cxx_utilxx_base` 的 `utilxx/cancel.h`、`utilxx/async_offload.h` 同一命名空间)
- **禁止**依赖任何业务引擎 (图引擎/数据库等) 与主程序业务头文件
- 与具体业务绑定的工具 (数据库封装、全局设置库、git 工作树等) 由主程序自行实现，
  本库不提供
- 对外标识 (HTTP `Server` / `User-Agent`) 的产品名默认取库名，使用方经
  `utilxx_base::setProductName` 换成自己的名字

## 目录结构

```
include/utilxx/
  http_client.h  http_header.h  http_error.h  http_server.h  ws_client.h
  router.h  regex.h  aho_corasick.h
  diff_util.h  crypto.h
  net_hub.h  net_hub_tls.h   # 通用网络服务 (HTTP/TCP/WS/UDP, 按属主 id 隔离)
src/                    实现 (crypto/http_client/http_header/http_server/regex/ws_client
                        /net_hub/net_hub_tls)
```

## 构建与使用

```cmake
# 顺序: 先查找依赖库的依赖 (条件依赖, 导出接口只声明目标名), 再导入依赖库本体
if (CXX_UTILXX_BASE_LINUX_IO_URING_SUPPORTED)  # cxx_utilxx_base 声明该依赖
  find_package(PkgConfig REQUIRED)
  pkg_check_modules(uring REQUIRED IMPORTED_TARGET liburing)
endif ()
if (CXX_UTILXX_ENABLE_HYPERSCAN)               # 本库声明该依赖
  pkg_check_modules(hyperscan REQUIRED IMPORTED_TARGET libhs)
endif ()
find_package(cxx_utilxx REQUIRED)   # 内部 find_dependency(cxx_utilxx_base) 链解析其余依赖
target_link_libraries(your_target PRIVATE cxx_utilxx_static)  # 或 cxx_utilxx_shared
```

- 产物命名: Release `libcxx_utilxx.so` / `libcxx_utilxx_static.a`,
  Debug 追加 `d` → `libcxx_utilxxd.so` / `libcxx_utilxx_staticd.a`
- 可选特性由 CMake 开关控制: `CXX_UTILXX_ENABLE_HYPERSCAN` (正则实现)
- **条件依赖只声明库名, 使用方在本机 find (顺序: 先依赖库的依赖, 再依赖库本体)**:
  开启 HyperScan 后导出接口里出现的是 `PkgConfig::hyperscan` 与裸库名 `hs_runtime`
  (**名称**, 与 `fmt::fmt`/`OpenSSL::SSL` 同类), 不含库文件路径。静态库不携带依赖二进制,
  具体库由使用方在自己机器上解析: 须**先**在自身 CMakeLists 的依赖查找段写
  `pkg_check_modules(hyperscan REQUIRED IMPORTED_TARGET libhs)`
  (`hs_runtime` 经 `INTERFACE_LINK_DIRECTORIES` 里的安装目录以裸库名解析, 无需 find),
  **再** `find_package(cxx_utilxx)` —— 顺序颠倒会报 "target ... not found";
  本库 PUBLIC 依赖的 `cxx_utilxx_base` 声明的 `PkgConfig::uring` 同理须先查找

```c++
#include "utilxx/http_client.h"

auto resp = co_await utilxx::HttpClient::postAsync(url, body, "application/json", headers,
                                                   utilxx::HttpClient::RequestConfig{});
auto json = resp.bodyJson();          // std::optional<utilxx_base::Json>
```

## 关停与关闭语义（实测过、容易踩的）

- `HttpServer::stop()` 除了关监听端口，还会关掉已建立的连接。只关 acceptor 的话，客户端
  复用的 keep-alive 连接会接着发请求，服务看起来“停不掉”。连接表用 weak_ptr，协程自己结束时
  自动出表。
- `HttpServer::serve()` 必须按引用接 stream。按值接会把 socket 移进协程参数，`serveTcp`
  手里那个 `tcp_stream` 已经是搬空的，关它没有作用。
- 连接协程用 `weak_from_this()` 抱住服务对象（只在使用方用 `make_shared` 构造时生效），
  否则 `stop()` 叫醒协程时对象可能已经销毁。
- `TcpConnection::abort()` 先 `cancel()` 再 `close()`：Windows 上带挂起读的 `closesocket`
  会把连接重置，已经写进发送缓冲的数据客户端收不到（表现是少收一截，截断位置常落在
  16 KiB 的整数倍）。
- 静态文件路由的 `Range` 支持 `bytes=a-b` / `bytes=a-` / `bytes=-N`（后缀长度为 0 回 416）。

## 子进程相关
HTTP 客户端的 DNS 解析在阻塞路径上工作, 调用方应经 `utilxx::offloadAsync` /
offloadCancellableAsync 卸载到线程池, 避免阻塞 io_context 线程; 取消语义统一经
`utilxx::CancelToken` (见 `cxx_utilxx_base`)。

## 平台

Linux / Windows / macOS / Android / iOS 均可编译; HyperScan 与 io_uring 仅在
Linux (HyperScan 另支持 Windows 受限支持) 生效, 未启用时自动回退 std::regex /
同步文件 I/O。

## 导出面

动态变体**默认不导出任何符号**, 只有公开头文件中标注 `UTILXX_API` 的 API 才进入
导出表/导入库 (静态链入的第三方符号、std 模板实例都不会外泄):

- MSVC: 标注展开为 `dllexport` (构建动态库时) / `dllimport` (使用方);
  静态使用方由目标接口定义 `CXX_UTILXX_STATIC`, 宏展开为空
- GCC/Clang: 编译期 `-fvisibility=hidden` (+ `-fvisibility-inlines-hidden`),
  标注展开为 `visibility("default")`
- 不使用 CMake 的 `WINDOWS_EXPORT_ALL_SYMBOLS`: 该机制要解析每个 `.obj` 的符号表
  生成 `.def`, 而 `/GL` (LTO) 产物只有编译器中间表示、没有符号表, 二者互斥
