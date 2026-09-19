/// cxx_utilxx 动态库符号导出宏
///
/// 定位: 动态库 (cxx_utilxx_shared) **默认不导出任何符号**, 只有标注本宏的
/// 公开 API 才进入导出表/导入库。这样链接器 (含 LTO 的跨模块裁剪、/OPT:ICF、
/// ELF 的 --gc-sections) 才能安全裁剪内部符号与静态链入的第三方符号。
///
/// 为什么不用 `WINDOWS_EXPORT_ALL_SYMBOLS` (CMake 自动导出):
/// 该机制靠解析每个 `.obj` 的符号表生成 `.def`, 而 MSVC 的 `/GL` (LTO) 产物
/// 不含符号表 (dumpbin 显示 `File Type: ANONYMOUS OBJECT`), 解析必然失败
/// (`unrecognized file format in 'xxx.obj, 0'`) —— 自动导出与 LTO 天生互斥。
///
/// 用法:
/// - 编译本库动态库: CMake 定义 `CXX_UTILXX_EXPORTS` → `dllexport`
/// - 静态链接本库 (cxx_utilxx_static): 目标接口定义 `CXX_UTILXX_STATIC`
///   → 宏为空 (避免误用 dllimport 造成"不一致的 dll 链接"错误)
/// - 其他情况视为动态库使用方 → `dllimport`
#pragma once

#if defined(_WIN32) || defined(__CYGWIN__)
#  if defined(CXX_UTILXX_STATIC)
#    define UTILXX_API
#  elif defined(CXX_UTILXX_EXPORTS)
#    define UTILXX_API __declspec(dllexport)
#  else
#    define UTILXX_API __declspec(dllimport)
#  endif
#elif defined(__GNUC__) || defined(__clang__)
#  define UTILXX_API __attribute__((visibility("default")))
#else
#  define UTILXX_API
#endif
