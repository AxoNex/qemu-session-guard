# ADR-0005：MSYS2 / QEMU 二进制发现策略

- 状态：已接受
- 日期：2026-10-25
- 相关安全不变量：**不变量 8**（不硬编码 MSYS2 路径）

## 背景

部署机可能装 MSYS2（UCRT64 或 MINGW64 前缀）、单独的 QEMU for Windows
安装包，或把 `qemu-system-*.exe` 放在 PATH 里。硬编码 `C:\msys64\ucrt64\bin`
既漏掉非默认安装位置，也无法区分 UCRT64 / MINGW64。

## 决策

发现优先级（`qemu_discovery.discover`，高到低）：

1. 环境变量 / 配置 `QEMU_BINARY_DIR`（管理员显式指定，最高优先）；
2. `%MSYS2_ROOT%\ucrt64\bin`（UCRT64，推荐运行时）；
3. `%MSYS2_ROOT%\mingw64\bin`（MINGW64 回退）；
4. 从 `PATH` 搜 `qemu-system-*`。

约定：

- `MSYS2_ROOT` 默认 `C:\msys64`，可被环境变量覆盖；
- 对每个候选执行 `qemu-system-* --version` 校验可执行并解析版本，
  解析不出版本的候选被跳过并记 warning；
- 记录 `QemuVariant`（UCRT64 / MINGW64 / OTHER）用于审计与 UI 展示；
- 支持的架构后缀集中在 `ARCH_SUFFIXES`（x86_64 / aarch64 / riscv64 / …）。

## 后果

- 默认 MSYS2 安装开箱即用；非默认位置只需设 `QEMU_BINARY_DIR` 或
  `MSYS2_ROOT`，无需改代码；
- UCRT64 优先符合 MSYS2 官方推荐（UCRT64 是当前默认环境）；
- 代价：首次发现要 fork 若干 `--version`（秒级），结果可缓存。
