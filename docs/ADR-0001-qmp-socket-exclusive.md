# ADR-0001：QMP socket 由插件独占管理

- 状态：已接受
- 日期：2026-10-25
- 相关安全不变量：**不变量 4**（模型不得直连 QMP socket）

## 背景

QEMU 的 QMP（QEMU Machine Protocol）是完全特权通道：任何能连接 QMP socket
的进程都能执行 `quit`、`stop`、`system_powerdown`、`blockdev-add`（读宿主机
任意文件）、`human-monitor-command`（等价于 `-monitor`，可执行 `migrate`、
`pmemsave` 写宿主文件等）。一旦模型或其诱导的代码拿到 QMP 地址，就绕过了
整个权限体系。

## 决策

1. **QMP socket 地址由 QmpBroker 在 spawn 时随机分配**：
   - Windows（MSYS2 不支持 AF_UNIX）：`tcp:127.0.0.1:<随机高端口>,server=on,wait=off`；
   - 其他平台：`unix:<data_dir>/qmp/<vm_id>-<随机>.sock,server=on,wait=off`。
2. 地址**只保存在插件内存的 `_VMRuntime`**，不写库、不进日志、不进 API 响应；
   `vm_status` 等 tool 返回前 `pop("qmp_address")`。
3. **禁止**注册参数出现 `-qmp` / `-monitor` / `-chardev`（模型不可自建通道）。
4. QMP 客户端（`qmp_client.QmpSession`）只暴露语义化方法给 QmpBroker；
   模型 tools 层**只暴露语义化操作**（`vm_start` 等），不存在"执行任意 QMP
   命令"的 tool。
5. QMP 连接异常断开时，状态标 `UNKNOWN` 并发出 `vm.qmp_lost` 告警，**不自动
   重连**（重连等于承认地址可能被第三方占用，破坏独占性假设）。

## 后果

- 模型侧唯一能影响 VM 的途径是结构化 tool 调用，全部经过 PermissionEngine。
- 随机端口 / 随机 socket 文件名让"猜地址"在事实上不可行；攻击面收敛到
  loopback 端口扫描，而 `-sandbox on` 与一次性地址让扫描窗口极短。
- 代价：插件崩溃后正在运行的 VM 失去控制（进程仍在但 QMP 句柄丢失）——
  设计上接受，因为重启后重新 `discover` 并仅登记，不接管旧进程。
