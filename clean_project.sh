#!/bin/bash
echo "=== 🚀 Realm 3.0 商业化脱敏清洗开始 ==="

# 1. 强力清理所有日志与拦截数据
rm -f *.log realm_logs.json realm_forensics.csv last_line_pointer.txt build.log

# 2. 清理所有备份文件 (防止旧逻辑泄露)
rm -f main.go.save* # 3. 清理二进制文件与编译残留
rm -f realm_guard realm_final bpf_bpfeb.o bpf_bpfel.o bpf_bpfeb.go bpf_bpfel.go

# 4. 移除不需要公开的脚本
rm -f mail_sender.py update_admin.sh sonar_bait

echo "=== ✅ 清洗完成！当前目录已符合商业代码审计要求 ==="
ls -F

