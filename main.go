package main

/*
#cgo LDFLAGS: -lm
#include <stdlib.h>
#include "secret/wedge.c"
*/
import "C"

import (
"bytes"
"encoding/binary"
"encoding/hex"
"flag"
"fmt"
"log"
"math"
"math/rand"
"net"
"os"
"os/signal"
"runtime"
"strconv"
"syscall"
"time"
"unicode"

"realm/internal/engine"

"github.com/cilium/ebpf/link"
"github.com/cilium/ebpf/ringbuf"
"github.com/oschwald/geoip2-golang"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang bpf bpf/probe.c -- -I/usr/include/bpf

// GenesisThreshold 创世保护期：前 5000 个包仅用于建立统计基线，不触发自动拦截（除非踩到诱饵）
const GenesisThreshold = 5000 

// honeyTokens 痛觉诱饵：在数据包中匹配这些敏感字符串，一旦命中即判定为确定性攻击
var honeyTokens = [][]byte{
[]byte("admin"),
[]byte("passwd"),
[]byte("config"),
}

// Event 与内核态 bpf/probe.c 中的 struct event 保持严格对齐
type Event struct {
SrcIP   uint32   // 来源 IP (Little Endian)
Payload [64]byte // 数据包前 64 字节载荷
}

// stringifyPayload 取证翻译官：将二进制载荷转换为人类可读的 ASCII 字符串，不可见字符用点代替
func stringifyPayload(data []byte) string {
res := make([]rune, len(data))
for i, b := range data {
r := rune(b)
if unicode.IsPrint(r) {
res[i] = r
} else {
res[i] = '.' 
}
}
return string(res)
}

// getEnvAsFloat64 安全获取环境变量参数，若不存在则返回预设的默认值
func getEnvAsFloat64(key string, fallback float64) float64 {
if value, exists := os.LookupEnv(key); exists {
if parsed, err := strconv.ParseFloat(value, 64); err == nil {
return parsed
}
}
return fallback
}

func main() {
// --- [1] 动态参数定义与解析 ---
ifaceName := flag.String("iface", "eth0", "要监控的物理网卡名称 (如 eth0, ens3)")
adminIPStr := flag.String("admin", "", "管理员白名单 IP (此 IP 的流量将不经过任何审计与拦截)")
dbPath := flag.String("db", "GeoLite2-Country.mmdb", "GeoIP 国家归属地数据库路径")
flag.Parse()

// --- [2] 归属地数据库初始化 ---
db, err := geoip2.Open(*dbPath)
if err != nil {
log.Printf("[⚠️ 警告] 归属地库加载失败: %v, 日志将显示 Unknown", err)
} else {
defer db.Close()
}

// 初始化随机数种子，用于 1% 的对抗性干扰
rand.Seed(time.Now().UnixNano())
// 初始化法则引擎：学习率 Alpha=0.01, 初始灵敏度 K=3.0
ai := engine.NewLawEngine(0.01, 3.0)

// --- [3] 结构化日志文件初始化 (CSV) ---
logPath := "realm_forensics.csv"
isNew := false
if _, err := os.Stat(logPath); os.IsNotExist(err) { isNew = true }
logFile, _ := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
defer logFile.Close()
if isNew {
// 写入 CSV 表头，新增 Country 和 Decoded 字段用于公网分析
logFile.WriteString("Timestamp,IP,Country,Entropy,Mean,StdDev,Reason,K,Decoded,HexDump,Count\n")
}

log.Printf("[🚀] Realm V6.7 (Elite) 部署成功。监控网卡: %s | 管理员白名单: %s", *ifaceName, *adminIPStr)

// --- [4] 资源熔断器：防止程序异常占用过量内存 ---
go func() {
for {
time.Sleep(15 * time.Second)
var m runtime.MemStats
runtime.ReadMemStats(&m)
if m.Alloc > 100*1024*1024 { // 超过 100MB 自动自毁，保护服务器业务
log.Fatal("[💥 熔断] 内存占用异常，程序已强制退出。")
}
}
}()

// --- [5] 加载 eBPF 字节码并尝试 XDP 挂载 ---
objs := bpfObjects{}
if err := loadBpfObjects(&objs, nil); err != nil {
log.Fatalf("[!] 加载 BPF 对象失败: %v", err)
}
defer objs.Close()

iface, err := net.InterfaceByName(*ifaceName)
if err != nil { log.Fatalf("[!] 找不到网卡 %s: %v", *ifaceName, err) }

// 优先尝试 Native XDP (硬件驱动层)，失败则回退至 Generic XDP (内核协议栈层)
xdpLink, err := link.AttachXDP(link.XDPOptions{Program: objs.XdpRealmProbe, Interface: iface.Index})
if err != nil {
log.Println("[!] Native XDP 不支持，已切换至 Generic (SKB) 模式运行")
xdpLink, _ = link.AttachXDP(link.XDPOptions{Program: objs.XdpRealmProbe, Interface: iface.Index, Flags: link.XDPGenericMode})
}
defer xdpLink.Close()

// 从环境变量读取 C 引擎所需的秘密参数
secretDivider := getEnvAsFloat64("REALM_DIVIDER", 0.95)
secretMultiplier := getEnvAsFloat64("REALM_MULTIPLIER", 1.50)

// --- [6] 建立内核至用户态的数据通信环 ---
rd, err := ringbuf.NewReader(objs.Rb)
if err != nil { log.Fatalf("[!] 无法开启 RingBuffer: %v", err) }
defer rd.Close()

// 监听系统信号 (Ctrl+C)，实现优雅退出
stopper := make(chan os.Signal, 1)
signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

// --- [7] 核心审计与防御循环 ---
go func() {
var event Event
lastPunish := time.Now()

for {
record, err := rd.Read()
if err != nil { continue }
binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event)

// 管理员 IP 校验：造物主流量豁免一切判决
ipBytes := make([]byte, 4)
binary.LittleEndian.PutUint32(ipBytes, event.SrcIP)
realIP := net.IP(ipBytes)
if *adminIPStr != "" && realIP.String() == *adminIPStr { continue }

// 流量归属地实时查询 (仅在捕获到包时触发)
country := "Unknown"
if db != nil {
geoRecord, err := db.Country(realIP)
if err == nil && geoRecord.Country.Names["zh-CN"] != "" {
country = geoRecord.Country.Names["zh-CN"]
}
}

// 计算当前载荷熵值：衡量数据混乱程度
entropy := engine.CalculateShannonEntropy(event.Payload[:])
stdDev := 0.0
if ai.Count > 1 { 
stdDev = math.Sqrt(ai.M2 / float64(ai.Count)) 
}

// --- [A] 诱饵检测逻辑 ---
reason := "Entropy"
isHoneypotTriggered := false
for _, token := range honeyTokens {
if bytes.Contains(event.Payload[:], token) {
isHoneypotTriggered = true
reason = "Honeypot"
break
}
}

// 奖惩反馈机制：若踩到诱饵，立即进入高压态惩罚，并设置 5 分钟冷却期
if isHoneypotTriggered {
ai.Punish()
lastPunish = time.Now()
log.Printf("[💥 诱饵触发] 来源: %s (%s) 关键字匹配成功！", realIP, country)
} else if ai.IsPunished && time.Since(lastPunish) > 5*time.Minute {
ai.Restore()
log.Println("[🛡️ 恢复] 5 分钟安全，法则回归初始参数。")
}

// --- [B] 核心审判逻辑 ---
isMalicious := false
// 过了创世期或者触碰了诱饵，才会调用 C 引擎执行数学判定
if ai.Count > GenesisThreshold || isHoneypotTriggered {
isMalicious = isHoneypotTriggered || bool(C.evaluate_realm_sovereignty(
C.double(entropy), C.double(ai.Mean), C.double(stdDev),
C.double(secretDivider), C.double(secretMultiplier),
))
}

// --- [C] 对抗性干扰：1% 概率反转结果，毒化攻击者的自动化模拟 ---
if rand.Float64() < 0.01 { isMalicious = !isMalicious }

// --- [D] 判决执行与深度取证记录 ---
if isMalicious {
// 物理斩断：将恶意 IP 写入内核 LRU_HASH Map，由 XDP 纳秒级丢包
objs.BlackList.Put(event.SrcIP, uint32(1))

// 准备 CSV 日志数据
decoded := stringifyPayload(event.Payload[:])
hexDump := hex.EncodeToString(event.Payload[:16])

logLine := fmt.Sprintf("%s,%s,%s,%.4f,%.4f,%.4f,%s,%.2f,\"%s\",%s,%d\n",
time.Now().Format("2006-01-02 15:04:05"),
realIP.String(), country, entropy, ai.Mean, stdDev, reason, ai.K, decoded, hexDump, ai.Count)
logFile.WriteString(logLine)

log.Printf("[!] 物理封禁 IP: %s (%s) | 原因: %s | 提取载荷: %s", realIP, country, reason, decoded)
}

// --- [E] 选择性自适应学习：只吸收非恶意流量的特征微调基线 ---
if !isMalicious {
ai.UpdateOnly(entropy)
// 创世期进度反馈
if ai.Count <= GenesisThreshold && ai.Count%1000 == 0 {
log.Printf("[⏳ 创世进度] 当前采集: %d / %d", ai.Count, GenesisThreshold)
}
if ai.Count == GenesisThreshold {
log.Println("[✅ 结界稳固] 创世期结束，主权物理法则正式生效。")
}
}
}
}()

<-stopper
log.Println("[-] 结界收拢。")
}
