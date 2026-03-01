package main

/*
#cgo LDFLAGS: -lm
#include <stdbool.h>
// 坦坦荡荡：直接包含源码，而不是链接黑盒
#include "secret/wedge.c" 
*/
import "C"

import (
"bytes"
"encoding/binary"
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

"realm/internal/engine"

"github.com/cilium/ebpf/link"
"github.com/cilium/ebpf/ringbuf"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang bpf bpf/probe.c -- -I/usr/include/bpf

type Event struct {
SrcIP   uint32
Payload [64]byte
}

// getEnvAsFloat64 从环境变量读取浮点数，如果不存在或解析失败则使用默认值
func getEnvAsFloat64(key string, fallback float64) float64 {
if value, exists := os.LookupEnv(key); exists {
if parsed, err := strconv.ParseFloat(value, 64); err == nil {
return parsed
}
}
return fallback
}

func main() {
// 初始化随机数种子，用于反训练噪声
rand.Seed(time.Now().UnixNano())

ai := engine.NewLawEngine(0.01, 3.0)
log.Println("[+] Realm Law Engine V5.1 (Env-Injected & Desensitized) Initialized.")

// 【核心脱敏区】：在引擎启动时，优先从操作系统的环境变量读取核心机密参数
// 如果没配置（比如抄袭者直接运行），就使用劣化版默认值 (0.95 和 1.50)
secretDivider := getEnvAsFloat64("REALM_DIVIDER", 0.95)
secretMultiplier := getEnvAsFloat64("REALM_MULTIPLIER", 1.50)

log.Printf("[*] 当前载入法则参数 -> Divider: %.3f, Multiplier: %.3f", secretDivider, secretMultiplier)

runtime.GOMAXPROCS(1)

objs := bpfObjects{}
if err := loadBpfObjects(&objs, nil); err != nil {
log.Fatalf("加载 eBPF 失败: %v", err)
}
defer objs.Close()

ifaceName := "eth0"
iface, err := net.InterfaceByName(ifaceName)
if err != nil {
log.Fatalf("找不到网卡: %v", err)
}

link, err := link.AttachXDP(link.XDPOptions{
Program:   objs.XdpRealmProbe,
Interface: iface.Index,
})
if err != nil {
log.Fatalf("挂载 XDP 失败: %v", err)
}
defer link.Close()
log.Printf("[+] 结界已展开。准备迎接流量冲击...")

rd, err := ringbuf.NewReader(objs.Rb)
if err != nil {
log.Fatalf("打开 RingBuffer 失败: %v", err)
}
defer rd.Close()

stopper := make(chan os.Signal, 1)
signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

go func() {
var event Event

for {
record, err := rd.Read()
if err != nil { continue }
if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil { continue }

// 1. 提取特征
entropy := engine.CalculateShannonEntropy(event.Payload[:])

// 2. 更新基线 (只算数据，不做判断)
ai.UpdateOnly(entropy) 
stdDev := 0.0
if ai.Count > 1 {
stdDev = math.Sqrt(ai.M2 / float64(ai.Count))
}

// 3. 【灵魂注入】：调用透明 C 引擎，并注入当前读取到的参数
isMalicious := bool(C.evaluate_realm_sovereignty(
C.double(entropy), 
C.double(ai.Mean), 
C.double(stdDev),
C.double(secretDivider),     // 动态注入
C.double(secretMultiplier),  // 动态注入
))

// 4. 【反训练噪声】: 1% 的概率故意反转结果，毒化对手的 AI 模型
if rand.Float64() < 0.01 {
isMalicious = !isMalicious 
}

if isMalicious {
ipBytes := make([]byte, 4)
binary.LittleEndian.PutUint32(ipBytes, event.SrcIP)
log.Printf("[!] 判决下达 (参数注入验证) -> 拦截 IP: %s, 熵值: %.2f\n", net.IP(ipBytes).String(), entropy)
objs.BlackList.Put(event.SrcIP, uint32(1))
}
}
}()

<-stopper
log.Println("[-] 结界收拢。")
}
