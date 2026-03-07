package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go bpf probe.c

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math"
	"net"
	"net/http"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/oschwald/geoip2-golang"
)

type RunMode string
const (
	ModeObservation RunMode = "OBSERVATION"
	ModeDefense     RunMode = "DEFENSE"
	ModeDisabled    RunMode = "DISABLED"
)

type LifecycleController struct {
	CurrentMode      RunMode
	InstallTime      time.Time
	DefenseStartTime time.Time
	sync.RWMutex
}

type IPRecord struct {
	IP             string
	Reputation     float64
	PenaltyBucket  float64
	LastUpdateTime time.Time
	EmaMean        float64
	EmaVar         float64
	TotalStrikes   int
}

type DropEvent struct {
	Time      string  `json:"time"`
	Timestamp int64   `json:"timestamp"`
	IP        string  `json:"ip"`
	Geo       string  `json:"geo"`
	Country   string  `json:"country"`
	Reason    string  `json:"reason"`
	Payload   string  `json:"payload"`
	Entropy   float64 `json:"entropy"`
	Strikes   int     `json:"strikes"`
}

type LogEntry struct {
	IP          string  `json:"ip"`
	StrikeCount int     `json:"strike_count"`
	AttackType  string  `json:"attack_type"`
	Payload     string  `json:"payload"`
}

var (
	ipStateMap  = make(map[string]*IPRecord)
	recentDrops = make([]DropEvent, 0)
	totalBlocks = 0
	todayBlocks = 0
	stateMutex  sync.RWMutex

	bloomFilter         = make(map[string]bool)
	bannedIPsReleaseMap = make(map[string]int64) 
	bloomMutex          sync.RWMutex

	// [新增] 指挥官持久化白名单：用于在 Go 引擎层面彻底屏蔽审计
	authenticatedIPs = make(map[string]bool)
	authMutex        sync.RWMutex

	sanitizeRegex = regexp.MustCompile(`(?i)(password|passwd|pwd|token|secret|session|auth|cookie|authorization)=([^& \n]+)`)

	ebpfObjs   bpfObjects
	controller = &LifecycleController{CurrentMode: ModeObservation, InstallTime: time.Now()}
	geoDB      *geoip2.Reader

	sonarPorts = []int{6379, 2222, 2375, 3306}
)

// ==========================================
// 模块：精确刑满释放机制
// ==========================================
func scheduleRelease(ipStr string, ipUint32 uint32) {
	releaseTime := time.Now().Add(10 * time.Minute).Unix()
	
	bloomMutex.Lock()
	bannedIPsReleaseMap[ipStr] = releaseTime
	bloomMutex.Unlock()

	time.AfterFunc(10*time.Minute, func() {
		ebpfObjs.BlacklistMap.Delete(ipUint32)

		stateMutex.Lock()
		if record, exists := ipStateMap[ipStr]; exists {
			record.PenaltyBucket = 0.0
			record.Reputation = 50.0 
		}
		stateMutex.Unlock()

		bloomMutex.Lock()
		delete(bloomFilter, ipStr)
		delete(bannedIPsReleaseMap, ipStr) 
		bloomMutex.Unlock()

		log.Printf("🕊️ [刑满释放] IP: %s 10分钟封禁期满。", ipStr)
	})
}

// ==========================================
// 模块：L2 原生流量嗅探器
// ==========================================
func startTrafficSniffer() {
	conn, err := net.ListenPacket("ip4:tcp", "0.0.0.0")
	if err != nil { return }
	log.Println("👁️ [风控大脑] L2 原生流量嗅探阵列已上线...")

	buf := make([]byte, 65535)
	for {
		n, addr, err := conn.ReadFrom(buf)
		if err != nil || n < 20 { continue }

		// 22 端口 SSH 物理豁免
		srcPort := binary.BigEndian.Uint16(buf[0:2])
		dstPort := binary.BigEndian.Uint16(buf[2:4])
		if srcPort == 22 || dstPort == 22 { continue }

		ip := addr.String()
		payload := string(buf[:n])
		if len(payload) > 20 {
			go ProcessTraffic(ip, payload, "TRAFFIC_AUDIT", false)
		}
	}
}

// ==========================================
// 模块：血色声呐
// ==========================================
func startScarletSonar() {
	for _, port := range sonarPorts {
		if port == 22 { continue } 
		go func(p int) {
			addr := fmt.Sprintf("0.0.0.0:%d", p)
			ln, err := net.Listen("tcp", addr)
			if err != nil { return }
			for {
				conn, err := ln.Accept()
				if err != nil { continue }
				host, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
				ProcessTraffic(host, fmt.Sprintf("TCP SYN -> %d", p), "TCP_CONNECT", true)
				conn.Close()
			}
		}(port)
	}
}

func calculateShannonEntropy(data string) float64 {
	if len(data) == 0 { return 0.0 }
	freq := make(map[rune]float64)
	for _, char := range data { freq[char]++ }
	entropy := 0.0
	length := float64(len(data))
	for _, count := range freq {
		probability := count / length
		entropy -= probability * math.Log2(probability)
	}
	return entropy
}

func getOrInitRecord(ip string) *IPRecord {
	if record, exists := ipStateMap[ip]; exists { return record }
	record := &IPRecord{IP: ip, Reputation: 50.0, PenaltyBucket: 0.0, LastUpdateTime: time.Now(), EmaMean: 3.5, EmaVar: 0.5}
	ipStateMap[ip] = record
	return record
}

// ==========================================
// 模块：核心风控判决 (已加入指挥官隐身逻辑)
// ==========================================
func ProcessTraffic(ip string, payload string, attackType string, isSonarHit bool) {
	// [关键修改] 检查是否为已认证的指挥官 IP
	authMutex.RLock()
	if authenticatedIPs[ip] {
		authMutex.RUnlock()
		return // 🛡️ 指挥官 IP 直接跳过所有记录与审计，实现 2.5 版本的隐身效果
	}
	authMutex.RUnlock()

	stateMutex.Lock()
	defer stateMutex.Unlock()

	record := getOrInitRecord(ip)
	now := time.Now()
	elapsedHours := now.Sub(record.LastUpdateTime).Hours()
	record.PenaltyBucket = math.Max(0, record.PenaltyBucket-(elapsedHours*5.0))

	penaltyWater := 0.0
	reason := ""
	currentEntropy := calculateShannonEntropy(payload)

	if isSonarHit {
		penaltyWater = 100.0
		reason = "高危诱饵触发"
	} else {
		sigma := math.Sqrt(record.EmaVar)
		threshold := record.EmaMean + (3 * sigma)

		if currentEntropy > threshold && currentEntropy > 4.5 {
			penaltyWater = 50.0
			reason = "高熵混淆攻击"
		} else if strings.Contains(payload, "/.env") || strings.Contains(payload, "UNION SELECT") {
			penaltyWater = 40.0
			reason = "高危漏洞探测"
		} else {
			alpha := 0.1
			diff := currentEntropy - record.EmaMean
			record.EmaMean = record.EmaMean + alpha*diff
			record.EmaVar = (1-alpha)*(record.EmaVar + alpha*diff*diff)
			record.Reputation = math.Min(100.0, record.Reputation+0.5)
			record.LastUpdateTime = now
			return
		}
	}

	record.PenaltyBucket += penaltyWater
	record.Reputation = math.Max(10.0, record.Reputation-penaltyWater*0.2)
	record.TotalStrikes++
	record.LastUpdateTime = now

	bucketCapacity := 100.0 * (record.Reputation / 50.0)

	if record.PenaltyBucket >= bucketCapacity {
		executeDropUnlocked(ip, record, reason, SanitizePayload(payload), currentEntropy, false)
	}
}

func executeDropUnlocked(ipStr string, record *IPRecord, reason string, payload string, entropy float64, isHistorical bool) {
	controller.RLock()
	mode := controller.CurrentMode
	controller.RUnlock()

	bloomMutex.RLock()
	if bloomFilter[ipStr] && !isHistorical {
		bloomMutex.RUnlock()
		return 
	}
	bloomMutex.RUnlock()

	country, city := getGeoLocation(ipStr)
	geoFormat := fmt.Sprintf("%s - %s", country, city)
	if city == "未知" || city == "" { geoFormat = country }

	event := DropEvent{
		Time:      time.Now().Format("01-02 15:04:05"),
		Timestamp: time.Now().Unix(),
		IP:        ipStr,
		Geo:       geoFormat,
		Country:   country,
		Reason:    reason,
		Payload:   payload,
		Entropy:   entropy,
		Strikes:   record.TotalStrikes,
	}
	
	recentDrops = append([]DropEvent{event}, recentDrops...)
	if len(recentDrops) > 20 { recentDrops = recentDrops[:20] }

	if !isHistorical { totalBlocks++; todayBlocks++ }

	if mode == ModeDefense && !isHistorical {
		ipUint32, err := ipToUint32(ipStr)
		if err == nil {
			ebpfObjs.BlacklistMap.Put(ipUint32, uint64(time.Now().Unix()))
			bloomMutex.Lock()
			bloomFilter[ipStr] = true
			bloomMutex.Unlock()
			scheduleRelease(ipStr, ipUint32)
		}
	}
}

func initGeoIP() { geoDB, _ = geoip2.Open("GeoLite2-City.mmdb") }
func getGeoLocation(ipStr string) (string, string) {
	if geoDB == nil { return "未知", "未知" }
	ip := net.ParseIP(ipStr)
	record, err := geoDB.City(ip)
	if err != nil || record == nil { return "未知", "未知" }
	country := record.Country.Names["zh-CN"]
	city := record.City.Names["zh-CN"]
	if country == "" { country = record.Country.Names["en"] }
	if city == "" { city = record.City.Names["en"] }
	return country, city
}
func SanitizePayload(raw string) string { return sanitizeRegex.ReplaceAllString(raw, "$1=******") }
func ipToUint32(ipStr string) (uint32, error) {
	ip := net.ParseIP(ipStr).To4()
	if ip == nil { return 0, fmt.Errorf("invalid IPv4") }
	return binary.LittleEndian.Uint32(ip), nil
}

func loadHistoricalData() {
	file, err := os.Open("realm_logs.json")
	if err != nil { return }
	defer file.Close()
	bytes, _ := io.ReadAll(file)
	var logs []LogEntry
	json.Unmarshal(bytes, &logs)
	for _, entry := range logs {
		if entry.IP != "" {
			totalBlocks++
			stateMutex.Lock()
			record := getOrInitRecord(entry.IP)
			record.Reputation = 10.0 
			record.TotalStrikes += entry.StrikeCount
			stateMutex.Unlock()
			executeDropUnlocked(entry.IP, record, "历史遗留黑名单继承", "PRELOADED", 3.5, true)
		}
	}
}

// ==========================================
// 模块：Web UI 中心 (含增强版指挥官认证)
// ==========================================
func startWebServer() {
	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" { http.NotFound(w, r); return }
		http.ServeFile(w, r, "frontend.html")
	})

	mux.HandleFunc("/realm-admin-2026", func(w http.ResponseWriter, r *http.Request) {
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err == nil {
			// [关键修改] 1. 将 IP 加入 Go 层的持久化白名单，实现彻底静默
			authMutex.Lock()
			authenticatedIPs[host] = true
			authMutex.Unlock()

			ipUint32, err := ipToUint32(host)
			if err == nil {
				// 2. 将 IP 写入 eBPF 白名单 (内核层放行)
				ebpfObjs.AdminWhitelist.Put(ipUint32, uint32(1))
				
				// 3. 清理该 IP 的所有现有惩罚记录与锁定状态
				ebpfObjs.BlacklistMap.Delete(ipUint32)
				
				stateMutex.Lock()
				record := getOrInitRecord(host)
				record.Reputation = 100.0
				record.PenaltyBucket = 0.0
				stateMutex.Unlock()

				bloomMutex.Lock()
				delete(bloomFilter, host)
				delete(bannedIPsReleaseMap, host)
				bloomMutex.Unlock()
				
				log.Printf("🛡️ [绝对豁免] 指挥官已通过认证，IP: %s 现已在内核与应用层双重隐身。", host)
			}
		}
		http.ServeFile(w, r, "backend.html")
	})

	mux.HandleFunc("/api/stats", func(w http.ResponseWriter, r *http.Request) {
		stateMutex.RLock()
		defer stateMutex.RUnlock()
		json.NewEncoder(w).Encode(map[string]interface{}{
			"today_blocks": todayBlocks, 
			"total_blocks": totalBlocks, 
			"recent_drops": recentDrops,
		})
	})

	mux.HandleFunc("/api/admin/stats", func(w http.ResponseWriter, r *http.Request) {
		stateMutex.RLock()
		defer stateMutex.RUnlock()
		controller.RLock()
		defer controller.RUnlock()

		type ActiveBan struct { IP string `json:"ip"`; ReleaseTime int64 `json:"release_time"` }
		var activeBans []ActiveBan
		bloomMutex.RLock()
		for ip, releaseTime := range bannedIPsReleaseMap {
			activeBans = append(activeBans, ActiveBan{IP: ip, ReleaseTime: releaseTime})
		}
		bloomMutex.RUnlock()

		host, _, _ := net.SplitHostPort(r.RemoteAddr)

		json.NewEncoder(w).Encode(map[string]interface{}{
			"current_mode": controller.CurrentMode, 
			"active_bans":  activeBans,
			"recent_drops": recentDrops,
			"admin_ip":     host,
		})
	})

	mux.HandleFunc("/api/admin/mode", func(w http.ResponseWriter, r *http.Request) {
		var req struct{ Mode RunMode `json:"mode"` }
		json.NewDecoder(r.Body).Decode(&req)
		controller.Lock()
		controller.CurrentMode = req.Mode
		controller.Unlock()
		json.NewEncoder(w).Encode(map[string]string{"message": "底层引擎已切换为 " + string(req.Mode)})
	})

	srv := &http.Server{Addr: "0.0.0.0:80", Handler: mux}
	srv.ListenAndServe()
}

func main() {
	initGeoIP()
	if err := loadBpfObjects(&ebpfObjs, nil); err != nil { log.Fatalf("❌ 加载 eBPF 探针失败: %v", err) }
	defer ebpfObjs.Close()

	iface, _ := net.InterfaceByName("ens4")
	xdpLink, _ := link.AttachXDP(link.XDPOptions{Program: ebpfObjs.RealmXdpDrop, Interface: iface.Index, Flags: link.XDPGenericMode})
	defer xdpLink.Close()

	go startTrafficSniffer()
	startScarletSonar()
	loadHistoricalData()

	controller.Lock()
	controller.CurrentMode = ModeDefense
	controller.DefenseStartTime = time.Now()
	controller.Unlock()

	go startWebServer()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGTERM, os.Interrupt)
	<-stop
}
