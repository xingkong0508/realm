package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"math"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel bpf bpf/probe.c

// ====== 核心数学模块：香农熵定向计算 ======
func calculateEntropy(data string) float64 {
	if len(data) == 0 {
		return 0
	}
	counts := make(map[rune]int)
	for _, char := range data {
		counts[char]++
	}
	var entropy float64
	for _, count := range counts {
		p := float64(count) / float64(len(data))
		entropy -= p * math.Log2(p)
	}
	return entropy
}

// ====== 全局状态与核心组件 ======
type BanManager struct {
	sync.Mutex
	records map[string]time.Time
	objs    *bpfObjects
}

type LogEntry struct {
	IP          string    `json:"ip"`
	Port        string    `json:"port"`
	StrikeCount int       `json:"strike_count"`
	AttackType  string    `json:"attack_type"`
	Payload     string    `json:"payload"`
	Entropy     float64   `json:"entropy"`
	BanTime     time.Time `json:"ban_time"`
	Status      string    `json:"status"`
}

var (
	banMgr      *BanManager
	adminIPConf string
	adminPath   string // 新增：将写死的后门路径转为动态变量

	dbLogs   []LogEntry
	dbMutex  sync.Mutex
	dbFile   = "./realm_logs.json"

	dynamicWhitelist = make(map[string]bool)
	whitelistMutex   sync.Mutex

	pendingBans  = make(map[string]*time.Timer)
	pendingMutex sync.Mutex
)

func ipToMapKey(ipStr string) uint32 {
	ip := net.ParseIP(ipStr).To4()
	if ip == nil {
		return 0
	}
	return uint32(ip[0]) | uint32(ip[1])<<8 | uint32(ip[2])<<16 | uint32(ip[3])<<24
}

// ====== JSON 文档数据库引擎 ======
func initDB() {
	file, err := os.ReadFile(dbFile)
	if err == nil {
		json.Unmarshal(file, &dbLogs)
		log.Printf("[🗄️] 成功加载历史档案: %d 条", len(dbLogs))
	} else {
		log.Println("[🗄️] 初始化全新 JSON 文档数据库")
	}
}

func saveDB() {
	data, err := json.MarshalIndent(dbLogs, "", "  ")
	if err == nil {
		os.WriteFile(dbFile, data, 0644)
	}
}

func main() {
	ifaceName := flag.String("iface", "ens4", "要保护的网卡名称")
	adminIP := flag.String("admin", "", "网吧/固定白名单IP (可选)")
	// 新增：允许通过命令行修改管理面板路径，默认保持原样以防你忘记
	adminPathFlag := flag.String("path", "/realm-admin-2026", "后台管理面板的隐藏路径")
	flag.Parse()
	
	adminIPConf = *adminIP
	adminPath = *adminPathFlag // 赋值给全局变量

	initDB()

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal("无法移除内存锁定:", err)
	}

	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatal("加载 BPF 失败:", err)
	}
	defer objs.Close()

	banMgr = &BanManager{
		records: make(map[string]time.Time),
		objs:    &objs,
	}

	if adminIPConf != "" {
		key := ipToMapKey(adminIPConf)
		var val uint32 = 1
		objs.AdminWhitelist.Update(&key, &val, 0)
	}

	iface, err := net.InterfaceByName(*ifaceName)
	if err != nil {
		log.Fatalf("找不到网卡 %s", *ifaceName)
	}

	l, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpRealmProbe,
		Interface: iface.Index,
		Flags:     link.XDPGenericMode,
	})
	if err != nil {
		log.Fatalf("❌ 物理层挂载失败: %v", err)
	}
	defer l.Close()

	fmt.Printf("\n[🚀] Realm 2.5 (赛博黑客风完全体) 启动成功！\n")
	fmt.Printf("[🔑] 指挥官大屏: http://服务器IP:8080%s\n", adminPath)

	go banMgr.cleaner()
	go startHoneypot()

	// 启动底层 TCP 端口诱捕
	go startTCPBait("6379", "Redis数据库", "+PONG\r\n")
	go startTCPBait("2222", "古老SSH服务", "SSH-2.0-OpenSSH_5.3p1 Debian-3ubuntu7\r\n")
	go startTCPBait("2375", "Docker API", "HTTP/1.1 200 OK\r\n\r\n{\"ApiVersion\":\"1.24\"}")

	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)
	log.Println("[🛡️] 结界与声呐已同步开启，正在静默狩猎... (按 Ctrl+C 停止)")
	<-stopper
}

func startTCPBait(port, serviceName, fakeBanner string) {
	listener, err := net.Listen("tcp", "0.0.0.0:"+port)
	if err != nil {
		return
	}
	defer listener.Close()

	for {
		conn, err := listener.Accept()
		if err != nil {
			continue
		}
		remoteIP, remotePort, _ := net.SplitHostPort(conn.RemoteAddr().String())

		go func(c net.Conn, ip, prt string) {
			c.Write([]byte(fakeBanner))
			c.Close()
			executeBan(ip, prt, "高危诱饵触发 ("+serviceName+")", "TCP SYN -> "+port, 0.0)
		}(conn, remoteIP, remotePort)
	}
}

func startHoneypot() {
	mux := http.NewServeMux()
	mux.HandleFunc("/", handleTraffic)
	server := &http.Server{Addr: ":8080", Handler: mux, ReadTimeout: 5 * time.Second, WriteTimeout: 10 * time.Second}
	server.ListenAndServe()
}

func handleTraffic(w http.ResponseWriter, r *http.Request) {
	remoteAddr, remotePort, _ := net.SplitHostPort(r.RemoteAddr)

	if r.URL.Path == "/favicon.ico" {
		return
	}

	// -----------------------------------------------------
	// 【增量优化：赛博朋克风的公开防御榜示 (正常用户通道)】
	// -----------------------------------------------------
	if r.URL.Path == "/" || r.URL.Path == "/index.html" || r.URL.Path == "/about" {
		dbMutex.Lock()
		totalBans := len(dbLogs)
		todayBans := 0
		now := time.Now()

		for i := len(dbLogs) - 1; i >= 0; i-- {
			if dbLogs[i].BanTime.YearDay() == now.YearDay() {
				todayBans++
			} else {
				break
			}
		}

		var latest10 string
		count := 0
		for i := len(dbLogs) - 1; i >= 0 && count < 10; i-- {
			entry := dbLogs[i]
			parts := strings.Split(entry.IP, ".")
			masked := entry.IP
			if len(parts) == 4 {
				masked = fmt.Sprintf("%s.%s.*.*", parts[0], parts[1])
			}
			latest10 += fmt.Sprintf("<tr style='border-bottom:1px solid #222;'><td style='padding:12px; color:#ff4444; font-family:monospace;'>%s</td><td style='padding:12px; color:#aaa; font-family:monospace;'>%s</td></tr>", masked, entry.BanTime.Format("2006-01-02 15:04:05"))
			count++
		}
		if latest10 == "" {
			latest10 = "<tr><td colspan='2' style='padding:15px; text-align:center; color:#555;'>今日暂无猎物落网</td></tr>"
		}
		dbMutex.Unlock()

		html := fmt.Sprintf(`<html><head><meta charset="utf-8">
		<style>
			body { background-color: #050505; color: #eee; font-family: -apple-system, sans-serif; text-align: center; padding: 40px; margin: 0; }
			.container { max-width: 800px; margin: 0 auto; background: #0a0a0a; border: 1px solid #1a1a1a; border-radius: 12px; box-shadow: 0 0 30px rgba(0, 175, 255, 0.05); padding: 40px; }
			h1 { color: #00afff; text-shadow: 0 0 10px rgba(0, 175, 255, 0.3); letter-spacing: 2px; }
			.status { color: #00ff00; font-family: monospace; background: #051a05; padding: 10px; border-radius: 4px; border: 1px solid #004400; margin-bottom: 30px; display: inline-block; }
			.stats-box { display: flex; justify-content: space-around; background: #111; padding: 25px; border-radius: 8px; border: 1px solid #222; margin-bottom: 30px; }
			.stat-num { font-size: 48px; font-weight: bold; }
			.stat-label { color: #888; font-size: 14px; text-transform: uppercase; letter-spacing: 1px; margin-top: 5px; }
			table { width: 100%%; border-collapse: collapse; text-align: left; background: #080808; border-radius: 8px; overflow: hidden; }
			th { background: #111; padding: 15px; color: #00afff; border-bottom: 2px solid #222; }
		</style>
		</head><body>
			<div class="container">
				<h1>🛡️ REALM SERVER 防御结界</h1>
				<div class="status">> 访客通道正常开启。底层 L3 内核级防御正在静默运作。</div>
				
				<div class="stats-box">
					<div><div class="stat-num" style="color:#ffaa00;">%d</div><div class="stat-label">今日拦截数 (Today)</div></div>
					<div><div class="stat-num" style="color:#ff4444;">%d</div><div class="stat-label">总计斩首数 (Total)</div></div>
				</div>
				
				<h3 style="color:#ccc; text-align:left; border-left:4px solid #ff4444; padding-left:10px;">💀 自动处刑榜单 (最新10条脱敏记录)</h3>
				<table><tr><th>封禁源 IP (掩码保护)</th><th>被斩首时间</th></tr>%s</table>
			</div>
		</body></html>`, todayBans, totalBans, latest10)

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte(html))
		return
	}

	// -----------------------------------------------------
	// 原有防误杀、特赦与死缓逻辑 (全量保留无删减)
	// -----------------------------------------------------
	whitelistMutex.Lock()
	isWhitelisted := dynamicWhitelist[remoteAddr]
	whitelistMutex.Unlock()

	// 替换为动态变量 adminPath
	if (remoteAddr == adminIPConf && adminIPConf != "") || isWhitelisted {
		if r.URL.Path == adminPath {
			sendAdminDashboard(w, remoteAddr)
		} else {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Write([]byte("<h2>🛡️ 您正在免死金牌保护下浏览</h2>"))
		}
		return
	}

	// 替换为动态变量 adminPath
	if r.URL.Path == adminPath {
		whitelistMutex.Lock()
		dynamicWhitelist[remoteAddr] = true
		whitelistMutex.Unlock()

		key := ipToMapKey(remoteAddr)
		var val uint32 = 1
		banMgr.objs.AdminWhitelist.Update(&key, &val, 0)

		pendingMutex.Lock()
		if timer, ok := pendingBans[remoteAddr]; ok {
			timer.Stop()
			delete(pendingBans, remoteAddr)
		}
		pendingMutex.Unlock()

		sendAdminDashboard(w, remoteAddr)
		return
	}

	sendHackerResponse(w, remoteAddr)

	payload := r.Method + " " + r.URL.Path + "?" + r.URL.RawQuery
	entropy := calculateEntropy(payload)

	attackType := "常规盲扫"
	if strings.Contains(r.URL.Path, "login") || strings.Contains(r.URL.Path, "admin") {
		attackType = "撞库尝试"
	} else if strings.Contains(r.URL.Path, ".env") || strings.Contains(r.URL.Path, "phpinfo") {
		attackType = "高危漏洞探测"
	} else if entropy > 4.2 {
		attackType = "高熵混淆攻击"
	}

	pendingMutex.Lock()
	if _, exists := pendingBans[remoteAddr]; !exists {
		timer := time.AfterFunc(15*time.Second, func() {
			executeBan(remoteAddr, remotePort, attackType, payload, entropy)
			pendingMutex.Lock()
			delete(pendingBans, remoteAddr)
			pendingMutex.Unlock()
		})
		pendingBans[remoteAddr] = timer
	}
	pendingMutex.Unlock()
}

func executeBan(ipStr, port, attackType, payload string, entropy float64) {
	whitelistMutex.Lock()
	if dynamicWhitelist[ipStr] {
		whitelistMutex.Unlock()
		return
	}
	whitelistMutex.Unlock()

	banMgr.banIP(ipStr)

	dbMutex.Lock()
	strikeCount := 1
	for _, log := range dbLogs {
		if log.IP == ipStr {
			strikeCount++
		}
	}

	newEntry := LogEntry{
		IP:          ipStr,
		Port:        port,
		StrikeCount: strikeCount,
		AttackType:  attackType,
		Payload:     payload,
		Entropy:     entropy,
		BanTime:     time.Now(),
		Status:      "BANNED",
	}
	dbLogs = append(dbLogs, newEntry)
	dbMutex.Unlock()
	saveDB()
}

func (m *BanManager) banIP(ipStr string) {
	m.Lock()
	defer m.Unlock()
	if _, exists := m.records[ipStr]; exists {
		return
	}
	key := ipToMapKey(ipStr)
	if key == 0 {
		return
	}
	var val uint32 = 1
	m.objs.BlackList.Update(&key, &val, 0)
	m.records[ipStr] = time.Now()
}

func (m *BanManager) cleaner() {
	ticker := time.NewTicker(30 * time.Second)
	for range ticker.C {
		m.Lock()
		now := time.Now()
		for ipStr, banTime := range m.records {
			if now.Sub(banTime) >= 10*time.Minute {
				key := ipToMapKey(ipStr)
				m.objs.BlackList.Delete(&key)
				delete(m.records, ipStr)

				dbMutex.Lock()
				for i := len(dbLogs) - 1; i >= 0; i-- {
					if dbLogs[i].IP == ipStr && dbLogs[i].Status == "BANNED" {
						dbLogs[i].Status = "RELEASED"
						break
					}
				}
				dbMutex.Unlock()
				saveDB()
			}
		}
		m.Unlock()
	}
}

// ====== 动态 UI 渲染工厂 (全量保留您截图中的精美 UI) ======
func sendAdminDashboard(w http.ResponseWriter, visitorIP string) {
	banMgr.Lock()
	var liveRows string
	now := time.Now()
	for ip, banTime := range banMgr.records {
		rem := 10*time.Minute - now.Sub(banTime)
		liveRows += fmt.Sprintf("<tr style='border-bottom:1px solid #333'><td><span class='live-dot'></span></td><td style='color:#ff5555'>%s</td><td style='color:#00ff00'>%.0f秒后释放</td></tr>", ip, rem.Seconds())
	}
	banMgr.Unlock()
	if liveRows == "" {
		liveRows = "<tr><td colspan='3' style='text-align:center;padding:15px;color:#666;'>结界内暂无活跃囚犯</td></tr>"
	}

	dbMutex.Lock()
	var historyRows string
	startIdx := len(dbLogs) - 20
	if startIdx < 0 {
		startIdx = 0
	}
	for i := len(dbLogs) - 1; i >= startIdx; i-- {
		entry := dbLogs[i]
		statusColor := "#00ff00"
		if entry.Status == "BANNED" {
			statusColor = "#ff0000"
		}
		entropyStr := fmt.Sprintf("%.2f", entry.Entropy)
		if entry.Entropy == 0 {
			entropyStr = "-"
		}
		historyRows += fmt.Sprintf("<tr style='border-bottom:1px solid #222; font-size:14px; color:#aaa;'><td>%s</td><td>%d次</td><td style='color:#00ffff'>%s</td><td style='color:#ffaa00'>%s</td><td>%s</td><td>%s</td><td style='color:%s'>%s</td></tr>",
			entry.IP, entry.StrikeCount, entropyStr, entry.AttackType, entry.Payload, entry.BanTime.Format("01-02 15:04:05"), statusColor, entry.Status)
	}
	dbMutex.Unlock()

	html := fmt.Sprintf(`
	<html><head><meta charset="utf-8">
	<style>
		body {background:#0a0a0a; color:#eee; font-family:-apple-system,sans-serif; padding:20px;}
		.panel {background:#111; border:1px solid #333; border-radius:8px; padding:20px; margin-bottom:20px;}
		table {width:100%%; border-collapse:collapse; text-align:left;}
		th {background:#222; padding:10px; color:#00afff; font-size:14px;}
		td {padding:10px;}
		.live-dot {height:8px; width:8px; background-color:red; border-radius:50%%; display:inline-block; box-shadow: 0 0 5px red;}
	</style>
	</head><body>
		<div style="display:flex; justify-content:space-between; align-items:center;">
			<h2 style="color:#00afff;">🛡️ Realm 2.5 战术指挥中心 (含熵审判)</h2>
			<span style="background:#222; padding:5px 15px; border-radius:20px; font-size:12px;">✅ 身份认证: %s</span>
		</div>
		<div class="panel">
			<h3 style="color:#fff;">📡 实况雷达 (L3内核锁定中)</h3>
			<table><tr><th>状态</th><th>囚犯 IP</th><th>剩余刑期</th></tr>%s</table>
		</div>
		<div class="panel">
			<h3 style="color:#fff;">🗄️ 全量威胁档案馆 (Top 20)</h3>
			<table><tr><th>源 IP</th><th>执着度</th><th>混乱度(熵)</th><th>威胁定性</th><th>攻击载荷</th><th>案发时间</th><th>当前状态</th></tr>%s</table>
		</div>
		<script>setTimeout(function(){ window.location.reload(); }, 10000);</script>
	</body></html>`, visitorIP, liveRows, historyRows)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(html))
}

func sendHackerResponse(w http.ResponseWriter, hackerIP string) {
	dbMutex.Lock()
	var shameRows string
	count := 0
	for i := len(dbLogs) - 1; i >= 0 && count < 5; i-- {
		if dbLogs[i].IP != hackerIP {
			parts := strings.Split(dbLogs[i].IP, dbLogs[i].IP)
			masked := dbLogs[i].IP
			if len(parts) == 4 {
				masked = fmt.Sprintf("%s.%s.*.*", parts[0], parts[1])
			}
			shameRows += fmt.Sprintf("<tr><td style='padding:5px;'>%s</td><td style='padding:5px; color:#aa0000;'>%s</td></tr>", masked, dbLogs[i].AttackType)
			count++
		}
	}
	dbMutex.Unlock()

	if shameRows == "" {
		shameRows = "<tr><td colspan='2' style='padding:5px; color:#555;'>数据档案初始化中...</td></tr>"
	}

	html := fmt.Sprintf(`<html><head><meta charset="utf-8">
	<style>
		body {background:black; color:red; padding:40px; font-family:monospace; text-align:center;}
		.box {border: 1px solid #550000; display:inline-block; padding:30px; background:#110000;}
		.shame {border: 1px solid #330000; width: 100%%; margin-top:20px; text-align:left; color:#880000;}
		#timer {font-size: 60px; font-weight: bold; color: #ff3333; text-shadow: 0 0 10px red;}
	</style>
	</head><body>
		<div class="box">
			<h1>[ REALM 结界防御系统 ]</h1><hr style="border-color:#550000;">
			<p style="font-size:18px;">> 警告：检测到你的非法访问行为或高熵混淆探测。</p>
			<p>> 状态：系统已锁定你的设备特征，通讯链路即将切断。</p>
			<div id="timer">10</div>
			<p>> 倒计时结束后，你将被物理丢弃。</p>
			<table class="shame"><tr><th colspan="2" style="padding:10px; background:#220000;">💀 近期被斩首者档案</th></tr>%s</table>
		</div>
		<script>
			let count = 10;
			let t = setInterval(function(){
				count--;
				document.getElementById('timer').innerText = count;
				if(count <= 0) {
					clearInterval(t);
					document.getElementById('timer').innerText = "CONNECTION LOST";
					document.getElementById('timer').style.color = "#444";
					document.getElementById('timer').style.textShadow = "none";
				}
			}, 1000);
		</script>
	</body></html>`, shameRows)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(html))
}
