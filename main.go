package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/cloudflare/cloudflare-go"
	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"github.com/robfig/cron/v3"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

// ================= 模型定义 =================

type User struct {
	gorm.Model
	Username        string `gorm:"unique"`
	Password        string
	LoginAttempts   int
	LastLoginFailed time.Time
}

type Setting struct {
	gorm.Model
	CFToken          string
	TelegramBotToken string
	TelegramChatID   string
}

type Domain struct {
	gorm.Model
	ZoneID        string
	RecordName    string
	RecordType    string
	Proxied       bool
	LastIP        string
	Status        string
	LastMsg       string
	IPSource      string // "api" or "interface"
	InterfaceName string // e.g., "eth0"
}

type SystemLog struct {
	ID        uint `gorm:"primarykey"`
	CreatedAt time.Time
	Level     string
	Message   string
}

type IPHistory struct {
	ID         uint `gorm:"primarykey"`
	CreatedAt  time.Time
	RecordName string
	RecordType string
	OldIP      string
	NewIP      string
}

type DashboardStats struct {
	TotalDomains int64
	LastRunTime  string
	SuccessCount int64
	ErrorCount   int64
}

type BackupData struct {
	Setting Setting  `json:"setting"`
	Domains []Domain `json:"domains"`
}

// ================= 全局变量 =================

var (
	db          *gorm.DB
	lastRunTime time.Time
	runMutex    sync.Mutex
)

// ================= 核心逻辑 =================

var ipProvidersV4 = []string{"https://api.ipify.org", "https://api-ipv4.ip.sb/ip", "https://ipv4.icanhazip.com"}
var ipProvidersV6 = []string{"https://api64.ipify.org", "https://api-ipv6.ip.sb/ip", "https://ipv6.icanhazip.com"}

func getValidInterfaces() ([]string, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var names []string
	for _, i := range ifaces {
		if i.Flags&net.FlagUp == 0 {
			continue
		}
		if i.Flags&net.FlagLoopback != 0 {
			continue
		}
		names = append(names, i.Name)
	}
	return names, nil
}

func getInterfaceIP(ifaceName, ipType string) (string, error) {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return "", err
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return "", err
	}
	for _, addr := range addrs {
		ipNet, ok := addr.(*net.IPNet)
		if !ok || ipNet.IP.IsLoopback() {
			continue
		}
		ip := ipNet.IP
		if ipType == "tcp4" || ipType == "A" {
			if ip.To4() != nil {
				return ip.String(), nil
			}
		} else if ipType == "tcp6" || ipType == "AAAA" {
			if ip.To4() == nil && !ip.IsLinkLocalUnicast() {
				return ip.String(), nil
			}
		}
	}
	return "", fmt.Errorf("网卡 %s 上未找到 %s 地址", ifaceName, ipType)
}

func getPublicIP(ipType string) (string, error) {
	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				netType := "tcp4"
				if ipType == "AAAA" || ipType == "tcp6" {
					netType = "tcp6"
				}
				return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, netType, addr)
			},
		},
		Timeout: 8 * time.Second,
	}
	providers := ipProvidersV4
	if ipType == "AAAA" || ipType == "tcp6" {
		providers = ipProvidersV6
	}
	for _, url := range providers {
		resp, err := client.Get(url)
		if err == nil {
			defer resp.Body.Close()
			body, _ := io.ReadAll(resp.Body)
			ip := strings.TrimSpace(string(body))
			if ip != "" {
				return ip, nil
			}
		}
	}
	return "", fmt.Errorf("所有 IP 接口均访问失败")
}

func addLog(level, msg string) {
	db.Create(&SystemLog{Level: level, Message: msg})
	var count int64
	db.Model(&SystemLog{}).Count(&count)
	if count > 2000 {
		db.Where("id IN (?)", db.Model(&SystemLog{}).Select("id").Order("id asc").Limit(500)).Delete(&SystemLog{})
	}
}

func addHistory(name, rType, oldIP, newIP string) {
	db.Create(&IPHistory{RecordName: name, RecordType: rType, OldIP: oldIP, NewIP: newIP})
	var count int64
	db.Model(&IPHistory{}).Count(&count)
	if count > 100 {
		db.Where("id IN (?)", db.Model(&IPHistory{}).Select("id").Order("id asc").Limit(20)).Delete(&IPHistory{})
	}
}

func sendTelegramNotification(token, chatID, message string) error {
	if token == "" || chatID == "" {
		return nil
	}
	url := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", token)
	body, _ := json.Marshal(map[string]string{"chat_id": chatID, "text": message, "parse_mode": "HTML"})
	http.Post(url, "application/json", bytes.NewBuffer(body))
	return nil
}

func findZoneID(api *cloudflare.API, domain string) (string, error) {
	id, err := api.ZoneIDByName(domain)
	if err == nil {
		return id, nil
	}
	parts := strings.Split(domain, ".")
	for i := 1; i < len(parts)-1; i++ {
		rootDomain := strings.Join(parts[i:], ".")
		id, err := api.ZoneIDByName(rootDomain)
		if err == nil {
			return id, nil
		}
	}
	return "", fmt.Errorf("未找到 ZoneID，请检查域名拼写或 API 权限")
}

func runDDNS() {
	if !runMutex.TryLock() {
		return
	}
	defer runMutex.Unlock()
	lastRunTime = time.Now()

	var setting Setting
	if err := db.First(&setting).Error; err != nil || setting.CFToken == "" {
		return
	}

	api, err := cloudflare.NewWithAPIToken(setting.CFToken)
	if err != nil {
		addLog("ERROR", "Cloudflare API 初始化失败: "+err.Error())
		return
	}

	ipCache := make(map[string]string)
	
	getIPWithCache := func(d Domain) (string, error) {
		var cacheKey string
		if d.IPSource == "interface" {
			cacheKey = fmt.Sprintf("iface_%s_%s", d.InterfaceName, d.RecordType)
		} else {
			cacheKey = fmt.Sprintf("api_%s", d.RecordType)
		}

		if ip, ok := ipCache[cacheKey]; ok {
			if ip == "" { return "", fmt.Errorf("pre-fail") }
			return ip, nil
		}

		var ip string
		var err error
		if d.IPSource == "interface" {
			ip, err = getInterfaceIP(d.InterfaceName, d.RecordType)
		} else {
			ip, err = getPublicIP(d.RecordType)
		}

		if err != nil {
			ipCache[cacheKey] = ""
			return "", err
		}
		ipCache[cacheKey] = ip
		return ip, nil
	}

	var domains []Domain
	db.Find(&domains)

	for _, d := range domains {
		currentIP, err := getIPWithCache(d)
		
		if err != nil || currentIP == "" {
			if d.Status != "Error" {
				d.Status = "Error"
				d.LastMsg = "IP 获取失败"
				db.Save(&d)
				addLog("ERROR", fmt.Sprintf("[%s] 获取 IP 失败: %v", d.RecordName, err))
			}
			continue
		}

		if d.LastIP == currentIP && d.Status == "Synced" {
			continue
		}

		if d.ZoneID == "" {
			zid, err := findZoneID(api, d.RecordName)
			if err == nil {
				d.ZoneID = zid
				db.Save(&d)
			} else {
				addLog("ERROR", fmt.Sprintf("[%s] ZoneID 缺失且自动获取失败: %v", d.RecordName, err))
				continue
			}
		}

		records, _, err := api.ListDNSRecords(context.Background(), cloudflare.ZoneIdentifier(d.ZoneID), cloudflare.ListDNSRecordsParams{
			Name: d.RecordName, Type: d.RecordType,
		})

		if err != nil || len(records) == 0 {
			d.Status = "Error"
			d.LastMsg = "Cloudflare 上找不到该记录"
			db.Save(&d)
			addLog("ERROR", fmt.Sprintf("[%s] %s", d.RecordName, d.LastMsg))
			continue
		}

		record := records[0]
		if record.Content == currentIP && d.Status == "Synced" {
			d.LastIP = currentIP
			db.Save(&d)
			continue
		}

		_, err = api.UpdateDNSRecord(context.Background(), cloudflare.ZoneIdentifier(d.ZoneID), cloudflare.UpdateDNSRecordParams{
			ID: record.ID, Type: d.RecordType, Name: d.RecordName, Content: currentIP, Proxied: &d.Proxied,
		})

		if err != nil {
			d.Status = "Error"
			d.LastMsg = err.Error()
			addLog("ERROR", fmt.Sprintf("[%s] 更新失败: %v", d.RecordName, err))
		} else {
			oldIP := d.LastIP
			if oldIP == "" {
				oldIP = "首次设置"
			}
			d.Status = "Synced"
			d.LastIP = currentIP
			d.LastMsg = "同步成功"
			
			addHistory(d.RecordName, d.RecordType, oldIP, currentIP)
			addLog("SUCCESS", fmt.Sprintf("[%s] IP 更新成功: %s -> %s", d.RecordName, oldIP, currentIP))
			
			msg := fmt.Sprintf("✅ <b>IP 更新成功</b>\n\n域名: <code>%s</code>\n类型: %s\n来源: %s\n变更: <code>%s</code> -> <code>%s</code>", d.RecordName, d.RecordType, d.IPSource, oldIP, currentIP)
			go sendTelegramNotification(setting.TelegramBotToken, setting.TelegramChatID, msg)
		}
		db.Save(&d)
	}
}

// ================= Main =================

func main() {
	var err error
	db, err = gorm.Open(sqlite.Open("ddns_panel.db"), &gorm.Config{})
	if err != nil {
		panic("无法连接数据库")
	}
	db.AutoMigrate(&User{}, &Setting{}, &Domain{}, &SystemLog{}, &IPHistory{})
	if db.First(&Setting{}).Error != nil {
		db.Create(&Setting{})
	}

	c := cron.New()
	c.AddFunc("@every 5m", runDDNS)
	c.Start()

	gin.SetMode(gin.ReleaseMode)
	r := gin.Default()
	r.MaxMultipartMemory = 8 << 20 // 8 MiB

	store := cookie.NewStore([]byte("s3cr3t_k3y_g3n3r4t3d_r4nd0mly"))
	store.Options(sessions.Options{Path: "/", MaxAge: 86400 * 7, HttpOnly: true, Secure: false})
	r.Use(sessions.Sessions("ddns_session", store))
	r.Use(InstallMiddleware())

	t := template.New("base")
	t.New("common_header").Parse(commonHeaderHTML)
	t.New("common_footer").Parse(commonFooterHTML)
	t.New("login").Parse(loginHTML)
	t.New("install").Parse(installHTML)
	t.New("dashboard").Parse(dashboardHTML)
	t.New("settings").Parse(settingsHTML)
	t.New("logs").Parse(logsHTML)
	r.SetHTMLTemplate(t)

	r.GET("/install", func(c *gin.Context) { c.HTML(200, "install", nil) })
	r.POST("/do-install", handleInstall)
	r.GET("/login", func(c *gin.Context) { c.HTML(200, "login", nil) })
	r.POST("/do-login", handleLogin)
	r.GET("/logout", func(c *gin.Context) {
		s := sessions.Default(c)
		s.Clear()
		s.Save()
		c.Redirect(302, "/login")
	})

	auth := r.Group("/", AuthMiddleware())
	{
		auth.GET("/", handleDashboard)
		auth.GET("/api/interfaces", handleGetInterfaces)

		auth.GET("/settings", handleSettings)
		auth.POST("/settings/update", handleUpdateSettings)
		auth.POST("/settings/password", handleUpdatePassword)
		auth.POST("/settings/test-tg", handleTestTG)
		auth.GET("/settings/backup", handleBackup)
		auth.POST("/settings/restore", handleRestore)

		auth.GET("/logs", handleLogs)
		auth.GET("/logs/clear", handleClearLogs)
		auth.POST("/domain/add", handleAddDomain)
		auth.POST("/domain/update", handleUpdateDomain)
		auth.GET("/domain/delete/:id", handleDeleteDomain)
		auth.GET("/domain/sync", handleForceSync)
	}

	fmt.Println("---------------------------------------")
	fmt.Println("   Go DDNS Panel 已启动")
	fmt.Println("   访问地址: http://localhost:8080")
	fmt.Println("---------------------------------------")
	r.Run(":8080")
}

// ================= 中间件与处理函数 =================

func AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if sessions.Default(c).Get("user") == nil {
			c.Redirect(302, "/login")
			c.Abort()
			return
		}
		c.Next()
	}
}

func InstallMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		var count int64
		db.Model(&User{}).Count(&count)
		path := c.Request.URL.Path
		if count == 0 && path != "/install" && path != "/do-install" {
			c.Redirect(302, "/install")
			c.Abort()
			return
		}
		if count > 0 && (path == "/install" || path == "/do-install") {
			c.Redirect(302, "/")
			c.Abort()
			return
		}
		c.Next()
	}
}

func setFlash(c *gin.Context, t, m string) {
	s := sessions.Default(c)
	s.AddFlash(m, t)
	s.Save()
}

func handleGetInterfaces(c *gin.Context) {
	names, err := getValidInterfaces()
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, names)
}

func handleInstall(c *gin.Context) {
	u, p := c.PostForm("username"), c.PostForm("password")
	if len(u) < 3 {
		c.HTML(200, "install", gin.H{"Error": "账号过短"})
		return
	}
	h, _ := bcrypt.GenerateFromPassword([]byte(p), bcrypt.DefaultCost)
	db.Create(&User{Username: u, Password: string(h)})
	c.Redirect(302, "/login")
}

func handleLogin(c *gin.Context) {
	u, p := c.PostForm("username"), c.PostForm("password")
	var user User
	if err := db.Where("username = ?", u).First(&user).Error; err != nil {
		c.HTML(200, "login", gin.H{"Error": "用户不存在"})
		return
	}
	if user.LoginAttempts >= 5 {
		if time.Since(user.LastLoginFailed) < 15*time.Minute {
			timeLeft := 15 - int(time.Since(user.LastLoginFailed).Minutes())
			c.HTML(200, "login", gin.H{"Error": fmt.Sprintf("尝试次数过多，请等待 %d 分钟", timeLeft)})
			return
		} else {
			user.LoginAttempts = 0
			db.Save(&user)
		}
	}
	if bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(p)) != nil {
		user.LoginAttempts++
		user.LastLoginFailed = time.Now()
		db.Save(&user)
		left := 5 - user.LoginAttempts
		c.HTML(200, "login", gin.H{"Error": fmt.Sprintf("密码错误，还剩 %d 次尝试机会", left)})
		return
	}
	user.LoginAttempts = 0
	db.Save(&user)
	s := sessions.Default(c)
	s.Set("user", user.Username)
	s.Save()
	c.Redirect(302, "/")
}

func handleDashboard(c *gin.Context) {
	var domains []Domain
	db.Find(&domains)
	var history []IPHistory
	db.Order("created_at desc").Limit(10).Find(&history)

	stats := DashboardStats{TotalDomains: int64(len(domains)), LastRunTime: "从未"}
	if !lastRunTime.IsZero() {
		stats.LastRunTime = lastRunTime.Format("15:04:05")
	}
	for _, d := range domains {
		if d.Status == "Synced" {
			stats.SuccessCount++
		}
		if d.Status == "Error" {
			stats.ErrorCount++
		}
	}
	s := sessions.Default(c)
	flashes := s.Flashes()
	s.Save()
	c.HTML(200, "dashboard", gin.H{
		"Page": "dashboard", "Domains": domains, "History": history, "Stats": stats, "Flashes": flashes,
	})
}

func handleUpdatePassword(c *gin.Context) {
	username := sessions.Default(c).Get("user").(string)
	oldPass, newPass := c.PostForm("old_password"), c.PostForm("new_password")
	var user User
	if db.Where("username = ?", username).First(&user).Error != nil {
		setFlash(c, "error", "用户不存在")
		c.Redirect(302, "/settings")
		return
	}
	if bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(oldPass)) != nil {
		setFlash(c, "error", "原密码错误")
		c.Redirect(302, "/settings")
		return
	}
	if len(newPass) < 5 {
		setFlash(c, "error", "新密码太短")
		c.Redirect(302, "/settings")
		return
	}
	h, _ := bcrypt.GenerateFromPassword([]byte(newPass), bcrypt.DefaultCost)
	user.Password = string(h)
	db.Save(&user)
	setFlash(c, "success", "密码修改成功，请重新登录")
	s := sessions.Default(c)
	s.Clear()
	s.Save()
	c.Redirect(302, "/login")
}

func handleSettings(c *gin.Context) {
	var s Setting
	db.First(&s)
	username := sessions.Default(c).Get("user").(string)
	sess := sessions.Default(c)
	flashes := sess.Flashes()
	sess.Save()
	c.HTML(200, "settings", gin.H{"Page": "settings", "Setting": s, "Username": username, "Flashes": flashes})
}

func handleUpdateSettings(c *gin.Context) {
	var s Setting
	db.First(&s)
	s.CFToken = c.PostForm("token")
	s.TelegramBotToken = c.PostForm("tg_token")
	s.TelegramChatID = c.PostForm("tg_chat_id")
	db.Save(&s)
	setFlash(c, "success", "设置已保存")
	c.Redirect(302, "/settings")
}

func handleBackup(c *gin.Context) {
	var s Setting
	db.First(&s)
	var d []Domain
	db.Find(&d)
	data := BackupData{Setting: s, Domains: d}
	jsonBytes, _ := json.MarshalIndent(data, "", "  ")
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=ddns_backup_%s.json", time.Now().Format("20060102")))
	c.Data(200, "application/json", jsonBytes)
}

func handleRestore(c *gin.Context) {
	file, _, err := c.Request.FormFile("backup_file")
	if err != nil {
		setFlash(c, "error", "文件上传失败")
		c.Redirect(302, "/settings")
		return
	}
	defer file.Close()
	var data BackupData
	if err := json.NewDecoder(file).Decode(&data); err != nil {
		setFlash(c, "error", "JSON 解析失败")
		c.Redirect(302, "/settings")
		return
	}
	var s Setting
	db.First(&s)
	s.CFToken = data.Setting.CFToken
	s.TelegramBotToken = data.Setting.TelegramBotToken
	s.TelegramChatID = data.Setting.TelegramChatID
	db.Save(&s)
	for _, newD := range data.Domains {
		var oldD Domain
		if err := db.Where("record_name = ? AND record_type = ?", newD.RecordName, newD.RecordType).First(&oldD).Error; err == nil {
			oldD.Proxied = newD.Proxied
			oldD.ZoneID = newD.ZoneID
			oldD.IPSource = newD.IPSource
			oldD.InterfaceName = newD.InterfaceName
			db.Save(&oldD)
		} else {
			newD.ID = 0
			db.Create(&newD)
		}
	}
	setFlash(c, "success", "系统配置已恢复")
	c.Redirect(302, "/settings")
}

func handleTestTG(c *gin.Context) {
	if err := sendTelegramNotification(c.PostForm("tg_token"), c.PostForm("tg_chat_id"), "🔔 <b>测试消息</b>"); err != nil {
		setFlash(c, "error", "发送失败: "+err.Error())
	} else {
		setFlash(c, "success", "发送成功")
	}
	c.Redirect(302, "/settings")
}

func handleLogs(c *gin.Context) {
	var logs []SystemLog
	db.Order("created_at desc").Limit(200).Find(&logs)
	c.HTML(200, "logs", gin.H{"Page": "logs", "Logs": logs})
}

func handleClearLogs(c *gin.Context) {
	if err := db.Exec("DELETE FROM system_logs").Error; err != nil {
		setFlash(c, "error", "清空失败: "+err.Error())
	} else {
		setFlash(c, "success", "日志已全部清空")
	}
	c.Redirect(302, "/logs")
}

func handleAddDomain(c *gin.Context) {
	var setting Setting
	if err := db.First(&setting).Error; err != nil || setting.CFToken == "" {
		setFlash(c, "error", "请先配置 Cloudflare API Token")
		c.Redirect(302, "/")
		return
	}
	api, err := cloudflare.NewWithAPIToken(setting.CFToken)
	if err != nil {
		setFlash(c, "error", "API 初始化失败")
		c.Redirect(302, "/")
		return
	}
	recordName := c.PostForm("record_name")
	zoneID, err := findZoneID(api, recordName)
	if err != nil {
		setFlash(c, "error", "未找到 ZoneID: "+err.Error())
		c.Redirect(302, "/")
		return
	}

	ipSource := c.PostForm("ip_source")
	if ipSource == "" { ipSource = "api" }

	db.Create(&Domain{
		ZoneID: zoneID, RecordName: recordName,
		RecordType: c.PostForm("record_type"), Proxied: c.PostForm("proxied") == "on", 
		Status: "Pending", IPSource: ipSource, InterfaceName: c.PostForm("interface_name"),
	})
	go runDDNS()
	setFlash(c, "success", "域名添加成功，正在后台同步...")
	c.Redirect(302, "/")
}

func handleUpdateDomain(c *gin.Context) {
	var domain Domain
	id := c.PostForm("id")
	if err := db.First(&domain, id).Error; err != nil {
		setFlash(c, "error", "域名不存在")
		c.Redirect(302, "/")
		return
	}
	newName := c.PostForm("record_name")
	newType := c.PostForm("record_type")
	newProxied := c.PostForm("proxied") == "on"
	newIPSource := c.PostForm("ip_source")
	newInterface := c.PostForm("interface_name")

	if domain.RecordName != newName || domain.RecordType != newType || domain.IPSource != newIPSource || domain.InterfaceName != newInterface {
		domain.Status = "Pending"
		domain.LastMsg = "配置已修改，等待同步"
		domain.ZoneID = ""
	}
	domain.RecordName = newName
	domain.RecordType = newType
	domain.Proxied = newProxied
	domain.IPSource = newIPSource
	domain.InterfaceName = newInterface

	db.Save(&domain)
	go runDDNS()
	setFlash(c, "success", "域名修改成功")
	c.Redirect(302, "/")
}

func handleDeleteDomain(c *gin.Context) {
	db.Delete(&Domain{}, c.Param("id"))
	setFlash(c, "success", "域名已删除")
	c.Redirect(302, "/")
}

func handleForceSync(c *gin.Context) {
	go runDDNS()
	setFlash(c, "success", "正在后台同步...")
	time.Sleep(500 * time.Millisecond)
	c.Redirect(302, "/")
}

// ================= UI 优化版模板 =================

const commonHeaderHTML = `
<!DOCTYPE html>
<html lang="zh">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DDNS Master</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.10.5/font/bootstrap-icons.css">
    <style>
        :root {
            --primary-color: #6366f1; /* Indigo */
            --primary-hover: #4f46e5;
            --sidebar-bg: #1e1e2d;
            --sidebar-text: #a2a3b7;
            --sidebar-active-bg: rgba(255, 255, 255, 0.08);
            --sidebar-active-text: #ffffff;
            --body-bg: #f5f8fa;
            --card-border-radius: 12px;
            --font-family: 'Inter', system-ui, -apple-system, sans-serif;
        }

        body {
            background-color: var(--body-bg);
            font-family: var(--font-family);
            color: #3f4254;
            font-size: 0.925rem;
        }

        /* 侧边栏样式优化 */
        .wrapper { display: flex; min-height: 100vh; }
        .sidebar {
            width: 260px;
            background-color: var(--sidebar-bg);
            color: var(--sidebar-text);
            position: fixed;
            height: 100vh;
            z-index: 1000;
            transition: all 0.3s ease;
            display: flex;
            flex-direction: column;
        }
        
        .brand {
            height: 70px;
            display: flex;
            align-items: center;
            padding: 0 25px;
            font-size: 1.25rem;
            font-weight: 700;
            color: #fff;
            text-decoration: none;
            border-bottom: 1px solid rgba(255,255,255,0.05);
        }
        .brand i { color: var(--primary-color); margin-right: 10px; font-size: 1.4rem; }

        .nav-menu { padding: 20px 10px; flex-grow: 1; }
        .nav-link {
            color: var(--sidebar-text);
            padding: 12px 20px;
            margin-bottom: 5px;
            border-radius: 8px;
            font-weight: 500;
            display: flex;
            align-items: center;
            transition: all 0.2s;
        }
        .nav-link:hover {
            color: #fff;
            background-color: rgba(255,255,255,0.04);
        }
        .nav-link.active {
            color: var(--sidebar-active-text);
            background-color: var(--sidebar-active-bg);
        }
        .nav-link i { margin-right: 12px; font-size: 1.1rem; }

        .sidebar-footer {
            padding: 20px;
            border-top: 1px solid rgba(255,255,255,0.05);
        }

        /* 内容区域 */
        .content {
            flex: 1;
            margin-left: 260px;
            padding: 30px;
            transition: all 0.3s;
        }

        /* 卡片优化 */
        .card {
            border: none;
            border-radius: var(--card-border-radius);
            box-shadow: 0 0 20px 0 rgba(76, 87, 125, 0.02);
            background: #fff;
            margin-bottom: 24px;
        }
        .card-header {
            background: transparent;
            border-bottom: 1px solid #f0f0f0;
            padding: 20px 25px;
            font-weight: 600;
            font-size: 1.05rem;
            color: #181c32;
        }
        .card-body { padding: 25px; }

        /* 按钮优化 */
        .btn {
            border-radius: 6px;
            padding: 0.55rem 1.25rem;
            font-weight: 500;
            border: none;
        }
        .btn-primary { background-color: var(--primary-color); }
        .btn-primary:hover { background-color: var(--primary-hover); }
        .btn-light-primary {
            background-color: #e0e7ff;
            color: var(--primary-color);
        }
        .btn-light-primary:hover {
            background-color: #c7d2fe;
            color: var(--primary-hover);
        }
        .btn-outline-secondary { border: 1px solid #e4e6ef; color: #7e8299; }
        .btn-outline-secondary:hover { background-color: #f5f8fa; color: #3f4254; border-color: #e4e6ef; }

        /* 表格优化 */
        .table thead th {
            text-transform: uppercase;
            font-size: 0.75rem;
            letter-spacing: 0.05em;
            color: #b5b5c3;
            font-weight: 600;
            border-bottom-width: 1px;
            padding: 15px 25px;
        }
        .table tbody td {
            padding: 18px 25px;
            vertical-align: middle;
            color: #3f4254;
            font-weight: 500;
            border-bottom-color: #f0f0f0;
        }
        .table-hover tbody tr:hover { background-color: #f9f9f9; }

        /* 状态徽章 */
        .badge { padding: 0.5em 0.8em; font-weight: 600; }
        .bg-light-success { background-color: #e8fff3; color: #50cd89; }
        .bg-light-danger { background-color: #fff5f8; color: #f1416c; }
        .bg-light-warning { background-color: #fff8dd; color: #ffc700; }
        .bg-light-info { background-color: #f8f5ff; color: #7239ea; }

        /* 输入框 */
        .form-control, .form-select {
            border-color: #e4e6ef;
            color: #5e6278;
            padding: 0.75rem 1rem;
            border-radius: 8px;
            box-shadow: none !important;
        }
        .form-control:focus, .form-select:focus {
            border-color: var(--primary-color);
            background-color: #fcfcfc;
        }
        .form-label { color: #3f4254; font-weight: 500; margin-bottom: 0.5rem; }

        /* 移动端适配：已移除 mobile-toggle 相关控制逻辑，改为默认常驻或通过侧边栏宽度控制 */
        @media (max-width: 991px) {
            .sidebar { transform: translateX(-100%); width: 260px; }
            .content { margin-left: 0; }
            .sidebar.show { transform: translateX(0); box-shadow: 0 0 40px rgba(0,0,0,0.1); }
        }
    </style>
</head>
<body>
    <div class="toast-container position-fixed top-0 end-0 p-3" style="z-index: 1070">
    {{ range $key, $val := .Flashes }}
        {{ range $msg := $val }}
        <div class="toast show align-items-center border-0 shadow-sm mb-3" role="alert" aria-live="assertive" aria-atomic="true">
            <div class="d-flex">
                <div class="toast-body d-flex align-items-center">
                    <i class="bi {{ if eq $key "error" }}bi-x-circle-fill text-danger{{ else }}bi-check-circle-fill text-success{{ end }} fs-5 me-3"></i>
                    <div>{{ $msg }}</div>
                </div>
                <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast"></button>
            </div>
        </div>
        {{ end }}
    {{ end }}
    </div>

    <div class="wrapper">
        <div class="sidebar">
            <a href="/" class="brand">
                <i class="bi bi-hdd-network"></i> DDNS Master
            </a>
            <div class="nav-menu">
                <a href="/" class="nav-link {{ if eq .Page "dashboard" }}active{{ end }}">
                    <i class="bi bi-grid"></i> 仪表盘
                </a>
                <a href="/settings" class="nav-link {{ if eq .Page "settings" }}active{{ end }}">
                    <i class="bi bi-sliders"></i> 系统配置
                </a>
                <a href="/logs" class="nav-link {{ if eq .Page "logs" }}active{{ end }}">
                    <i class="bi bi-journal-text"></i> 运行日志
                </a>
            </div>
            <div class="sidebar-footer">
                <a href="/logout" class="nav-link text-danger p-0" style="justify-content: flex-start;">
                    <i class="bi bi-box-arrow-left"></i> 退出登录
                </a>
            </div>
        </div>
        <div class="content">
`

const commonFooterHTML = `
        </div>
    </div>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        // 自动隐藏 Toast
        setTimeout(() => { document.querySelectorAll('.toast').forEach(el => el.classList.remove('show')); }, 4000);
    </script>
</body>
</html>
`

const dashboardHTML = `
{{ template "common_header" . }}
<div class="d-flex justify-content-between align-items-center mb-4">
    <div>
        <h3 class="fw-bold m-0 text-dark">概览</h3>
        <p class="text-muted small m-0">系统运行状态监控</p>
    </div>
    <div>
        <a href="/domain/sync" class="btn btn-light-primary me-2"><i class="bi bi-arrow-clockwise me-1"></i> 立即同步</a>
        <button class="btn btn-primary" data-bs-toggle="modal" data-bs-target="#addModal"><i class="bi bi-plus-lg me-1"></i> 添加域名</button>
    </div>
</div>

<div class="row g-4 mb-4">
    <div class="col-md-4">
        <div class="card h-100">
            <div class="card-body d-flex align-items-center">
                <div class="rounded-3 p-3 d-flex align-items-center justify-content-center" style="background: rgba(99, 102, 241, 0.1); color: #6366f1; width: 60px; height: 60px;">
                    <i class="bi bi-globe fs-2"></i>
                </div>
                <div class="ms-4">
                    <div class="text-muted small fw-bold text-uppercase ls-1">托管域名</div>
                    <div class="fs-2 fw-bold text-dark">{{ .Stats.TotalDomains }}</div>
                </div>
            </div>
        </div>
    </div>
    <div class="col-md-4">
        <div class="card h-100">
            <div class="card-body d-flex align-items-center">
                <div class="rounded-3 p-3 d-flex align-items-center justify-content-center" style="background: rgba(80, 205, 137, 0.1); color: #50cd89; width: 60px; height: 60px;">
                    <i class="bi bi-check-circle fs-2"></i>
                </div>
                <div class="ms-4">
                    <div class="text-muted small fw-bold text-uppercase ls-1">状态正常</div>
                    <div class="fs-2 fw-bold text-dark">{{ .Stats.SuccessCount }}</div>
                </div>
            </div>
        </div>
    </div>
    <div class="col-md-4">
        <div class="card h-100">
            <div class="card-body d-flex align-items-center">
                <div class="rounded-3 p-3 d-flex align-items-center justify-content-center" style="background: rgba(241, 65, 108, 0.1); color: #f1416c; width: 60px; height: 60px;">
                    <i class="bi bi-activity fs-2"></i>
                </div>
                <div class="ms-4">
                    <div class="text-muted small fw-bold text-uppercase ls-1">上次同步</div>
                    <div class="fs-5 fw-bold text-dark">{{ .Stats.LastRunTime }}</div>
                </div>
            </div>
        </div>
    </div>
</div>

<div class="card mb-4">
    <div class="card-header d-flex align-items-center justify-content-between">
        <span>域名列表</span>
        <span class="badge bg-light text-muted border">自动同步中</span>
    </div>
    <div class="table-responsive">
        <table class="table table-hover align-middle mb-0">
            <thead>
                <tr>
                    <th class="ps-4">域名信息</th>
                    <th>类型</th>
                    <th>来源</th>
                    <th>代理</th>
                    <th>当前 IP</th>
                    <th>状态</th>
                    <th class="text-end pe-4">操作</th>
                </tr>
            </thead>
            <tbody>
                {{ range .Domains }}
                <tr>
                    <td class="ps-4">
                        <div class="fw-bold text-dark fs-6">{{ .RecordName }}</div>
                        <div class="text-muted small text-truncate" style="max-width: 150px;">ID: {{ .ZoneID }}</div>
                    </td>
                    <td>
                        {{ if eq .RecordType "AAAA" }}
                        <span class="badge bg-light text-dark border">IPv6</span>
                        {{ else }}
                        <span class="badge bg-light-info">IPv4</span>
                        {{ end }}
                    </td>
                    <td>
                        {{ if eq .IPSource "interface" }}
                        <span class="badge bg-light text-secondary border"><i class="bi bi-ethernet me-1"></i>{{ .InterfaceName }}</span>
                        {{ else }}
                        <span class="badge bg-light text-secondary border"><i class="bi bi-cloud me-1"></i>Web API</span>
                        {{ end }}
                    </td>
                    <td>
                        {{ if .Proxied }}
                        <i class="bi bi-cloud-check-fill text-warning fs-4" data-bs-toggle="tooltip" title="CDN开启"></i>
                        {{ else }}
                        <i class="bi bi-cloud-slash text-muted fs-4" data-bs-toggle="tooltip" title="直连"></i>
                        {{ end }}
                    </td>
                    <td>
                        <span class="font-monospace text-secondary fw-bold small">{{ if .LastIP }}{{ .LastIP }}{{ else }}<span class="text-muted fst-italic">等待获取...</span>{{ end }}</span>
                    </td>
                    <td>
                        {{ if eq .Status "Synced" }}
                            <span class="badge bg-light-success">已同步</span>
                        {{ else if eq .Status "Error" }}
                            <span class="badge bg-light-danger">错误</span>
                            <i class="bi bi-info-circle ms-1 text-danger" title="{{ .LastMsg }}"></i>
                        {{ else }}
                            <span class="badge bg-light-warning text-warning">等待中</span>
                        {{ end }}
                    </td>
                    <td class="text-end pe-4">
                        <button class="btn btn-icon btn-sm btn-light-primary me-2 btn-edit" 
                                data-id="{{ .ID }}" 
                                data-name="{{ .RecordName }}" 
                                data-type="{{ .RecordType }}" 
                                data-proxied="{{ .Proxied }}"
                                data-ipsource="{{ .IPSource }}"
                                data-interface="{{ .InterfaceName }}"
                                data-bs-toggle="modal" data-bs-target="#editModal">
                            <i class="bi bi-pencil-fill"></i>
                        </button>
                        <a href="/domain/delete/{{ .ID }}" class="btn btn-icon btn-sm btn-light-danger" onclick="return confirm('确定要删除 {{ .RecordName }} 吗?')">
                            <i class="bi bi-trash-fill"></i>
                        </a>
                    </td>
                </tr>
                {{ else }}
                <tr>
                    <td colspan="7" class="text-center py-5">
                        <div class="text-muted mb-2"><i class="bi bi-inbox fs-1 opacity-50"></i></div>
                        <div class="text-muted">暂无域名，请点击右上角添加</div>
                    </td>
                </tr>
                {{ end }}
            </tbody>
        </table>
    </div>
</div>

<div class="card">
    <div class="card-header">
        <i class="bi bi-clock-history me-2 text-primary"></i> 最近变动
    </div>
    <div class="list-group list-group-flush">
        {{ range .History }}
        <div class="list-group-item p-3 border-0 border-bottom">
            <div class="d-flex justify-content-between align-items-center">
                <div class="d-flex align-items-center">
                    <div class="me-3 d-flex flex-column align-items-center text-muted small" style="min-width: 50px;">
                         <span>{{ .CreatedAt.Format "15:04" }}</span>
                         <span style="font-size: 0.7rem;">{{ .CreatedAt.Format "01-02" }}</span>
                    </div>
                    <div>
                        <div class="fw-bold text-dark">{{ .RecordName }} <span class="badge bg-light text-muted border ms-1" style="font-size: 0.7em;">{{ .RecordType }}</span></div>
                        <div class="font-monospace small mt-1">
                            <span class="text-muted text-decoration-line-through me-2">{{ .OldIP }}</span>
                            <i class="bi bi-arrow-right text-primary me-2"></i>
                            <span class="text-success fw-bold">{{ .NewIP }}</span>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        {{ else }}
        <div class="p-4 text-center text-muted small">暂无 IP 变动历史</div>
        {{ end }}
    </div>
</div>

<div class="modal fade" id="addModal" tabindex="-1">
    <div class="modal-dialog modal-dialog-centered">
        <form action="/domain/add" method="POST" class="w-100">
            <div class="modal-content shadow-lg">
                <div class="modal-header">
                    <h5 class="modal-title fw-bold">添加域名</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                </div>
                <div class="modal-body p-4">
                    <div class="mb-3">
                        <label class="form-label">记录类型</label>
                        <select name="record_type" class="form-select">
                            <option value="A">IPv4 (A 记录)</option>
                            <option value="AAAA">IPv6 (AAAA 记录)</option>
                        </select>
                    </div>
                    
                    <div class="mb-3">
                        <label class="form-label">完整域名</label>
                        <input type="text" name="record_name" class="form-control" required placeholder="例如: vpn.example.com">
                    </div>

                    <div class="mb-3">
                         <label class="form-label">IP 获取来源</label>
                         <select name="ip_source" class="form-select ip-source-select" data-target="add_iface_div">
                            <option value="api">外部 API (ipify.org 等)</option>
                            <option value="interface">网卡接口 (Interface)</option>
                         </select>
                         
                         <div id="add_iface_div" class="mt-3 d-none p-3 bg-light rounded border border-dashed">
                            <label class="form-label small text-muted mb-2">选择网卡接口</label>
                            <select name="interface_name" class="form-select iface-list-select">
                                <option value="" disabled selected>加载中...</option>
                            </select>
                         </div>
                    </div>
                    
                    <div class="form-check form-switch mt-4">
                        <input class="form-check-input" type="checkbox" name="proxied" id="pchk">
                        <label class="form-check-label fw-medium ms-2" for="pchk">Cloudflare CDN (小黄云)</label>
                    </div>
                </div>
                <div class="modal-footer p-3 bg-light">
                    <button type="button" class="btn btn-outline-secondary" data-bs-dismiss="modal">取消</button>
                    <button type="submit" class="btn btn-primary">确认添加</button>
                </div>
            </div>
        </form>
    </div>
</div>

<div class="modal fade" id="editModal" tabindex="-1">
    <div class="modal-dialog modal-dialog-centered">
        <form action="/domain/update" method="POST" class="w-100">
            <input type="hidden" name="id" id="edit_id">
            <div class="modal-content shadow-lg">
                <div class="modal-header">
                    <h5 class="modal-title fw-bold">编辑域名</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                </div>
                <div class="modal-body p-4">
                    <div class="mb-3">
                        <label class="form-label">记录类型</label>
                        <select name="record_type" id="edit_type" class="form-select">
                            <option value="A">IPv4 (A 记录)</option>
                            <option value="AAAA">IPv6 (AAAA 记录)</option>
                        </select>
                    </div>
                    <div class="mb-3">
                        <label class="form-label">完整域名</label>
                        <input type="text" name="record_name" id="edit_name" class="form-control" required>
                    </div>
                    <div class="mb-3">
                         <label class="form-label">IP 获取来源</label>
                         <select name="ip_source" id="edit_ip_source" class="form-select ip-source-select" data-target="edit_iface_div">
                            <option value="api">外部 API</option>
                            <option value="interface">网卡接口</option>
                         </select>
                         <div id="edit_iface_div" class="mt-3 d-none p-3 bg-light rounded border border-dashed">
                            <label class="form-label small text-muted mb-2">选择网卡接口</label>
                            <select name="interface_name" id="edit_interface" class="form-select iface-list-select">
                                <option value="" disabled selected>加载中...</option>
                            </select>
                         </div>
                    </div>
                    <div class="form-check form-switch mt-4">
                        <input class="form-check-input" type="checkbox" name="proxied" id="edit_proxied">
                        <label class="form-check-label fw-medium ms-2" for="edit_proxied">Cloudflare CDN (小黄云)</label>
                    </div>
                </div>
                <div class="modal-footer p-3 bg-light">
                    <button type="button" class="btn btn-outline-secondary" data-bs-dismiss="modal">取消</button>
                    <button type="submit" class="btn btn-primary">保存修改</button>
                </div>
            </div>
        </form>
    </div>
</div>

<script>
    document.addEventListener('DOMContentLoaded', function() {
        // 网卡加载逻辑
        function loadInterfaces() {
            fetch('/api/interfaces')
                .then(r => r.json())
                .then(data => {
                    document.querySelectorAll('.iface-list-select').forEach(select => {
                        const currentVal = select.getAttribute('data-value') || '';
                        select.innerHTML = '';
                        data.forEach(iface => {
                            const opt = document.createElement('option');
                            opt.value = iface;
                            opt.textContent = iface;
                            if(iface === currentVal) opt.selected = true;
                            select.appendChild(opt);
                        });
                    });
                });
        }
        loadInterfaces();

        // 联动显示
        document.querySelectorAll('.ip-source-select').forEach(el => {
            el.addEventListener('change', function() {
                const target = document.getElementById(this.getAttribute('data-target'));
                if(this.value === 'interface') target.classList.remove('d-none');
                else target.classList.add('d-none');
            });
        });

        // 编辑回显
        document.querySelectorAll('.btn-edit').forEach(btn => {
            btn.addEventListener('click', function() {
                document.getElementById('edit_id').value = this.dataset.id;
                document.getElementById('edit_name').value = this.dataset.name;
                document.getElementById('edit_type').value = this.dataset.type;
                document.getElementById('edit_proxied').checked = this.dataset.proxied === 'true';
                
                const src = this.dataset.ipsource || 'api';
                const sel = document.getElementById('edit_ip_source');
                sel.value = src;
                sel.dispatchEvent(new Event('change'));
                
                const ifaceSel = document.getElementById('edit_interface');
                ifaceSel.value = this.dataset.interface;
                ifaceSel.setAttribute('data-value', this.dataset.interface);
            });
        });
    });
</script>
{{ template "common_footer" . }}
`

const settingsHTML = `
{{ template "common_header" . }}
<div class="container-fluid p-0">
    <div class="mb-4">
        <h3 class="fw-bold m-0 text-dark">系统配置</h3>
        <p class="text-muted small">系统运行参数与安全策略管理</p>
    </div>

    <div class="row g-4">
        <div class="col-md-6 col-xl-7">
            <div class="card h-100">
                <div class="card-header d-flex align-items-center">
                    <div class="rounded-circle bg-light-info p-2 me-3">
                        <i class="bi bi-cloud-check text-info"></i>
                    </div>
                    <span>Cloudflare 核心对接</span>
                </div>
                <div class="card-body d-flex flex-column justify-content-center">
                    <form action="/settings/update" method="POST" id="cfForm">
                        <div class="mb-2">
                            <label class="form-label small text-muted fw-bold">API Token</label>
                            <div class="input-group">
                                <input type="password" name="token" class="form-control" value="{{ .Setting.CFToken }}" placeholder="在此粘贴您的 Cloudflare Token">
                                <button class="btn btn-primary px-4" type="submit">保存</button>
                            </div>
                        </div>
                        <div class="form-text small"><i class="bi bi-info-circle me-1"></i>令牌需具备 Zone.DNS:Edit 权限</div>
                    </form>
                </div>
            </div>
        </div>

        <div class="col-md-6 col-xl-5">
            <div class="card h-100">
                <div class="card-header d-flex align-items-center">
                    <div class="rounded-circle bg-light-danger p-2 me-3">
                        <i class="bi bi-shield-lock text-danger"></i>
                    </div>
                    <span>访问权限控制</span>
                </div>
                <div class="card-body">
                    <form action="/settings/password" method="POST">
                        <div class="row g-2">
                            <div class="col-6">
                                <input type="password" name="old_password" class="form-control form-control-sm" placeholder="当前密码" required>
                            </div>
                            <div class="col-6">
                                <input type="password" name="new_password" class="form-control form-control-sm" placeholder="新密码" required>
                            </div>
                            <div class="col-12">
                                <button class="btn btn-outline-danger btn-sm w-100">更新登录凭证</button>
                            </div>
                        </div>
                    </form>
                </div>
            </div>
        </div>

        <div class="col-md-6 col-xl-7">
            <div class="card">
                <div class="card-header d-flex align-items-center">
                    <div class="rounded-circle bg-light-primary p-2 me-3">
                        <i class="bi bi-send text-primary"></i>
                    </div>
                    <span>Telegram 推送中枢</span>
                </div>
                <div class="card-body">
                    <form action="/settings/update" method="POST">
                        <input type="hidden" name="token" value="{{ .Setting.CFToken }}">
                        <div class="row g-3">
                            <div class="col-sm-7">
                                <label class="form-label small text-muted">Bot Token</label>
                                <input type="text" name="tg_token" class="form-control form-control-sm" placeholder="机器人的 API 令牌" value="{{ .Setting.TelegramBotToken }}">
                            </div>
                            <div class="col-sm-5">
                                <label class="form-label small text-muted">Chat ID</label>
                                <input type="text" name="tg_chat_id" class="form-control form-control-sm" placeholder="您的用户 ID" value="{{ .Setting.TelegramChatID }}">
                            </div>
                        </div>
                        <div class="d-flex justify-content-end mt-3 gap-2">
                            <button type="submit" formaction="/settings/test-tg" class="btn btn-light-primary btn-sm">测试</button>
                            <button type="submit" class="btn btn-primary btn-sm px-4">更新通知配置</button>
                        </div>
                    </form>
                </div>
            </div>
        </div>

        <div class="col-md-6 col-xl-5">
            <div class="card">
                <div class="card-header d-flex align-items-center">
                    <div class="rounded-circle bg-light-success p-2 me-3">
                        <i class="bi bi-database text-success"></i>
                    </div>
                    <span>数据快照与恢复</span>
                </div>
                <div class="card-body">
                    <div class="d-flex gap-2">
                        <a href="/settings/backup" class="btn btn-light-primary btn-sm flex-grow-1 py-2">
                            <i class="bi bi-download me-1"></i>导出 JSON
                        </a>
                        <form action="/settings/restore" method="POST" enctype="multipart/form-data" id="restoreForm" class="flex-grow-1">
                            <input type="file" name="backup_file" id="bfile" class="d-none" onchange="document.getElementById('restoreForm').submit()" accept=".json">
                            <label for="bfile" class="btn btn-light-success btn-sm w-100 py-2 cursor-pointer mb-0">
                                <i class="bi bi-upload me-1"></i>导入快照
                            </label>
                        </form>
                    </div>
                    <div class="mt-2 text-center">
                        <span class="text-muted small" style="font-size: 0.7rem;">建议在重大配置变更前进行快照备份</span>
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>
{{ template "common_footer" . }}
`

const logsHTML = `
{{ template "common_header" . }}
<div class="d-flex justify-content-between align-items-center mb-4">
    <div>
        <h3 class="fw-bold m-0 text-dark">运行日志</h3>
        <p class="text-muted small m-0">最近 200 条系统操作记录</p>
    </div>
    <div>
        <a href="/logs/clear" class="btn btn-outline-danger btn-sm me-2" onclick="return confirm('确定清空？')">
            <i class="bi bi-trash"></i> 清空
        </a>
        <a href="/logs" class="btn btn-white btn-sm border shadow-sm">
            <i class="bi bi-arrow-clockwise"></i> 刷新
        </a>
    </div>
</div>

<div class="card">
    <div class="table-responsive">
        <table class="table table-striped table-hover align-middle mb-0">
            <thead>
                <tr>
                    <th class="ps-4" style="width: 180px;">时间</th>
                    <th style="width: 100px;">级别</th>
                    <th>信息内容</th>
                </tr>
            </thead>
            <tbody>
                {{ range .Logs }}
                <tr>
                    <td class="ps-4 text-muted small font-monospace">{{ .CreatedAt.Format "01-02 15:04:05" }}</td>
                    <td>
                        {{ if eq .Level "ERROR" }}
                        <span class="badge bg-light-danger">ERROR</span>
                        {{ else if eq .Level "SUCCESS" }}
                        <span class="badge bg-light-success">SUCCESS</span>
                        {{ else }}
                        <span class="badge bg-light-info">INFO</span>
                        {{ end }}
                    </td>
                    <td class="text-dark small text-break">{{ .Message }}</td>
                </tr>
                {{ else }}
                <tr><td colspan="3" class="text-center py-5 text-muted small">暂无日志</td></tr>
                {{ end }}
            </tbody>
        </table>
    </div>
</div>
{{ template "common_footer" . }}
`

const loginHTML = `<!DOCTYPE html>
<html lang="zh">
<head>
    <title>登录 - DDNS Master</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        body { 
            background: #f3f4f6; 
            background-image: radial-gradient(#e5e7eb 1px, transparent 1px);
            background-size: 20px 20px;
            font-family: 'Inter', sans-serif; 
            display: flex; align-items: center; justify-content: center; min-height: 100vh; 
        }
        .login-card { 
            width: 100%; max-width: 400px; border: none; 
            border-radius: 16px; 
            box-shadow: 0 10px 40px -10px rgba(0,0,0,0.1); 
            background: white; padding: 40px; 
        }
        .brand-icon { 
            width: 50px; height: 50px; 
            background: linear-gradient(135deg, #6366f1, #4f46e5); 
            color: white; border-radius: 12px; 
            display: flex; align-items: center; justify-content: center; 
            margin: 0 auto 20px; font-size: 24px; font-weight: bold; 
        }
        .form-control { 
            padding: 12px; border-radius: 8px; border: 1px solid #e5e7eb; background: #f9fafb;
        }
        .form-control:focus { 
            background: #fff; border-color: #6366f1; box-shadow: 0 0 0 4px rgba(99, 102, 241, 0.1); 
        }
        .btn-primary { 
            width: 100%; padding: 12px; border-radius: 8px; 
            background: #4f46e5; border: none; font-weight: 600; 
            transition: all 0.2s;
        }
        .btn-primary:hover { background: #4338ca; transform: translateY(-1px); }
    </style>
</head>
<body>
    <div class="login-card">
        <div class="text-center mb-4">
            <div class="brand-icon">D</div>
            <h4 class="fw-bold text-dark mb-1">Welcome Back</h4>
            <p class="text-muted small">DDNS Master 管理面板</p>
        </div>
        {{ if .Error }}
        <div class="alert alert-danger py-2 small border-0 bg-danger bg-opacity-10 text-danger mb-4 text-center rounded-3">{{ .Error }}</div>
        {{ end }}
        <form action="/do-login" method="POST">
            <div class="mb-3">
                <label class="form-label small fw-bold text-secondary">用户名</label>
                <input type="text" name="username" class="form-control" required>
            </div>
            <div class="mb-4">
                <label class="form-label small fw-bold text-secondary">密码</label>
                <input type="password" name="password" class="form-control" required>
            </div>
            <button class="btn btn-primary">立即登录</button>
        </form>
    </div>
</body>
</html>`

const installHTML = `<!DOCTYPE html>
<html lang="zh">
<head>
    <title>初始化 - DDNS Master</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        body { 
            background: #ecfdf5; 
            background-image: radial-gradient(#d1fae5 1px, transparent 1px);
            background-size: 20px 20px;
            font-family: 'Inter', sans-serif; 
            display: flex; align-items: center; justify-content: center; min-height: 100vh; 
        }
        .login-card { 
            width: 100%; max-width: 400px; border: none; 
            border-radius: 16px; 
            box-shadow: 0 10px 40px -10px rgba(16, 185, 129, 0.1); 
            background: white; padding: 40px; 
        }
        .brand-icon { 
            width: 50px; height: 50px; 
            background: linear-gradient(135deg, #10b981, #059669); 
            color: white; border-radius: 12px; 
            display: flex; align-items: center; justify-content: center; 
            margin: 0 auto 20px; font-size: 24px; 
        }
        .form-control { 
            padding: 12px; border-radius: 8px; border: 1px solid #e5e7eb; background: #f9fafb;
        }
        .form-control:focus { 
            background: #fff; border-color: #10b981; box-shadow: 0 0 0 4px rgba(16, 185, 129, 0.1); 
        }
        .btn-success { 
            width: 100%; padding: 12px; border-radius: 8px; 
            background: #10b981; border: none; font-weight: 600; 
            transition: all 0.2s;
        }
        .btn-success:hover { background: #059669; transform: translateY(-1px); }
    </style>
</head>
<body>
    <div class="login-card">
        <div class="text-center mb-4">
            <div class="brand-icon">⚡</div>
            <h4 class="fw-bold text-dark mb-1">系统初始化</h4>
            <p class="text-muted small">设置管理员账号</p>
        </div>
        {{ if .Error }}
        <div class="alert alert-danger py-2 small border-0 bg-danger bg-opacity-10 text-danger mb-4 text-center rounded-3">{{ .Error }}</div>
        {{ end }}
        <form action="/do-install" method="POST">
            <div class="mb-3">
                <label class="form-label small fw-bold text-secondary">用户名</label>
                <input type="text" name="username" class="form-control" placeholder="Admin" required>
            </div>
            <div class="mb-4">
                <label class="form-label small fw-bold text-secondary">密码</label>
                <input type="password" name="password" class="form-control" placeholder="Password" required>
            </div>
            <button class="btn btn-success">完成安装</button>
        </form>
    </div>
</body>
</html>`