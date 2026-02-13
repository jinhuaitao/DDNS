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
			if ip == "" {
				return "", fmt.Errorf("pre-fail")
			}
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
	r.MaxMultipartMemory = 8 << 20

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
	t.New("account").Parse(accountHTML) // 解析新的账号模板
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
		auth.POST("/settings/test-tg", handleTestTG)
		auth.GET("/settings/backup", handleBackup)
		auth.POST("/settings/restore", handleRestore)

		// 账号安全相关
		auth.GET("/account", handleAccount)
		auth.POST("/account/password", handleUpdatePassword)

		auth.GET("/logs", handleLogs)
		auth.GET("/logs/clear", handleClearLogs)
		auth.POST("/domain/add", handleAddDomain)
		auth.POST("/domain/update", handleUpdateDomain)
		auth.GET("/domain/delete/:id", handleDeleteDomain)
		auth.GET("/domain/sync", handleForceSync)
	}

	fmt.Println("---------------------------------------")
	fmt.Println("   Go DDNS Panel (UI Enhanced) 已启动")
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

	stats := DashboardStats{TotalDomains: int64(len(domains)), LastRunTime: "等待同步"}
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

// 新增处理函数：渲染账号管理页面
func handleAccount(c *gin.Context) {
	username := sessions.Default(c).Get("user").(string)
	sess := sessions.Default(c)
	flashes := sess.Flashes()
	sess.Save()
	c.HTML(200, "account", gin.H{"Page": "account", "Username": username, "Flashes": flashes})
}

func handleUpdatePassword(c *gin.Context) {
	username := sessions.Default(c).Get("user").(string)
	oldPass, newPass := c.PostForm("old_password"), c.PostForm("new_password")
	var user User
	if db.Where("username = ?", username).First(&user).Error != nil {
		setFlash(c, "error", "用户不存在")
		c.Redirect(302, "/account")
		return
	}
	if bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(oldPass)) != nil {
		setFlash(c, "error", "原密码错误")
		c.Redirect(302, "/account")
		return
	}
	if len(newPass) < 5 {
		setFlash(c, "error", "新密码太短")
		c.Redirect(302, "/account")
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
	if ipSource == "" {
		ipSource = "api"
	}

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

// ================= HTML 模板 =================

const commonHeaderHTML = `
<!DOCTYPE html>
<html lang="zh" class="h-100">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DDNS Pro</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.10.5/font/bootstrap-icons.css">
    <script defer src="https://cdn.jsdelivr.net/npm/alpinejs@3.12.0/dist/cdn.min.js"></script>
    <link href="https://cdn.jsdelivr.net/npm/@sweetalert2/theme-bootstrap-4/bootstrap-4.min.css" rel="stylesheet">
    <script src="https://cdn.jsdelivr.net/npm/sweetalert2@11"></script>

    <style>
        :root {
            --primary: #4f46e5;
            --primary-light: #e0e7ff;
            --primary-hover: #4338ca;
            --bg-body: #f8fafc;
            --sidebar-width: 280px;
            --sidebar-bg: #1e293b;
            --card-radius: 16px;
            --transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
        }

        body {
            background-color: var(--bg-body);
            font-family: 'Inter', system-ui, -apple-system, sans-serif;
            color: #334155;
            height: 100%;
            -webkit-font-smoothing: antialiased;
        }

        /* === 侧边栏 === */
        .sidebar {
            width: var(--sidebar-width);
            background: var(--sidebar-bg);
            color: #94a3b8;
            position: fixed;
            top: 0;
            left: 0;
            height: 100vh;
            z-index: 1040;
            transition: var(--transition);
            display: flex;
            flex-direction: column;
            border-right: 1px solid rgba(255,255,255,0.05);
        }
        
        .brand {
            height: 80px;
            display: flex;
            align-items: center;
            padding: 0 32px;
            font-size: 1.4rem;
            font-weight: 700;
            color: #fff;
            text-decoration: none;
            letter-spacing: -0.5px;
        }
        
        .nav-menu {
            padding: 0 16px;
            flex-grow: 1;
        }

        .nav-link {
            color: #94a3b8;
            padding: 14px 20px;
            margin-bottom: 8px;
            border-radius: 12px;
            display: flex;
            align-items: center;
            font-weight: 500;
            transition: var(--transition);
        }
        
        .nav-link:hover {
            color: #fff;
            background: rgba(255,255,255,0.08);
            transform: translateX(4px);
        }
        
        .nav-link.active {
            color: #fff;
            background: var(--primary);
            box-shadow: 0 4px 12px rgba(79, 70, 229, 0.3);
        }
        
        .nav-link i { margin-right: 14px; font-size: 1.2rem; }

        /* === 主内容区 === */
        .main-wrapper {
            margin-left: var(--sidebar-width);
            transition: margin-left 0.3s ease;
            min-height: 100vh;
            display: flex;
            flex-direction: column;
        }

        /* === 顶部导航 === */
        .top-navbar {
            background: rgba(255, 255, 255, 0.8);
            backdrop-filter: blur(12px);
            -webkit-backdrop-filter: blur(12px);
            height: 80px;
            padding: 0 40px;
            display: flex;
            align-items: center;
            justify-content: space-between;
            position: sticky;
            top: 0;
            z-index: 1030;
            border-bottom: 1px solid rgba(0,0,0,0.03);
        }

        /* === 组件通用 === */
        .card {
            border: none;
            border-radius: var(--card-radius);
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.02), 0 10px 15px -3px rgba(0, 0, 0, 0.03);
            background: #fff;
            transition: var(--transition);
            overflow: hidden;
        }
        
        .card:hover {
            transform: translateY(-2px);
            box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.05), 0 8px 10px -6px rgba(0, 0, 0, 0.01);
        }

        .btn { border-radius: 10px; padding: 0.6rem 1.2rem; font-weight: 600; letter-spacing: 0.3px; transition: var(--transition); }
        .btn-primary { background-color: var(--primary); border-color: var(--primary); box-shadow: 0 4px 6px -1px rgba(79, 70, 229, 0.2); }
        .btn-primary:hover { background-color: var(--primary-hover); transform: translateY(-1px); box-shadow: 0 6px 10px -1px rgba(79, 70, 229, 0.3); }
        .btn-light-primary { background: var(--primary-light); color: var(--primary); border: none; }
        .btn-light-primary:hover { background: #dbeafe; color: var(--primary-hover); }

        .table thead th { background: #f8fafc; text-transform: uppercase; font-size: 0.7rem; color: #64748b; font-weight: 700; border-bottom: 1px solid #e2e8f0; padding: 16px 24px; }
        .table tbody td { padding: 20px 24px; vertical-align: middle; border-bottom: 1px solid #f1f5f9; color: #475569; font-weight: 500; }
        .badge { font-weight: 600; padding: 0.5em 1em; border-radius: 6px; letter-spacing: 0.3px; }
        .form-control, .form-select { border-color: #e2e8f0; border-radius: 10px; padding: 0.75rem 1rem; background-color: #f8fafc; transition: var(--transition); }
        .form-control:focus, .form-select:focus { background-color: #fff; border-color: var(--primary); box-shadow: 0 0 0 4px rgba(79, 70, 229, 0.1); }

        @media (max-width: 991.98px) {
            .sidebar { transform: translateX(-100%); }
            .sidebar.show { transform: translateX(0); }
            .main-wrapper { margin-left: 0; }
            .top-navbar { padding: 0 20px; }
        }
    </style>
</head>
<body x-data="{ sidebarOpen: false }">

    <aside class="sidebar" :class="{ 'show': sidebarOpen }">
        <a href="/" class="brand">
            <i class="bi bi-cloud-lightning-fill text-primary me-2 fs-3"></i> 
            <span style="background: linear-gradient(90deg, #fff, #94a3b8); -webkit-background-clip: text; -webkit-text-fill-color: transparent;">DDNS Pro</span>
        </a>
        
        <div class="nav-menu mt-2">
            <small class="text-uppercase fw-bold px-3 mb-2 d-block" style="font-size: 0.7rem; letter-spacing: 1px; color: #475569;">Menu</small>
            <a href="/" class="nav-link {{ if eq .Page "dashboard" }}active{{ end }}">
                <i class="bi bi-grid-1x2-fill"></i> 概览仪表盘
            </a>
            <a href="/settings" class="nav-link {{ if eq .Page "settings" }}active{{ end }}">
                <i class="bi bi-gear-fill"></i> 系统配置
            </a>
            <a href="/logs" class="nav-link {{ if eq .Page "logs" }}active{{ end }}">
                <i class="bi bi-file-text-fill"></i> 运行日志
            </a>
        </div>
    </aside>

    <div x-show="sidebarOpen" @click="sidebarOpen = false" class="position-fixed top-0 start-0 w-100 h-100 bg-dark bg-opacity-50" style="z-index: 1035; display: none;" x-transition.opacity></div>

    <div class="main-wrapper">
        <header class="top-navbar">
            <div class="d-flex align-items-center">
                <button class="btn btn-icon btn-light d-lg-none me-3" @click="sidebarOpen = !sidebarOpen">
                    <i class="bi bi-list fs-4"></i>
                </button>
                <div>
                    <h5 class="mb-0 fw-bold text-dark d-none d-sm-block" style="letter-spacing: -0.5px;">
                        {{ if eq .Page "dashboard" }}仪表盘{{ else if eq .Page "settings" }}系统设置{{ else if eq .Page "account" }}账号管理{{ else }}运行日志{{ end }}
                    </h5>
                    <small class="text-muted d-none d-sm-block" style="font-size: 0.8rem;">Welcome back, Administrator</small>
                </div>
            </div>
            <div class="d-flex align-items-center gap-4">
                <a href="https://github.com/jinhuaitao/DDNS" target="_blank" class="text-secondary opacity-50 hover-primary transition" title="Github Repo">
                    <i class="bi bi-github fs-5"></i>
                </a>
                <div class="dropdown">
                    <a href="#" class="d-flex align-items-center text-decoration-none" data-bs-toggle="dropdown">
                        <div class="bg-primary text-white rounded-circle d-flex align-items-center justify-content-center fw-bold shadow-sm" 
                             style="width: 42px; height: 42px; border: 2px solid #e0e7ff;">A</div>
                    </a>
                    <ul class="dropdown-menu dropdown-menu-end border-0 shadow-lg p-2" style="border-radius: 12px; min-width: 200px;">
                        <li><h6 class="dropdown-header">账户操作</h6></li>
                        <li><a class="dropdown-item rounded" href="/account"><i class="bi bi-shield-lock me-2"></i>账号设置</a></li>
                        <li><hr class="dropdown-divider"></li>
                        <li><a class="dropdown-item rounded text-danger" href="/logout"><i class="bi bi-box-arrow-right me-2"></i>退出登录</a></li>
                    </ul>
                </div>
            </div>
        </header>

        <main class="p-4 p-md-5 flex-grow-1">
`

const commonFooterHTML = `
        </main>
        
        <footer class="text-center py-4 text-muted small">
            &copy; 2024 DDNS Pro Panel. Powered by Go & Gin.
        </footer>
    </div>

    <script>
        const Toast = Swal.mixin({
            toast: true,
            position: 'top-end',
            showConfirmButton: false,
            timer: 3000,
            timerProgressBar: true,
            didOpen: (toast) => {
                toast.addEventListener('mouseenter', Swal.stopTimer)
                toast.addEventListener('mouseleave', Swal.resumeTimer)
            }
        });

        // Go Flash 消息桥接
        {{ range $key, $val := .Flashes }}
            {{ range $msg := $val }}
                Toast.fire({
                    icon: '{{ if eq $key "error" }}error{{ else }}success{{ end }}',
                    title: '{{ $msg }}'
                });
            {{ end }}
        {{ end }}

        // 删除确认通用函数
        function confirmDel(url, name) {
            Swal.fire({
                title: '确定删除?',
                text: "即将删除域名 " + name + "，此操作不可恢复!",
                icon: 'warning',
                showCancelButton: true,
                confirmButtonColor: '#d33',
                cancelButtonColor: '#3085d6',
                confirmButtonText: '是的，删除它!',
                cancelButtonText: '取消'
            }).then((result) => {
                if (result.isConfirmed) {
                    window.location.href = url;
                }
            })
            return false;
        }
    </script>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
`

const dashboardHTML = `
{{ template "common_header" . }}

<div class="row g-4 mb-5">
    <div class="col-md-4">
        <div class="card stat-card h-100 p-3">
            <div class="card-body d-flex align-items-center">
                <div class="flex-grow-1">
                    <p class="text-muted small text-uppercase fw-bold mb-1 tracking-wider">托管域名</p>
                    <h2 class="mb-0 fw-bold text-dark display-6">{{ .Stats.TotalDomains }}</h2>
                </div>
                <div class="bg-primary bg-opacity-10 p-3 rounded-4 text-primary d-flex align-items-center justify-content-center" style="width: 64px; height: 64px;">
                    <i class="bi bi-globe2 fs-2"></i>
                </div>
            </div>
        </div>
    </div>
    <div class="col-md-4">
        <div class="card stat-card h-100 p-3">
            <div class="card-body d-flex align-items-center">
                <div class="flex-grow-1">
                    <p class="text-muted small text-uppercase fw-bold mb-1 tracking-wider">同步正常</p>
                    <h2 class="mb-0 fw-bold text-success display-6">{{ .Stats.SuccessCount }}</h2>
                </div>
                <div class="bg-success bg-opacity-10 p-3 rounded-4 text-success d-flex align-items-center justify-content-center" style="width: 64px; height: 64px;">
                    <i class="bi bi-check-circle-fill fs-2"></i>
                </div>
            </div>
        </div>
    </div>
    <div class="col-md-4">
        <div class="card stat-card h-100 p-3">
            <div class="card-body d-flex align-items-center">
                <div class="flex-grow-1">
                    <p class="text-muted small text-uppercase fw-bold mb-1 tracking-wider">上次运行</p>
                    <h4 class="mb-0 fw-bold text-dark fs-4">{{ .Stats.LastRunTime }}</h4>
                </div>
                <div class="bg-info bg-opacity-10 p-3 rounded-4 text-info d-flex align-items-center justify-content-center" style="width: 64px; height: 64px;">
                    <i class="bi bi-activity fs-2"></i>
                </div>
            </div>
        </div>
    </div>
</div>

<div class="card mb-5">
    <div class="card-header bg-white py-4 px-4 border-0 d-flex justify-content-between align-items-center">
        <div>
            <h5 class="mb-1 fw-bold">域名管理</h5>
            <small class="text-muted">管理您的 DNS 解析记录与 CDN 状态</small>
        </div>
        <div class="d-flex gap-2">
            <a href="/domain/sync" class="btn btn-light btn-sm d-flex align-items-center gap-2 px-3">
                <i class="bi bi-arrow-repeat"></i> 立即同步
            </a>
            <button class="btn btn-primary btn-sm shadow-sm d-flex align-items-center gap-2 px-3" data-bs-toggle="modal" data-bs-target="#addModal">
                <i class="bi bi-plus-lg"></i> 添加域名
            </button>
        </div>
    </div>
    <div class="table-responsive">
        <table class="table table-hover align-middle mb-0">
            <thead>
                <tr>
                    <th class="ps-4">记录名称 / ZoneID</th>
                    <th>类型</th>
                    <th>IP 来源</th>
                    <th>Cloudflare CDN</th>
                    <th>当前解析 IP</th>
                    <th>状态</th>
                    <th class="text-end pe-4">操作</th>
                </tr>
            </thead>
            <tbody>
                {{ range .Domains }}
                <tr>
                    <td class="ps-4">
                        <div class="fw-bold text-dark fs-6">{{ .RecordName }}</div>
                        <div class="text-muted small font-monospace opacity-75 mt-1">{{ if .ZoneID }}{{ .ZoneID }}{{ else }}待获取...{{ end }}</div>
                    </td>
                    <td><span class="badge bg-secondary bg-opacity-10 text-secondary border border-secondary border-opacity-10">{{ .RecordType }}</span></td>
                    <td>
                        {{ if eq .IPSource "interface" }}
                        <div class="d-flex align-items-center gap-2">
                            <i class="bi bi-ethernet text-primary"></i>
                            <span class="small fw-bold text-muted">{{ .InterfaceName }}</span>
                        </div>
                        {{ else }}
                        <div class="d-flex align-items-center gap-2">
                            <i class="bi bi-globe text-info"></i>
                            <span class="small fw-bold text-muted">Web API</span>
                        </div>
                        {{ end }}
                    </td>
                    <td>
                        {{ if .Proxied }}
                        <span class="badge bg-warning bg-opacity-10 text-warning border border-warning border-opacity-10 px-3 py-2 rounded-pill">
                            <i class="bi bi-cloud-check-fill me-1"></i> 已开启
                        </span>
                        {{ else }}
                        <span class="badge bg-light text-muted border px-3 py-2 rounded-pill">
                            <i class="bi bi-cloud-slash me-1"></i> 直连
                        </span>
                        {{ end }}
                    </td>
                    <td class="font-monospace fw-bold text-dark">{{ if .LastIP }}{{ .LastIP }}{{ else }}<span class="text-muted fw-normal fst-italic">Waiting...</span>{{ end }}</td>
                    <td>
                        {{ if eq .Status "Synced" }}
                            <span class="badge bg-success bg-opacity-10 text-success px-3 py-2 rounded-pill">
                                <span class="spinner-grow spinner-grow-sm me-1" style="width: 0.4rem; height: 0.4rem; --bs-spinner-animation-speed: 2s;"></span>正常
                            </span>
                        {{ else if eq .Status "Error" }}
                            <span class="badge bg-danger bg-opacity-10 text-danger px-3 py-2 rounded-pill" data-bs-toggle="tooltip" title="{{ .LastMsg }}">
                                <i class="bi bi-exclamation-circle me-1"></i> 错误
                            </span>
                        {{ else }}
                            <span class="badge bg-warning bg-opacity-10 text-warning px-3 py-2 rounded-pill">等待中</span>
                        {{ end }}
                    </td>
                    <td class="text-end pe-4">
                        <div class="btn-group">
                            <button class="btn btn-icon btn-sm btn-light text-primary btn-edit" 
                                    data-id="{{ .ID }}" 
                                    data-name="{{ .RecordName }}" 
                                    data-type="{{ .RecordType }}" 
                                    data-proxied="{{ .Proxied }}"
                                    data-ipsource="{{ .IPSource }}"
                                    data-interface="{{ .InterfaceName }}"
                                    style="border-top-right-radius: 0; border-bottom-right-radius: 0;">
                                <i class="bi bi-pencil-square"></i>
                            </button>
                            <button class="btn btn-icon btn-sm btn-light text-danger" 
                                    style="border-top-left-radius: 0; border-bottom-left-radius: 0; border-left: 1px solid #e2e8f0;"
                                    onclick="confirmDel('/domain/delete/{{ .ID }}', '{{ .RecordName }}')">
                                <i class="bi bi-trash"></i>
                            </button>
                        </div>
                    </td>
                </tr>
                {{ else }}
                <tr>
                    <td colspan="7" class="text-center py-5 text-muted">
                        <div class="mb-3"><i class="bi bi-inbox-fill fs-1 text-light"></i></div>
                        <p class="mb-0">暂无域名，请点击右上角添加</p>
                    </td>
                </tr>
                {{ end }}
            </tbody>
        </table>
    </div>
</div>

<div class="card">
    <div class="card-header bg-white py-4 px-4 border-0">
        <h6 class="mb-0 fw-bold d-flex align-items-center">
            <span class="bg-primary rounded-circle p-1 me-2" style="width: 8px; height: 8px; display: inline-block;"></span>
            最近 IP 变更记录
        </h6>
    </div>
    <div class="list-group list-group-flush">
        {{ range .History }}
        <div class="list-group-item px-4 py-3 border-light list-group-item-action">
            <div class="d-flex justify-content-between align-items-center">
                <div class="d-flex align-items-center">
                    <div class="bg-light p-2 rounded me-3 text-secondary">
                        <i class="bi bi-arrow-left-right"></i>
                    </div>
                    <div>
                        <div class="fw-bold text-dark">{{ .RecordName }} <span class="badge bg-secondary bg-opacity-10 text-secondary ms-1" style="font-size: 0.65rem;">{{ .RecordType }}</span></div>
                        <div class="small font-monospace mt-1">
                            <span class="text-muted">{{ .OldIP }}</span>
                            <i class="bi bi-arrow-right-short mx-2 text-primary"></i>
                            <span class="text-dark fw-bold">{{ .NewIP }}</span>
                        </div>
                    </div>
                </div>
                <div class="text-end">
                    <div class="fw-bold text-dark" style="font-size: 0.9rem;">{{ .CreatedAt.Format "15:04" }}</div>
                    <div class="text-muted small" style="font-size: 0.75rem;">{{ .CreatedAt.Format "01-02" }}</div>
                </div>
            </div>
        </div>
        {{ else }}
        <div class="p-5 text-center text-muted small">
            暂无历史记录
        </div>
        {{ end }}
    </div>
</div>

<div class="modal fade" id="addModal" tabindex="-1">
    <div class="modal-dialog modal-dialog-centered">
        <form action="/domain/add" method="POST" class="w-100">
            <div class="modal-content border-0 shadow-lg">
                <div class="modal-header border-0 pb-0 px-4 pt-4">
                    <h5 class="modal-title fw-bold">添加域名</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                </div>
                <div class="modal-body p-4">
                    <div class="mb-4">
                        <label class="form-label small text-muted text-uppercase fw-bold">DNS 记录类型</label>
                        <select name="record_type" class="form-select bg-light border-0 py-2">
                            <option value="A">IPv4 (A 记录)</option>
                            <option value="AAAA">IPv6 (AAAA 记录)</option>
                        </select>
                    </div>
                    
                    <div class="mb-4">
                        <label class="form-label small text-muted text-uppercase fw-bold">完整域名</label>
                        <input type="text" name="record_name" class="form-control bg-light border-0 py-2" required placeholder="例如: vpn.example.com">
                    </div>

                    <div class="mb-4" x-data="{ source: 'api' }">
                         <label class="form-label small text-muted text-uppercase fw-bold">IP 获取方式</label>
                         <div class="d-flex gap-2 mb-2">
                             <div class="form-check form-check-inline border rounded p-2 px-3 m-0 flex-fill text-center cursor-pointer" :class="source === 'api' ? 'border-primary bg-primary bg-opacity-10 text-primary' : 'bg-light border-0'">
                                <input class="form-check-input d-none" type="radio" name="ip_source" id="src_api" value="api" x-model="source">
                                <label class="form-check-label w-100" for="src_api" style="cursor: pointer;">Web API</label>
                             </div>
                             <div class="form-check form-check-inline border rounded p-2 px-3 m-0 flex-fill text-center cursor-pointer" :class="source === 'interface' ? 'border-primary bg-primary bg-opacity-10 text-primary' : 'bg-light border-0'">
                                <input class="form-check-input d-none" type="radio" name="ip_source" id="src_iface" value="interface" x-model="source">
                                <label class="form-check-label w-100" for="src_iface" style="cursor: pointer;">网卡接口</label>
                             </div>
                         </div>
                         
                         <div x-show="source === 'interface'" class="p-3 bg-light rounded mt-2" style="display: none;">
                            <label class="form-label small mb-1">选择网卡</label>
                            <select name="interface_name" class="form-select form-select-sm iface-list-select bg-white">
                                <option value="" disabled selected>加载中...</option>
                            </select>
                         </div>
                    </div>
                    
                    <div class="form-check form-switch p-3 bg-light rounded d-flex align-items-center justify-content-between px-3">
                        <div>
                            <label class="form-check-label fw-bold mb-0 text-dark" for="pchk">Cloudflare CDN</label>
                            <div class="small text-muted" style="font-size: 0.75rem;">开启后 IP 将被隐藏</div>
                        </div>
                        <input class="form-check-input ms-0" type="checkbox" name="proxied" id="pchk" style="width: 3em; height: 1.5em;">
                    </div>
                </div>
                <div class="modal-footer border-0 pt-0 px-4 pb-4">
                    <button type="button" class="btn btn-light text-muted" data-bs-dismiss="modal">取消</button>
                    <button type="submit" class="btn btn-primary px-4">确认添加</button>
                </div>
            </div>
        </form>
    </div>
</div>

<div class="modal fade" id="editModal" tabindex="-1">
    <div class="modal-dialog modal-dialog-centered">
        <form action="/domain/update" method="POST" class="w-100">
            <input type="hidden" name="id" id="edit_id">
            <div class="modal-content border-0 shadow-lg">
                <div class="modal-header border-0 pb-0 px-4 pt-4">
                    <h5 class="modal-title fw-bold">编辑配置</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                </div>
                <div class="modal-body p-4">
                    <div class="row g-3">
                        <div class="col-md-4">
                            <label class="form-label small text-muted fw-bold">类型</label>
                            <select name="record_type" id="edit_type" class="form-select bg-light border-0">
                                <option value="A">A (IPv4)</option>
                                <option value="AAAA">AAAA (IPv6)</option>
                            </select>
                        </div>
                        <div class="col-md-8">
                            <label class="form-label small text-muted fw-bold">域名</label>
                            <input type="text" name="record_name" id="edit_name" class="form-control bg-light border-0" required>
                        </div>
                    </div>

                    <div class="mt-4">
                         <label class="form-label small text-muted fw-bold">IP 来源</label>
                         <select name="ip_source" id="edit_ip_source" class="form-select bg-light border-0 ip-source-select" data-target="edit_iface_div">
                            <option value="api">Web API</option>
                            <option value="interface">本机网卡</option>
                         </select>
                         <div id="edit_iface_div" class="mt-2 p-3 bg-light rounded d-none">
                            <label class="form-label small mb-1">网卡接口</label>
                            <select name="interface_name" id="edit_interface" class="form-select form-select-sm iface-list-select bg-white"></select>
                         </div>
                    </div>
                    <div class="form-check form-switch mt-4 p-3 bg-light rounded d-flex align-items-center justify-content-between px-3">
                        <div>
                            <label class="form-check-label fw-bold mb-0 text-dark" for="edit_proxied">Cloudflare CDN</label>
                        </div>
                        <input class="form-check-input ms-0" type="checkbox" name="proxied" id="edit_proxied" style="width: 3em; height: 1.5em;">
                    </div>
                </div>
                <div class="modal-footer border-0 pt-0 px-4 pb-4">
                    <button type="button" class="btn btn-light text-muted" data-bs-dismiss="modal">取消</button>
                    <button type="submit" class="btn btn-primary px-4">保存修改</button>
                </div>
            </div>
        </form>
    </div>
</div>

<script>
    document.addEventListener('DOMContentLoaded', function() {
        const editModal = new bootstrap.Modal(document.getElementById('editModal'));

        // 网卡加载
        fetch('/api/interfaces').then(r => r.json()).then(data => {
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

        // 原生 JS 处理编辑框回显
        document.querySelectorAll('.btn-edit').forEach(btn => {
            btn.addEventListener('click', function() {
                document.getElementById('edit_id').value = this.dataset.id;
                document.getElementById('edit_name').value = this.dataset.name;
                document.getElementById('edit_type').value = this.dataset.type;
                document.getElementById('edit_proxied').checked = this.dataset.proxied === 'true';
                
                const src = this.dataset.ipsource || 'api';
                const sel = document.getElementById('edit_ip_source');
                sel.value = src;
                
                const ifaceDiv = document.getElementById('edit_iface_div');
                if(src === 'interface') ifaceDiv.classList.remove('d-none');
                else ifaceDiv.classList.add('d-none');
                
                const ifaceSel = document.getElementById('edit_interface');
                ifaceSel.value = this.dataset.interface;
                
                editModal.show();
            });
        });

        // 编辑框联动
        document.getElementById('edit_ip_source').addEventListener('change', function(){
             const ifaceDiv = document.getElementById('edit_iface_div');
             if(this.value === 'interface') ifaceDiv.classList.remove('d-none');
             else ifaceDiv.classList.add('d-none');
        });
    });
</script>
{{ template "common_footer" . }}
`

const settingsHTML = `
{{ template "common_header" . }}
<div class="row g-4">
    <div class="col-lg-6">
        <div class="card h-100">
            <div class="card-body p-4">
                <div class="d-flex align-items-center mb-4">
                    <div class="bg-warning bg-opacity-10 p-3 rounded-circle text-warning me-3">
                        <i class="bi bi-cloud-lightning fs-4"></i>
                    </div>
                    <div>
                        <h6 class="fw-bold mb-0">Cloudflare API</h6>
                        <small class="text-muted">核心连接配置</small>
                    </div>
                </div>
                <form action="/settings/update" method="POST">
                    <div class="mb-3">
                        <label class="form-label small text-muted fw-bold">API Token</label>
                        <input type="password" name="token" class="form-control" value="{{ .Setting.CFToken }}" placeholder="在此粘贴 API 令牌">
                        <div class="form-text">令牌需要 <span class="badge bg-light text-dark border">Zone.DNS:Edit</span> 权限</div>
                    </div>
                    <input type="hidden" name="tg_token" value="{{ .Setting.TelegramBotToken }}">
                    <input type="hidden" name="tg_chat_id" value="{{ .Setting.TelegramChatID }}">
                    <button class="btn btn-primary w-100 mt-2">保存 Cloudflare 配置</button>
                </form>
            </div>
        </div>
    </div>

    <div class="col-lg-6">
        <div class="card h-100">
            <div class="card-body p-4">
                <div class="d-flex align-items-center mb-4">
                    <div class="bg-info bg-opacity-10 p-3 rounded-circle text-info me-3">
                        <i class="bi bi-telegram fs-4"></i>
                    </div>
                    <div>
                        <h6 class="fw-bold mb-0">Telegram 通知</h6>
                        <small class="text-muted">IP 变动实时推送</small>
                    </div>
                </div>
                <form action="/settings/update" method="POST">
                    <input type="hidden" name="token" value="{{ .Setting.CFToken }}">
                    <div class="row g-3 mb-3">
                        <div class="col-md-7">
                            <label class="form-label small text-muted fw-bold">Bot Token</label>
                            <input type="text" name="tg_token" class="form-control" value="{{ .Setting.TelegramBotToken }}">
                        </div>
                        <div class="col-md-5">
                            <label class="form-label small text-muted fw-bold">Chat ID</label>
                            <input type="text" name="tg_chat_id" class="form-control" value="{{ .Setting.TelegramChatID }}">
                        </div>
                    </div>
                    <div class="d-flex gap-2 mt-2">
                        <button type="submit" formaction="/settings/test-tg" class="btn btn-light-primary flex-grow-1">发送测试消息</button>
                        <button type="submit" class="btn btn-primary flex-grow-1">保存配置</button>
                    </div>
                </form>
            </div>
        </div>
    </div>

    <div class="col-lg-6">
        <div class="card h-100">
            <div class="card-body p-4">
                <div class="d-flex align-items-center mb-4">
                    <div class="bg-success bg-opacity-10 p-3 rounded-circle text-success me-3">
                        <i class="bi bi-database fs-4"></i>
                    </div>
                    <div>
                        <h6 class="fw-bold mb-0">备份与恢复</h6>
                        <small class="text-muted">数据快照管理</small>
                    </div>
                </div>
                <div class="d-grid gap-3">
                    <a href="/settings/backup" class="btn btn-light border py-2">
                        <i class="bi bi-download me-2"></i>导出配置 (JSON)
                    </a>
                    <form action="/settings/restore" method="POST" enctype="multipart/form-data" id="restoreForm">
                        <input type="file" name="backup_file" id="bfile" class="d-none" onchange="document.getElementById('restoreForm').submit()" accept=".json">
                        <label for="bfile" class="btn btn-light-success border-success border-opacity-25 w-100 mb-0 py-2">
                            <i class="bi bi-upload me-2"></i>从文件恢复
                        </label>
                    </form>
                </div>
            </div>
        </div>
    </div>
</div>
{{ template "common_footer" . }}
`

const accountHTML = `
{{ template "common_header" . }}
<div class="row justify-content-center">
    <div class="col-lg-6 col-md-8">
        <div class="card h-100">
            <div class="card-body p-4 p-md-5">
                <div class="d-flex align-items-center mb-5">
                    <div class="bg-danger bg-opacity-10 p-3 rounded-circle text-danger me-4">
                        <i class="bi bi-shield-lock-fill fs-3"></i>
                    </div>
                    <div>
                        <h4 class="fw-bold mb-1">账号安全中心</h4>
                        <p class="text-muted mb-0 small">定期修改密码以保护您的系统安全</p>
                    </div>
                </div>

                <form action="/account/password" method="POST">
                    <div class="mb-4">
                        <label class="form-label small text-muted fw-bold text-uppercase">当前用户</label>
                        <input type="text" class="form-control" value="{{ .Username }}" disabled>
                    </div>
                    
                    <div class="mb-4">
                        <label class="form-label small text-muted fw-bold text-uppercase">当前密码</label>
                        <input type="password" name="old_password" class="form-control" placeholder="请输入当前使用的密码" required>
                    </div>
                    
                    <div class="mb-5">
                        <label class="form-label small text-muted fw-bold text-uppercase">设置新密码</label>
                        <input type="password" name="new_password" class="form-control" placeholder="新密码 (至少 5 位)" required>
                        <div class="form-text mt-2"><i class="bi bi-info-circle me-1"></i> 修改成功后需要重新登录</div>
                    </div>

                    <div class="d-grid">
                        <button class="btn btn-primary py-3">
                            <i class="bi bi-check-lg me-2"></i>确认修改密码
                        </button>
                    </div>
                </form>
            </div>
        </div>
    </div>
</div>
{{ template "common_footer" . }}
`

const logsHTML = `
{{ template "common_header" . }}
<div class="card h-100">
    <div class="card-header bg-white py-3 border-0 d-flex justify-content-between align-items-center">
        <h6 class="mb-0 fw-bold">系统日志 (最新 200 条)</h6>
        <div>
            <a href="/logs/clear" class="btn btn-outline-danger btn-sm me-2" onclick="return confirmDel('/logs/clear', '所有日志')">
                <i class="bi bi-trash"></i> 清空
            </a>
            <a href="/logs" class="btn btn-light btn-sm border">
                <i class="bi bi-arrow-clockwise"></i> 刷新
            </a>
        </div>
    </div>
    <div class="table-responsive">
        <table class="table table-striped align-middle mb-0" style="font-size: 0.9rem;">
            <thead>
                <tr>
                    <th class="ps-4" style="width: 160px;">Time</th>
                    <th style="width: 100px;">Level</th>
                    <th>Message</th>
                </tr>
            </thead>
            <tbody>
                {{ range .Logs }}
                <tr>
                    <td class="ps-4 text-muted font-monospace">{{ .CreatedAt.Format "01-02 15:04:05" }}</td>
                    <td>
                        {{ if eq .Level "ERROR" }}
                        <span class="badge bg-danger bg-opacity-10 text-danger">ERROR</span>
                        {{ else if eq .Level "SUCCESS" }}
                        <span class="badge bg-success bg-opacity-10 text-success">SUCCESS</span>
                        {{ else }}
                        <span class="badge bg-info bg-opacity-10 text-info">INFO</span>
                        {{ end }}
                    </td>
                    <td class="text-break">{{ .Message }}</td>
                </tr>
                {{ else }}
                <tr><td colspan="3" class="text-center py-5 text-muted">暂无日志数据</td></tr>
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
    <title>登录 - DDNS Pro</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.10.5/font/bootstrap-icons.css">
    <style>
        body { 
            background: #f8fafc;
            font-family: 'Inter', sans-serif;
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            color: #334155;
        }
        .login-card {
            width: 100%; max-width: 400px;
            background: #fff;
            border-radius: 24px;
            box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.05), 0 8px 10px -6px rgba(0, 0, 0, 0.01);
            padding: 48px;
            border: 1px solid rgba(255,255,255,0.5);
        }
        .form-control {
            padding: 14px;
            border-radius: 12px;
            border: 1px solid #e2e8f0;
            background-color: #f8fafc;
            font-size: 0.95rem;
            transition: all 0.3s;
        }
        .form-control:focus {
            background-color: #fff;
            border-color: #4f46e5;
            box-shadow: 0 0 0 4px rgba(79, 70, 229, 0.1);
        }
        .btn-primary {
            width: 100%; padding: 14px;
            background-color: #4f46e5;
            border: none;
            border-radius: 12px;
            font-weight: 600;
            font-size: 1rem;
            transition: all 0.2s;
            box-shadow: 0 4px 6px -1px rgba(79, 70, 229, 0.2);
        }
        .btn-primary:hover { background-color: #4338ca; transform: translateY(-2px); box-shadow: 0 10px 15px -3px rgba(79, 70, 229, 0.3); }
        .logo-box {
            width: 64px; height: 64px;
            background: linear-gradient(135deg, #4f46e5 0%, #6366f1 100%);
            border-radius: 16px;
            display: flex; align-items: center; justify-content: center;
            color: white;
            margin: 0 auto 24px auto;
            box-shadow: 0 10px 15px -3px rgba(79, 70, 229, 0.3);
        }
    </style>
</head>
<body>
    <div class="login-card">
        <div class="text-center mb-5">
            <div class="logo-box">
                <i class="bi bi-cloud-lightning-fill fs-2"></i>
            </div>
            <h4 class="fw-bold text-dark mb-2">Welcome Back</h4>
            <p class="text-muted small">请输入您的管理员凭证</p>
        </div>
        {{ if .Error }}
        <div class="alert alert-danger border-0 bg-danger bg-opacity-10 text-danger text-center small rounded-3 py-3 mb-4">
            <i class="bi bi-exclamation-circle me-1"></i> {{ .Error }}
        </div>
        {{ end }}
        <form action="/do-login" method="POST">
            <div class="mb-4">
                <input type="text" name="username" class="form-control" placeholder="用户名" required>
            </div>
            <div class="mb-4">
                <input type="password" name="password" class="form-control" placeholder="密码" required>
            </div>
            <button class="btn btn-primary">登 录</button>
        </form>
        <div class="text-center mt-4">
            <small class="text-muted opacity-50">Powered by GoRelay DDNS</small>
        </div>
    </div>
</body>
</html>`

const installHTML = `<!DOCTYPE html>
<html lang="zh">
<head>
    <title>初始化 - DDNS Pro</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700&display=swap" rel="stylesheet">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.10.5/font/bootstrap-icons.css">
    <style>
        body { 
            background: #ecfdf5;
            font-family: 'Plus Jakarta Sans', sans-serif;
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .bg-pattern {
            position: absolute; width: 100%; height: 100%; top: 0; left: 0;
            background-image: radial-gradient(#d1fae5 1px, transparent 1px);
            background-size: 24px 24px;
            z-index: -1;
        }
        .login-card {
            width: 100%; max-width: 400px;
            background: #fff;
            border-radius: 16px;
            box-shadow: 0 10px 25px -5px rgba(16, 185, 129, 0.1);
            padding: 40px;
        }
        .form-control {
            padding: 12px;
            border-radius: 8px;
            border: 1px solid #e5e7eb;
            background-color: #f9fafb;
        }
        .form-control:focus {
            background-color: #fff;
            border-color: #10b981;
            box-shadow: 0 0 0 3px rgba(16, 185, 129, 0.1);
        }
        .btn-success {
            width: 100%; padding: 12px;
            background-color: #10b981;
            border: none;
            border-radius: 8px;
            font-weight: 600;
            transition: all 0.2s;
        }
        .btn-success:hover { background-color: #059669; transform: translateY(-1px); }
    </style>
</head>
<body>
    <div class="bg-pattern"></div>
    <div class="login-card">
        <div class="text-center mb-4">
            <div class="d-inline-flex align-items-center justify-content-center bg-success text-white rounded-3 mb-3" style="width: 48px; height: 48px;">
                <i class="bi bi-hdd-rack-fill fs-4"></i>
            </div>
            <h4 class="fw-bold text-dark">系统初始化</h4>
            <p class="text-muted small">设置您的管理员账号</p>
        </div>
        {{ if .Error }}
        <div class="alert alert-danger border-0 bg-danger bg-opacity-10 text-danger text-center small rounded-3 py-2 mb-4">{{ .Error }}</div>
        {{ end }}
        <form action="/do-install" method="POST">
            <div class="mb-3">
                <label class="form-label small fw-bold text-muted">管理员用户名</label>
                <input type="text" name="username" class="form-control" placeholder="Admin" required>
            </div>
            <div class="mb-4">
                <label class="form-label small fw-bold text-muted">设置密码</label>
                <input type="password" name="password" class="form-control" placeholder="Password" required>
            </div>
            <button class="btn btn-success shadow-sm">完成安装</button>
        </form>
    </div>
</body>
</html>`
