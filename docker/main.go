package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"syscall"
)

const (
	pathOwnConfig         = "/config.json"
	pathShadowSocksConfig = "/etc/shadowsocks.json"
	pathKCPTunConfig      = "/etc/kcptun.json"

	defaultShadowSocksReustPort  = true
	defaultShadowSocksIPV6First  = false // 'true' breaks outline
	defaultShadowSocksFastOpen   = true
	defaultShadowSocksNoDelay    = true
	defaultShadowSocksTimeout    = 60
	defaultShadowSocksNameServer = "1.1.1.1"
	defaultShadowSocksMethod     = "chacha20-ietf-poly1305"

	defaultKCPTunProfile     = "fast"
	defaultKCPTunCrypt       = "none"
	defaultKCPTunDSCP        = 0
	defaultKCPTunCompression = false
	defaultKCPTunDataShard   = 10
	defaultKCPTunParityShard = 3
	defaultKCPTunMTU         = 1350

	defaultObfsMode = "tls"
	defaultObfsHost = "cx01.cloudfront.net"

	portShadowSocks = 443
	portKCPTun      = 444

	qrCodeURL = `https://api.qrserver.com/v1/create-qr-code/?format=svg&qzone=4&data=%s`
)

var (
	availableShadowSocksCiphers = map[string]struct{}{
		"aes-128-gcm":            struct{}{},
		"aes-192-gcm":            struct{}{},
		"aes-256-gcm":            struct{}{},
		"rc4-md5":                struct{}{},
		"aes-128-cfb":            struct{}{},
		"aes-192-cfb":            struct{}{},
		"aes-256-cfb":            struct{}{},
		"aes-128-ctr":            struct{}{},
		"aes-192-ctr":            struct{}{},
		"aes-256-ctr":            struct{}{},
		"bf-cfb":                 struct{}{},
		"camellia-128-cfb":       struct{}{},
		"camellia-192-cfb":       struct{}{},
		"camellia-256-cfb":       struct{}{},
		"chacha20-ietf-poly1305": struct{}{},
		"salsa20":                struct{}{},
		"chacha20":               struct{}{},
		"chacha20-ietf":          struct{}{},
	}

	availableKCPTunProfiles = map[string]struct{}{
		"normal": struct{}{},
		"fast":   struct{}{},
		"fast2":  struct{}{},
		"fast3":  struct{}{},
	}

	availableKCPTunCiphers = map[string]struct{}{
		"aes":      struct{}{},
		"aes-128":  struct{}{},
		"aes-192":  struct{}{},
		"salsa20":  struct{}{},
		"blowfish": struct{}{},
		"twofish":  struct{}{},
		"cast5":    struct{}{},
		"3des":     struct{}{},
		"tea":      struct{}{},
		"xtea":     struct{}{},
		"xor":      struct{}{},
		"sm4":      struct{}{},
		"none":     struct{}{},
	}

	availableObfsModes = map[string]struct{}{
		"http": struct{}{},
		"tls":  struct{}{},
	}
)

type shadowSocksOwnConfig struct {
	ReusePort  bool   `json:"reuse_port"`
	FastOpen   bool   `json:"fast_open"`
	IPV6First  bool   `json:"ipv6_first"`
	NoDelay    bool   `json:"no_delay"`
	Timeout    uint   `json:"timeout"`
	Password   string `json:"password"`
	NameServer string `json:"nameserver"`
	Method     string `json:"method"`
}

type shadowSocksConfigFile struct {
	Server     []string `json:"server"`
	ServerPort uint     `json:"server_port"`
	Password   string   `json:"password"`
	Method     string   `json:"method"`
	Timeout    uint     `json:"timeout"`
	User       string   `json:"user"`
	FastOpen   bool     `json:"fast_open"`
	ReusePort  bool     `json:"reuse_port"`
	NoDelay    bool     `json:"no_delay"`
	IPV6First  bool     `json:"ipv6_first"`
	NameServer string   `json:"nameserver"`
	Mode       string   `json:"mode"`
	Plugin     string   `json:"plugin,omitempty"`
	PluginOpts string   `json:"plugin_opts,omitempty"`
}

type kcpTunOwnConfig struct {
	Profile     string `json:"profile"`
	Crypt       string `json:"crypt"`
	Compression bool   `json:"compression"`
	Key         string `json:"key"`
	MTU         uint   `json:"mtu"`
	DSCP        uint   `json:"dscp"`
	DataShard   uint   `json:"datashard"`
	ParityShard uint   `json:"parityshard"`
}

type kcpTunConfigFile struct {
	Listen      string `json:"listen"`
	Target      string `json:"target"`
	Crypt       string `json:"crypt"`
	Mode        string `json:"mode"`
	Key         string `json:"key"`
	MTU         uint   `json:"mtu"`
	DSCP        uint   `json:"dscp"`
	NoComp      bool   `json:"nocomp"`
	DataShard   uint   `json:"datashard"`
	ParityShard uint   `json:"parityshard"`
}

type obfsOwnConfig struct {
	Mode string `json:"mode"`
	Host string `json:"host"`
}

type ownConfig struct {
	IP          string               `json:"ip"`
	Name        string               `json:"name"`
	ShadowSocks shadowSocksOwnConfig `json:"shadowsocks"`
	KCPTun      kcpTunOwnConfig      `json:"kcptun"`
	OBFS        obfsOwnConfig        `json:"obfs"`
}

func (c *ownConfig) shadowSocksConfig() *shadowSocksConfigFile {
	return &shadowSocksConfigFile{
		Server:     []string{"[::0]", "0.0.0.0"},
		ServerPort: portShadowSocks,
		Password:   c.ShadowSocks.Password,
		Method:     c.ShadowSocks.Method,
		Timeout:    c.ShadowSocks.Timeout,
		User:       "root",
		FastOpen:   c.ShadowSocks.FastOpen,
		ReusePort:  c.ShadowSocks.ReusePort,
		NoDelay:    c.ShadowSocks.NoDelay,
		IPV6First:  c.ShadowSocks.IPV6First,
		NameServer: c.ShadowSocks.NameServer,
		Mode:       "tcp_and_udp",
		Plugin:     "obfs-server",
		PluginOpts: fmt.Sprintf("obfs=%s;failover=%s", c.OBFS.Mode, c.OBFS.Host),
	}
}

func (c *ownConfig) kcpTunConfig() *kcpTunConfigFile {
	return &kcpTunConfigFile{
		Listen:      fmt.Sprintf(":%d", portKCPTun),
		Target:      net.JoinHostPort("127.0.0.1", strconv.Itoa(portShadowSocks)),
		Crypt:       c.KCPTun.Crypt,
		Mode:        c.KCPTun.Profile,
		Key:         c.KCPTun.Key,
		DSCP:        c.KCPTun.DSCP,
		NoComp:      !c.KCPTun.Compression,
		DataShard:   c.KCPTun.DataShard,
		ParityShard: c.KCPTun.ParityShard,
	}
}

func (c *ownConfig) shadowSocksURL() *url.URL {
	u := &url.URL{
		Scheme: "ss",
		Host:   net.JoinHostPort(c.IP, strconv.Itoa(portShadowSocks)),
		User:   url.User(c.getShadowSocksUser()),
		RawQuery: c.makePluginQuery("obfs-local", map[string]string{
			"obfs":      c.OBFS.Mode,
			"obfs-host": c.OBFS.Host,
		}),
	}
	if c.Name != "" {
		u.Fragment = c.Name
	}

	return u
}

func (c *ownConfig) kcpTunURL() *url.URL {
	base := c.shadowSocksURL()
	base.Host = net.JoinHostPort(c.IP, strconv.Itoa(portKCPTun))
	params := map[string]string{
		"crypt":       c.KCPTun.Crypt,
		"mode":        c.KCPTun.Profile,
		"datashard":   strconv.Itoa(int(c.KCPTun.DataShard)),
		"parityshard": strconv.Itoa(int(c.KCPTun.ParityShard)),
		"mtu":         strconv.Itoa(int(c.KCPTun.MTU)),
		"dscp":        strconv.Itoa(int(c.KCPTun.DSCP)),
		"key":         c.KCPTun.Key,
	}
	if !c.KCPTun.Compression {
		params["nocomp"] = "true"
	}
	base.RawQuery = c.makePluginQuery("kcptun", params)

	return base
}

func (c *ownConfig) getShadowSocksUser() string {
	decoded := fmt.Sprintf("%s:%s", c.ShadowSocks.Method, c.ShadowSocks.Password)
	return base64.URLEncoding.EncodeToString([]byte(decoded))
}

func (c *ownConfig) makePluginQuery(name string, options map[string]string) string {
	chunks := []string{name}
	for k, v := range options {
		chunks = append(chunks, fmt.Sprintf("%s=%s", k, v))
	}

	values := url.Values{}
	values.Set("plugin", strings.Join(chunks, ";"))

	return values.Encode()
}

func main() {
	ownConf, err := makeOwnConfig()
	if err != nil {
		log.Fatalf("Cannot read own configuration file: %s", err.Error())
	}

	mode := ""
	flag.StringVar(&mode, "mode", "run",
		"which mode to use. 'show' shows connection options, 'run' runs application")
	flag.Parse()

	if len(flag.Args()) != 0 {
		log.Fatal("This tool does not support CLI arguments")
	}

	switch mode {
	case "run":
		mainRun(ownConf)
	case "show":
		mainShow(ownConf)
	default:
		log.Fatal("Unknown mode")
	}
}

func mainRun(conf *ownConfig) {
	if err := writeConfig(pathShadowSocksConfig, conf.shadowSocksConfig()); err != nil {
		log.Fatal("Cannot write shadowsocks config: %s", err.Error())
	}
	if err := writeConfig(pathKCPTunConfig, conf.kcpTunConfig()); err != nil {
		log.Fatal("Cannot write kcptun config: %s", err.Error())
	}

	if err := syscall.Exec("/sbin/runsvdir", []string{"/sbin/runsvdir", "/etc/service"}, os.Environ()); err != nil {
		log.Fatal(err.Error())
	}
}

func mainShow(conf *ownConfig) {
	dataToShow := map[string]map[string]string{
		"shadowsocks": makeResult(conf.shadowSocksURL()),
		"kcptun":      makeResult(conf.kcpTunURL()),
	}

	if err := encodeJSON(os.Stdout, dataToShow); err != nil {
		log.Fatal(err.Error())
	}
}

func encodeJSON(w io.Writer, value interface{}) error {
	encoder := json.NewEncoder(w)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")

	return encoder.Encode(value)
}

func writeConfig(path string, config interface{}) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	if err = encodeJSON(file, config); err != nil {
		return err
	}

	return nil
}

func makeOwnConfig() (*ownConfig, error) {
	ownConf := &ownConfig{
		ShadowSocks: shadowSocksOwnConfig{
			ReusePort:  defaultShadowSocksReustPort,
			IPV6First:  defaultShadowSocksIPV6First,
			NoDelay:    defaultShadowSocksNoDelay,
			Timeout:    defaultShadowSocksTimeout,
			NameServer: defaultShadowSocksNameServer,
			Method:     defaultShadowSocksMethod,
			FastOpen:   defaultShadowSocksFastOpen,
		},
		KCPTun: kcpTunOwnConfig{
			Profile:     defaultKCPTunProfile,
			Crypt:       defaultKCPTunCrypt,
			Compression: defaultKCPTunCompression,
			DataShard:   defaultKCPTunDataShard,
			ParityShard: defaultKCPTunParityShard,
			DSCP:        defaultKCPTunDSCP,
			MTU:         defaultKCPTunMTU,
		},
		OBFS: obfsOwnConfig{
			Mode: defaultObfsMode,
			Host: defaultObfsHost,
		},
	}

	contents, err := ioutil.ReadFile(pathOwnConfig)
	if err != nil {
		return nil, err
	}
	if err = json.Unmarshal(contents, ownConf); err != nil {
		return nil, err
	}

	if net.ParseIP(ownConf.IP) == nil {
		return nil, errors.New("Incorrect IP is set")
	}

	if ownConf.ShadowSocks.Password == "" {
		return nil, errors.New("Password must not be empty")
	}
	if _, ok := availableShadowSocksCiphers[ownConf.ShadowSocks.Method]; !ok {
		return nil, errors.New("Unknown crypt method")
	}

	if ownConf.KCPTun.Key == "" {
		return nil, errors.New("KCPTun key has to be set")
	}
	if _, ok := availableKCPTunCiphers[ownConf.KCPTun.Crypt]; !ok {
		return nil, errors.New("Unsupported KCPTun crypt is set")
	}
	if _, ok := availableKCPTunProfiles[ownConf.KCPTun.Profile]; !ok {
		return nil, errors.New("Unsupported KCPTun profile is set")
	}

	if _, ok := availableObfsModes[ownConf.OBFS.Mode]; !ok {
		return nil, errors.New("Unsupported OBFS mode")
	}

	return ownConf, nil
}

func makeResult(u *url.URL) map[string]string {
	qrURL := fmt.Sprintf(qrCodeURL, url.QueryEscape(u.String()))

	return map[string]string{
		"url": u.String(),
		"qr":  qrURL,
	}
}
