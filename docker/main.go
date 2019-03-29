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
	"syscall"
)

const (
	pathOwnConfig         = "/config.json"
	pathShadowSocksConfig = "/etc/shadowsocks.json"

	defaultShadowSocksReusePort  = true
	defaultShadowSocksIPV6First  = false // 'true' breaks outline
	defaultShadowSocksFastOpen   = true
	defaultShadowSocksNoDelay    = true
	defaultShadowSocksTimeout    = 60
	defaultShadowSocksNameServer = "1.1.1.1"
	defaultShadowSocksMethod     = "chacha20-ietf-poly1305"

	portShadowSocks = 443

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

type pluginConfig struct {
	Host string `json:"host"`
}

type ownConfig struct {
	IP          string               `json:"ip"`
	Name        string               `json:"name"`
	ShadowSocks shadowSocksOwnConfig `json:"shadowsocks"`
}

func (c *ownConfig) shadowSocksConfig() *shadowSocksConfigFile {
	return &shadowSocksConfigFile{
		Server:     []string{"0.0.0.0"},
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
		Plugin:     "v2ray-plugin",
		PluginOpts: "server",
	}
}

func (c *ownConfig) shadowSocksURL() *url.URL {
	u := &url.URL{
		Scheme: "ss",
		Host:   net.JoinHostPort(c.IP, strconv.Itoa(portShadowSocks)),
		User:   url.User(c.getShadowSocksUser()),
	}
	if c.Name != "" {
		u.Fragment = c.Name
	}

	return u
}

func (c *ownConfig) getShadowSocksUser() string {
	decoded := fmt.Sprintf("%s:%s", c.ShadowSocks.Method, c.ShadowSocks.Password)
	return base64.URLEncoding.EncodeToString([]byte(decoded))
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
		panic(err)
	}

	if err := syscall.Exec("/sbin/runsvdir", []string{"/sbin/runsvdir", "/etc/service"}, os.Environ()); err != nil {
		log.Fatal(err.Error())
	}
}

func mainShow(conf *ownConfig) {
	dataToShow := map[string]map[string]string{
		"shadowsocks": makeResult(conf.shadowSocksURL()),
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
			ReusePort:  defaultShadowSocksReusePort,
			IPV6First:  defaultShadowSocksIPV6First,
			NoDelay:    defaultShadowSocksNoDelay,
			Timeout:    defaultShadowSocksTimeout,
			NameServer: defaultShadowSocksNameServer,
			Method:     defaultShadowSocksMethod,
			FastOpen:   defaultShadowSocksFastOpen,
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

	return ownConf, nil
}

func makeResult(u *url.URL) map[string]string {
	qrURL := fmt.Sprintf(qrCodeURL, url.QueryEscape(u.String()))

	return map[string]string{
		"url": u.String(),
		"qr":  qrURL,
	}
}
