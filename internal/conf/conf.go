package conf

import (
	"os"

	"github.com/spf13/viper"
)

type Config struct {
	Realm        string `mapstructure:"realm"`
	Endpoint     string `mapstructure:"endpoint"`
	ClientID     string `mapstructure:"clientid"`
	ClientSecret string `mapstructure:"clientsecret"`
	ClientScope  string `mapstructure:"clientscope"`
	ClientRole   string `mapstructure:"clientrole"`
	ProxyURL     string `mapstructure:"proxyurl"`
	RequireOTP   bool   `mapstructure:"requireotp"`
}

var (
	defaults = map[string]interface{}{
		"realm":       "master",
		"endpoint":    "localhost",
		"clientscope": "openid",
		"requireotp":  false,
	}
	ConfigPath string
)

func LoadConfig() (config Config, err error) {
	for k, v := range defaults {
		viper.SetDefault(k, v)
	}
	if len(ConfigPath) == 0 {

		ConfigPath = os.Getenv("KC_SSH_CONFIG")
	}

	viper.SetConfigFile(ConfigPath)
	viper.SetConfigType("toml")
	viper.AddConfigPath("/opt/kc-ssh-pam")
	viper.AddConfigPath(".")
	viper.AddConfigPath("$HOME/.config")
	viper.SetEnvPrefix("kc_ssh")
	viper.AutomaticEnv()

	err = viper.ReadInConfig()
	if err != nil {
		return
	}
	err = viper.Unmarshal(&config)
	return
}
