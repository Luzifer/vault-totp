package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"time"

	"github.com/Luzifer/rconfig"
	"github.com/hashicorp/vault/api"
	homedir "github.com/mitchellh/go-homedir"
	"github.com/pquerna/otp/totp"
)

var (
	cfg = struct {
		Field          string `flag:"field" default:"secret" description:"Field inside the key to search the TOTP secret in"`
		NoTime         bool   `flag:"no-time,n" default:"false" description:"Omit printing the validity time"`
		OneShot        bool   `flag:"one-shot,1" default:"false" description:"Prints token only once instead continuously"`
		TestSecret     string `flag:"test" default:"" description:"Use a test secret from CLI instead of using a secret from Vault"`
		VaultAddress   string `flag:"vault-addr" env:"VAULT_ADDR" default:"https://127.0.0.1:8200" description:"Vault API address"`
		VaultToken     string `flag:"vault-token" env:"VAULT_TOKEN" vardefault:"vault-token" description:"Vault Token to use for accessing Vault instance"`
		VersionAndExit bool   `flag:"version" default:"false" description:"Prints current version and exits"`
	}{}

	version = "dev"
)

func vaultTokenFromDisk() string {
	vf, err := homedir.Expand("~/.vault-token")
	if err != nil {
		return ""
	}

	data, err := ioutil.ReadFile(vf)
	if err != nil {
		return ""
	}

	return string(data)
}

func init() {
	rconfig.SetVariableDefaults(map[string]string{
		"vault-token": vaultTokenFromDisk(),
	})

	if err := rconfig.Parse(&cfg); err != nil {
		log.Fatalf("Unable to parse commandline options: %s", err)
	}

	if cfg.VersionAndExit {
		fmt.Printf("vault-totp %s\n", version)
		os.Exit(0)
	}

	if cfg.VaultToken == "" && cfg.TestSecret == "" {
		log.Fatalf("You need to specify a vault-token")
	}
}

func main() {
	if len(rconfig.Args()) < 2 && cfg.TestSecret == "" {
		log.Fatalf("Please specify a vault key to read the secret from.\n\nUsage: vault-totp [opts] <vault-key>")
	}

	var (
		secret string
		err    error
	)

	if cfg.TestSecret == "" {
		secret, err = getSecretFromVault()
		if err != nil {
			log.Fatalf("Error to retrieve secret: %s", err)
		}
	} else {
		secret = cfg.TestSecret
	}

	for range time.Tick(250 * time.Millisecond) {
		output, err := buildOutput(secret)
		if err != nil {
			log.Fatalf("An error ocurred while generating the code: %s", err)
		}

		fmt.Printf("\r%s", output)

		if cfg.OneShot {
			break
		}
	}

	fmt.Println("")
}

func getSecretFromVault() (string, error) {
	client, err := api.NewClient(&api.Config{
		Address: cfg.VaultAddress,
	})

	if err != nil {
		return "", fmt.Errorf("Unable to create client: %s", err)
	}

	client.SetToken(cfg.VaultToken)

	data, err := client.Logical().Read(rconfig.Args()[1])
	if err != nil {
		return "", fmt.Errorf("Unable to read from key %q: %s", rconfig.Args()[1], err)
	}

	if data.Data[cfg.Field] == nil {
		return "", fmt.Errorf("The key %q does not have a field named %q.", rconfig.Args()[1], cfg.Field)
	}

	return data.Data[cfg.Field].(string), nil
}

func buildOutput(secret string) (string, error) {
	// Output: "123456 (Valid 12s)", "123456 (Valid 1s)"

	n := time.Now()
	code, err := totp.GenerateCode(secret, n)
	if err != nil {
		return "", err
	}

	if cfg.NoTime {
		return fmt.Sprintf("%s", code), nil
	}

	remain := 30 - (n.Second() % 30)
	return fmt.Sprintf("%s (Valid %ds) ", code, remain), nil
}
