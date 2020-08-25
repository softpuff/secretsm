package cmd

import (
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/softpuff/secretsm/sm"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var debug bool
var region string
var (
	c = sm.NewConfig(region)
)

var (
	SMCMD = &cobra.Command{
		Use:   "secretsm [subcommand]",
		Short: "work with aws secretsmanager",
	}
)

var (
	getCMD = &cobra.Command{
		Use:   "get",
		Short: "secretsm get <secretName>",
		Args:  cobra.MaximumNArgs(1),
		ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
			secretNames, err := c.ListSecretsForComplete()
			if err != nil {
				log.Fatalf("Error returning list of secrets: %v\n", err)
			}
			return secretNames, cobra.ShellCompDirectiveNoFileComp
		},

		Run: func(cmd *cobra.Command, args []string) {
			switch argsNum := len(args); {
			case argsNum == 0:
				sort := viper.GetBool("sort")
				maxResults := viper.GetInt64("max-results")
				listSecrets(maxResults, sort)
			case argsNum > 0:
				s := args[0]
				raw := viper.GetBool("raw")
				getSecretValue(s, raw)
			}
		},
	}
)

var (
	setCMD = &cobra.Command{
		Use:  "set",
		Args: cobra.MinimumNArgs(1),
		ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
			secret := viper.GetString("secret-name")
			return sm.ListSecretKeys(c, secret), cobra.ShellCompDirectiveNoFileComp
		},
		Run: func(cmd *cobra.Command, args []string) {
			secret := viper.GetString("secret-name")
			add, remove, err := parseKeys(args)
			if err != nil {
				log.Fatalf("Error parsing args: %v\n", err)
			}
			sv, err := sm.UpdateSecretValue(c, secret, add, remove)
			if err != nil {
				log.Fatalf("Error setting secret: %v\n", err)
			}
			// sm.PrintSecretValue(sv)

			sm.PutSecretValue(c, secret, sv)
		},
	}
)

var (
	completionCmd = &cobra.Command{
		Use:   "completion",
		Short: "Generates bash completion script",
		Run: func(cmd *cobra.Command, args []string) {
			SMCMD.GenBashCompletion(os.Stdout)
		},
	}
)

func init() {
	cobra.OnInitialize(initConfig)
	SMCMD.PersistentFlags().StringVarP(&region, "region", "a", "", "aws region")
	SMCMD.PersistentFlags().BoolVarP(&debug, "debug", "d", false, "debug output")
	viper.BindPFlag("region", SMCMD.PersistentFlags().Lookup("region"))
	SMCMD.AddCommand(completionCmd)
	SMCMD.AddCommand(getCMD)
	SMCMD.AddCommand(setCMD)
	getCMD.Flags().BoolP("raw", "r", false, "raw secret output")
	getCMD.Flags().BoolP("sort", "s", false, "sort list by name")
	getCMD.Flags().Int64P("max-results", "m", 100, "max results returned")
	setCMD.Flags().StringP("secret-name", "", "", "name of the secret to edit")
	viper.BindPFlag("secret-name", setCMD.Flags().Lookup("secret-name"))
	viper.BindPFlag("sort", getCMD.Flags().Lookup("sort"))
	viper.BindPFlag("max-results", getCMD.Flags().Lookup("max-results"))
	viper.BindPFlag("raw", getCMD.Flags().Lookup("raw"))

	viper.BindEnv("region", "AWS_REGION")

	setCMD.RegisterFlagCompletionFunc("secret-name", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		secretNames, err := c.ListSecretsForComplete()
		if err != nil {
			log.Fatalf("Error returning list of secrets: %v\n", err)
		}
		return secretNames, cobra.ShellCompDirectiveNoFileComp

	})
}

func initConfig() {
	region = viper.GetString("region")
	if region == "" {
		log.Fatal("No region")
	}
}

func listSecrets(maxResults int64, sort bool) {
	var nt *string
	secrets, nextToken, err := c.ListSecrets(nt, maxResults)
	if err != nil {
		log.Fatalf("Listing secrets error: %v\n", err)
	}
	// sm.PrintSecretList(secrets, debug, sort)
	for nextToken != nil {
		secrets2, nt, err := c.ListSecrets(nextToken, maxResults)
		if err != nil {
			log.Fatalf("Listing secrets error: %v\n", err)
		}
		if debug {
			fmt.Printf("Next token: %v\n", nt)
		}
		secrets = append(secrets, secrets2...)
		nextToken = nt
	}
	sm.PrintSecretList(secrets, debug, sort)

}

func getSecretValue(s string, raw bool) {
	sv, err := c.GetSecretValue(s, raw)
	if err != nil {
		log.Fatalf("Getting secret value: %v\n", err)
	}

	sm.PrintSecretValue(sv)

}

func parseKeys(keys []string) (map[string]string, []string, error) {
	add := map[string]string{}
	var remove []string
	for _, key := range keys {
		if strings.Contains(key, "=") {
			parts := strings.SplitN(key, "=", 2)
			if len(parts) != 2 {
				return nil, nil, fmt.Errorf("Key/Value pair %s invalid", key)
			}
			add[parts[0]] = parts[1]
		} else if strings.HasSuffix(key, "-") {
			remove = append(remove, key[:len(key)-1])
		} else {
			return nil, nil, fmt.Errorf("Key/Value pair %s invalid", key)
		}
	}
	for _, deleteKey := range remove {
		if _, found := add[deleteKey]; found {
			return nil, nil, fmt.Errorf("%s is set and removed in the same command", deleteKey)
		}
	}
	return add, remove, nil
}
