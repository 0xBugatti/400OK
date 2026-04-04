package cmd

import (
	"fmt"
	"io"
	"log"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	bypassIP             string
	cfgFile              string
	delay                int
	folder               string
	httpMethod           string
	maxGoroutines        int
	nobanner             bool
	proxy                string
	randomAgent          bool
	rateLimit            bool
	timeout              int
	redirect             bool
	reqHeaders           []string
	requestFile          string
	schema               bool
	technique            []string
	uri                  string
	userAgent            string
	verbose              bool
	statusCodes          []string
	uniqueOutput         bool
	exclude              []string
	jsonOutput           string
	showSummary          bool
	smartFilterEnabled   bool
	smartFilterThreshold int
	jsonBody             string
	includeUnicodeBrute  bool
	includeUserAgentFuzz bool
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "400OK",
	Short: "Tool to bypass 40X response codes.",
	Long:  `Command line application that automates different ways to bypass 40X codes.`,

	Run: func(cmd *cobra.Command, args []string) {
		if len(folder) == 0 {
			folder = "payloads"
		}

		// Handle exclusion flags
		if cmd.Flags().Changed("technique") && cmd.Flags().Changed("exclude") {
			log.Fatal("Error: --technique and --exclude flags are mutually exclusive. Use one or the other.")
		}

		if cmd.Flags().Changed("exclude") && len(exclude) > 0 {
			// Start with all techniques
			allTechniques := []string{
				"verbs", "verbs-case", "headers", "endpaths", "midpaths",
				"double-encoding", "http-versions", "path-case", "extensions",
				"bugbounty-tips", "default-creds",
				// Monster exclusive techniques
				"ipv6", "host-header", "unicode", "waf-bypass", "wayback",
				"via-header", "forwarded", "cache-control", "accept-header",
				"protocol", "port",
				// New techniques
				"auth-headers", "url-fuzz-3pos", "api-version", "trailing-dot",
				"unicode-brute", "useragent-fuzz", "json-tamper",
			}
			// Filter out excluded techniques
			excludeMap := make(map[string]bool)
			for _, ex := range exclude {
				excludeMap[ex] = true
			}
			technique = []string{}
			for _, tech := range allTechniques {
				if !excludeMap[tech] {
					technique = append(technique, tech)
				}
			}
		}

		fi, _ := os.Stdin.Stat()
		if (fi.Mode() & os.ModeCharDevice) == 0 {
			inputBytes, _ := io.ReadAll(os.Stdin)
			content := string(inputBytes)
			lines := strings.Split(content, "\n")
			for _, line := range lines {
				line = strings.TrimSpace(line)
				if line == "" {
					continue
				}
				requester(line, proxy, userAgent, reqHeaders, bypassIP, folder, httpMethod, verbose, technique, nobanner, rateLimit, timeout, redirect, randomAgent, jsonBody)
			}
		} else {
			if len(requestFile) > 0 {
				loadFlagsFromRequestFile(requestFile, schema, verbose, technique, redirect)
			} else {
				if len(uri) == 0 {
					err := cmd.Help()
					if err != nil {
						log.Fatalf("Error printing help: %v", err)
					}
					log.Fatal()
				}
				requester(uri, proxy, userAgent, reqHeaders, bypassIP, folder, httpMethod, verbose, technique, nobanner, rateLimit, timeout, redirect, randomAgent, jsonBody)
			}
		}
	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	cobra.CheckErr(rootCmd.Execute())
}

func init() {
	cobra.OnInitialize(initConfig)

	rootCmd.PersistentFlags().StringVarP(&bypassIP, "bypass-ip", "i", "", "Use a specified IP address or hostname for bypassing access controls. Injects this IP in headers like 'X-Forwarded-For'.")
	rootCmd.PersistentFlags().IntVarP(&delay, "delay", "d", 0, "Specify a delay between requests in milliseconds. Helps manage request rate (default: 0ms).")
	rootCmd.PersistentFlags().StringVarP(&folder, "folder", "f", "", "Specify the folder location for payloads if not in the same directory as the executable.")
	rootCmd.PersistentFlags().StringSliceVarP(&reqHeaders, "header", "H", []string{""}, "Add one or more custom headers to requests. Repeatable flag for multiple headers.")
	rootCmd.PersistentFlags().BoolVarP(&schema, "http", "", false, "Use HTTP instead of HTTPS for requests defined in the request file.")
	rootCmd.PersistentFlags().StringVarP(&httpMethod, "http-method", "t", "", "Specify the HTTP method for the request (e.g., GET, POST). Default is 'GET'.")
	rootCmd.PersistentFlags().IntVarP(&maxGoroutines, "max-goroutines", "m", 50, "Limit the maximum number of concurrent goroutines to manage load (default: 50).")
	rootCmd.PersistentFlags().BoolVarP(&nobanner, "no-banner", "", false, "Disable the display of the startup banner (default: banner shown).")
	rootCmd.PersistentFlags().StringVarP(&proxy, "proxy", "x", "", "Specify a proxy server for requests (e.g., 'http://server:port').")
	rootCmd.PersistentFlags().BoolVarP(&randomAgent, "random-agent", "", false, "Enable the use of a randomly selected User-Agent.")
	rootCmd.PersistentFlags().BoolVarP(&rateLimit, "rate-limit", "l", false, "Halt requests upon encountering a 429 (rate limit) HTTP status code.")
	rootCmd.PersistentFlags().BoolVarP(&redirect, "redirect", "r", false, "Automatically follow redirects in responses.")
	rootCmd.PersistentFlags().StringVarP(&requestFile, "request-file", "", "", "Load request configuration and flags from a specified file.")
	rootCmd.PersistentFlags().StringSliceVarP(&statusCodes, "status", "", []string{}, "Filter output by comma-separated status codes (e.g., 200,301,403)")
	rootCmd.PersistentFlags().StringSliceVarP(&technique, "technique", "k", []string{
		"verbs", "verbs-case", "headers", "endpaths", "midpaths",
		"double-encoding", "http-versions", "path-case", "extensions",
		"bugbounty-tips", "default-creds",
		// Monster exclusive techniques
		"ipv6", "host-header", "unicode", "waf-bypass", "wayback",
		"via-header", "forwarded", "cache-control", "accept-header",
		"protocol", "port",
		// New techniques
		"auth-headers", "url-fuzz-3pos", "api-version", "trailing-dot",
		"unicode-brute", "useragent-fuzz",
	}, "Specify one or more attack techniques to use (e.g., headers,path-case,extensions).")
	rootCmd.PersistentFlags().IntVarP(&timeout, "timeout", "", 6000, "Specify a max timeout time in ms.")
	rootCmd.PersistentFlags().BoolVarP(&uniqueOutput, "unique", "", false, "Show unique output based on status code and response length.")
	rootCmd.PersistentFlags().StringVarP(&uri, "uri", "u", "", "Specify the target URL for the request.")
	rootCmd.PersistentFlags().StringVarP(&userAgent, "user-agent", "a", "", "Specify a custom User-Agent string for requests (default: '400OK').")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Enable verbose output for detailed request/response logging (not based on auto-calibrate).")
	rootCmd.PersistentFlags().StringSliceVarP(&exclude, "exclude", "e", []string{}, "Exclude specific techniques from running (e.g., extensions,default-creds). Cannot be used with -k/--technique.")
	rootCmd.PersistentFlags().StringVarP(&jsonOutput, "json", "j", "", "Save results to JSON file.")
	rootCmd.PersistentFlags().BoolVarP(&showSummary, "summary", "s", true, "Show scan summary at the end (default: true).")
	rootCmd.PersistentFlags().BoolVar(&smartFilterEnabled, "smart-filter", true, "Enable smart filter (mute repeated responses after threshold).")
	rootCmd.PersistentFlags().IntVar(&smartFilterThreshold, "smart-filter-threshold", 8, "Number of identical responses before smart filter mutes.")
	rootCmd.PersistentFlags().StringVar(&jsonBody, "json-body", "", "JSON body for mass assignment tampering technique.")
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	if cfgFile != "" {
		// Use config file from the flag.
		viper.SetConfigFile(cfgFile)
	} else {
		// Find home directory.
		home, err := os.UserHomeDir()
		cobra.CheckErr(err)

		// Search config in home directory with name ".400OK" (without extension).
		viper.AddConfigPath(home)
		viper.SetConfigType("yaml")
		viper.SetConfigName(".400OK")
	}

	viper.AutomaticEnv() // read in environment variables that match

	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err == nil {
		_, err := fmt.Fprintln(os.Stderr, "Using config file:", viper.ConfigFileUsed())
		if err != nil {
			log.Fatalf("Error writing to stderr: %v", err)
		}
	}
}
