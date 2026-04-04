package cmd

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/fatih/color"
)

// parseFile reads a file given its filename and returns a list containing each of its lines.
func parseFile(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer func(file *os.File) {
		err := file.Close()
		if err != nil {
			log.Printf("Error closing file: %v", err)
		}
	}(file)

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return lines, nil
}

// header represents an HTTP header.
type header struct {
	key   string
	value string
}

// request makes an HTTP request using headers `headers` and proxy `proxy`.
func request(method, uri string, headers []header, proxy *url.URL, rateLimit bool, timeout int, redirect bool) (int, []byte, error) {
	if method == "" {
		method = "GET"
	}

	if proxy == nil || len(proxy.Host) == 0 {
		proxy = nil
	}

	customTransport := &http.Transport{
		Proxy: http.ProxyURL(proxy),
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
		DialContext: (&net.Dialer{
			Timeout:   time.Duration(timeout) / 1000 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	client := &http.Client{
		Transport: customTransport,
	}

	if !redirect {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}

	parsedURL, err := url.Parse(uri)
	if err != nil {
		return 0, nil, fmt.Errorf("URL parse error: %w", err)
	}
	if parsedURL == nil {
		return 0, nil, fmt.Errorf("URL parse returned nil for: %s", uri)
	}

	parsedURL.RawPath = parsedURL.EscapedPath()

	req := &http.Request{
		Method: method,
		Host:   parsedURL.Host,
		URL:    parsedURL,
		Header: make(http.Header),
		Close:  true,
	}

	for _, header := range headers {
		req.Header.Add(header.key, header.value)
	}

	res, err := client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			log.Printf("Error closing response body: %v", err)
		}
	}(res.Body)

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return 0, nil, fmt.Errorf("error reading response body: %w", err)
	}

	if rateLimit && res.StatusCode == 429 {
		log.Fatalf("Rate limit detected (HTTP 429). Exiting...")
	}

	return res.StatusCode, body, nil
}

// requestWithBody makes an HTTP request with a request body (for POST/PUT/PATCH with JSON tampering).
func requestWithBody(method, uri string, headers []header, body []byte, proxy *url.URL, rateLimit bool, timeout int, redirect bool) (int, []byte, error) {
	if method == "" {
		method = "GET"
	}

	if proxy == nil || len(proxy.Host) == 0 {
		proxy = nil
	}

	customTransport := &http.Transport{
		Proxy: http.ProxyURL(proxy),
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
		DialContext: (&net.Dialer{
			Timeout:   time.Duration(timeout) / 1000 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	client := &http.Client{
		Transport: customTransport,
	}

	if !redirect {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}

	parsedURL, err := url.Parse(uri)
	if err != nil {
		return 0, nil, fmt.Errorf("URL parse error: %w", err)
	}
	if parsedURL == nil {
		return 0, nil, fmt.Errorf("URL parse returned nil for: %s", uri)
	}

	parsedURL.RawPath = parsedURL.EscapedPath()

	req := &http.Request{
		Method: method,
		Host:   parsedURL.Host,
		URL:    parsedURL,
		Header: make(http.Header),
		Close:  true,
		Body:   io.NopCloser(bytes.NewReader(body)),
	}

	for _, header := range headers {
		req.Header.Add(header.key, header.value)
	}

	res, err := client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			log.Printf("Error closing response body: %v", err)
		}
	}(res.Body)

	respBody, err := io.ReadAll(res.Body)
	if err != nil {
		return 0, nil, fmt.Errorf("error reading response body: %w", err)
	}

	if rateLimit && res.StatusCode == 429 {
		log.Fatalf("Rate limit detected (HTTP 429). Exiting...")
	}

	return res.StatusCode, respBody, nil
}

// loadFlagsFromRequestFile parse an HTTP request and configure the necessary flags for an execution
func loadFlagsFromRequestFile(requestFile string, schema bool, verbose bool, techniques []string, redirect bool) {
	// Read the content of the request file
	content, err := os.ReadFile(requestFile)
	if err != nil {
		log.Fatalf("Error reading request file: %v", err)
	}
	//Down HTTP/2 to HTTP/1.1
	temp := strings.Split(string(content), "\n")
	fistLine := strings.Replace(temp[0], "HTTP/2", "HTTP/1.1", 1)
	content = []byte(strings.Join(append([]string{fistLine}, temp[1:]...), "\n"))

	reqReader := strings.NewReader(string(content))
	req, err := http.ReadRequest(bufio.NewReader(reqReader))
	if err != nil {
		log.Fatalf("Error parsing request: %v", err)
	}
	if strings.HasPrefix(req.RequestURI, "http://") {
		req.RequestURI = "/" + strings.SplitAfterN(req.RequestURI, "/", 4)[3]
	}

	httpSchema := "https://"

	if schema {
		httpSchema = "http://"
	}

	uri := httpSchema + req.Host + strings.Split(req.RequestURI, "?")[0]

	// Extract headers from the request and assign them to the req_headers slice
	var reqHeaders []string
	// Append req.Header to reqHeaders
	for k, v := range req.Header {
		reqHeaders = append(reqHeaders, k+": "+strings.Join(v, ""))
	}
	httpMethod := req.Method
	// Assign the extracted values to the corresponding flag variables
	requester(uri, proxy, userAgent, reqHeaders, bypassIP, folder, httpMethod, verbose, techniques, nobanner, rateLimit, timeout, redirect, randomAgent, "")
}

func runAutocalibrate(options RequestOptions) (int, int) {
	calPaths := []string{
		"calibration_test_123456",
		"calib_nonexist_789xyz",
		"zz_calibrate_000",
	}

	var totalCl int
	var measurements []int

	baseURI := options.uri
	if !strings.HasSuffix(baseURI, "/") {
		baseURI += "/"
	}

	for _, calPath := range calPaths {
		calibrationURI := baseURI + calPath
		statusCode, response, err := request("GET", calibrationURI, options.headers, options.proxy, options.rateLimit, options.timeout, options.redirect)
		if err == nil && statusCode >= 400 {
			cl := len(response)
			measurements = append(measurements, cl)
			totalCl += cl
		}
	}

	avgCl := 0
	tolerance := 50
	if len(measurements) > 0 {
		avgCl = totalCl / len(measurements)
		maxDev := 0
		for _, m := range measurements {
			dev := m - avgCl
			if dev < 0 {
				dev = -dev
			}
			if dev > maxDev {
				maxDev = dev
			}
		}
		tolerance = max(50, maxDev*2)
	}

	fmt.Println(color.MagentaString("\n━━━━━━━━━━━━━━━ AUTO-CALIBRATION RESULTS ━━━━━━━━━━━━━━━"))
	fmt.Printf("[✔] Calibration: %d measurements, avg CL=%d, tolerance=±%d\n", len(measurements), avgCl, tolerance)

	return avgCl, tolerance
}
