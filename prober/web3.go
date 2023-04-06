// Copyright 2016 The Prometheus Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package prober

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptrace"
	"net/textproto"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common/math"
	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/prometheus/client_golang/prometheus"
	pconfig "github.com/prometheus/common/config"
	"golang.org/x/net/publicsuffix"

	"github.com/prometheus/blackbox_exporter/config"
)

const (
	EthereumRequest = `{ "jsonrpc":"2.0", "method":"eth_getBlockByNumber", "params":["latest", false], "id":74 }`
	StarknetRequest = `{ "jsonrpc":"2.0", "method":"starknet_getBlockWithTxs", "params": {"block_id": "latest"}, "id":73 }`
)

type EthereumResponse struct {
	JsonRPC string `json:"jsonrpc,omitempty"`
	Result  struct {
		Number    math.HexOrDecimal64 `json:"number"`
		Timestamp math.HexOrDecimal64 `json:"timestamp"`
	} `json:"result"`
}

type StarknetResponse struct {
	JsonRPC string `json:"jsonrpc,omitempty"`
	Result  struct {
		Number    uint64 `json:"block_number"`
		Timestamp uint64 `json:"timestamp"`
	} `json:"result"`
}

type AptosResponse struct {
	Number    math.HexOrDecimal64 `json:"block_height"`
	Timestamp math.HexOrDecimal64 `json:"ledger_timestamp"`
}

func ProbeWeb3(ctx context.Context, target string, module config.Module, registry *prometheus.Registry, logger log.Logger) (success bool) {
	var redirects int
	var (
		durationGaugeVec = prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "probe_web3_duration_seconds",
			Help: "Duration of http request by phase, summed over all redirects",
		}, []string{"phase"})
		contentLengthGauge = prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "probe_web3_content_length",
			Help: "Length of http content response",
		})
		blockNumberGauge = prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "probe_web3_block_number",
			Help: "Block number of current height",
		})
		blockTimestampGauge = prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "probe_web3_block_timestamp",
			Help: "Block timestamp of current height",
		})
		bodyUncompressedLengthGauge = prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "probe_web3_uncompressed_body_length",
			Help: "Length of uncompressed response body",
		})
		redirectsGauge = prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "probe_web3_redirects",
			Help: "The number of redirects",
		})

		isSSLGauge = prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "probe_web3_ssl",
			Help: "Indicates if SSL was used for the final redirect",
		})

		statusCodeGauge = prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "probe_web3_status_code",
			Help: "Response HTTP status code",
		})

		probeSSLEarliestCertExpiryGauge = prometheus.NewGauge(sslEarliestCertExpiryGaugeOpts)

		probeSSLLastChainExpiryTimestampSeconds = prometheus.NewGauge(sslChainExpiryInTimeStampGaugeOpts)

		probeSSLLastInformation = prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "probe_ssl_last_chain_info",
				Help: "Contains SSL leaf certificate information",
			},
			[]string{"fingerprint_sha256", "subject", "issuer", "subjectalternative"},
		)

		probeTLSVersion = prometheus.NewGaugeVec(
			probeTLSInfoGaugeOpts,
			[]string{"version"},
		)

		probeHTTPVersionGauge = prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "probe_web3_version",
			Help: "Returns the version of HTTP of the probe response",
		})

		probeFailedDueToRegex = prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "probe_failed_due_to_regex",
			Help: "Indicates if probe failed due to regex",
		})

		probeHTTPLastModified = prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "probe_web3_last_modified_timestamp_seconds",
			Help: "Returns the Last-Modified HTTP response header in unixtime",
		})
	)

	registry.MustRegister(durationGaugeVec)
	registry.MustRegister(contentLengthGauge)
	registry.MustRegister(blockNumberGauge)
	registry.MustRegister(blockTimestampGauge)
	registry.MustRegister(bodyUncompressedLengthGauge)
	registry.MustRegister(redirectsGauge)
	registry.MustRegister(isSSLGauge)
	registry.MustRegister(statusCodeGauge)
	registry.MustRegister(probeHTTPVersionGauge)
	registry.MustRegister(probeFailedDueToRegex)

	web3Config := module.Web3

	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		target = "http://" + target
	}

	targetURL, err := url.Parse(target)
	if err != nil {
		level.Error(logger).Log("msg", "Could not parse target URL", "err", err)
		return false
	}

	targetHost := targetURL.Hostname()
	targetPort := targetURL.Port()

	var ip *net.IPAddr
	if !module.HTTP.SkipResolvePhaseWithProxy || module.HTTP.HTTPClientConfig.ProxyURL.URL == nil {
		var lookupTime float64
		ip, lookupTime, err = chooseProtocol(ctx, module.HTTP.IPProtocol, module.HTTP.IPProtocolFallback, targetHost, registry, logger)
		durationGaugeVec.WithLabelValues("resolve").Add(lookupTime)
		if err != nil {
			level.Error(logger).Log("msg", "Error resolving address", "err", err)
			return false
		}
	}

	httpClientConfig := module.Web3.HTTPClientConfig
	if len(httpClientConfig.TLSConfig.ServerName) == 0 {
		// If there is no `server_name` in tls_config, use
		// the hostname of the target.
		httpClientConfig.TLSConfig.ServerName = targetHost

		// However, if there is a Host header it is better to use
		// its value instead. This helps avoid TLS handshake error
		// if targetHost is an IP address.
		for name, value := range web3Config.Headers {
			if textproto.CanonicalMIMEHeaderKey(name) == "Host" {
				httpClientConfig.TLSConfig.ServerName = value
			}
		}
	}
	client, err := pconfig.NewClientFromConfig(httpClientConfig, "web3_probe", pconfig.WithKeepAlivesDisabled())
	if err != nil {
		level.Error(logger).Log("msg", "Error generating HTTP client", "err", err)
		return false
	}

	httpClientConfig.TLSConfig.ServerName = ""
	noServerName, err := pconfig.NewRoundTripperFromConfig(httpClientConfig, "web3_probe", pconfig.WithKeepAlivesDisabled())
	if err != nil {
		level.Error(logger).Log("msg", "Error generating HTTP client without ServerName", "err", err)
		return false
	}

	jar, err := cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
	if err != nil {
		level.Error(logger).Log("msg", "Error generating cookiejar", "err", err)
		return false
	}
	client.Jar = jar

	// Inject transport that tracks traces for each redirect,
	// and does not set TLS ServerNames on redirect if needed.
	tt := newTransport(client.Transport, noServerName, logger)
	client.Transport = tt

	client.CheckRedirect = func(r *http.Request, via []*http.Request) error {
		level.Info(logger).Log("msg", "Received redirect", "location", r.Response.Header.Get("Location"))
		redirects = len(via)
		if redirects > 10 || !web3Config.HTTPClientConfig.FollowRedirects {
			level.Info(logger).Log("msg", "Not following redirect")
			return errors.New("don't follow redirects")
		}
		return nil
	}

	if web3Config.Method == "" {
		web3Config.Method = "GET"
	}

	origHost := targetURL.Host
	if ip != nil {
		// Replace the host field in the URL with the IP we resolved.
		if targetPort == "" {
			if strings.Contains(ip.String(), ":") {
				targetURL.Host = "[" + ip.String() + "]"
			} else {
				targetURL.Host = ip.String()
			}
		} else {
			targetURL.Host = net.JoinHostPort(ip.String(), targetPort)
		}
	}

	var (
		body           io.Reader
		respBodyBytes  int64
		blockNumber    uint64
		blockTimestamp uint64
	)

	switch {
	case web3Config.IsEthereum:
		body = strings.NewReader(EthereumRequest)
	case web3Config.IsStarknet:
		body = strings.NewReader(StarknetRequest)
	case web3Config.Body != "":
		body = strings.NewReader(web3Config.Body)
	case web3Config.BodyFile != "":
		body_file, err := os.Open(web3Config.BodyFile)
		if err != nil {
			level.Error(logger).Log("msg", "Error creating request", "err", err)
			return
		}
		defer body_file.Close()
		body = body_file
	}

	request, err := http.NewRequest(web3Config.Method, targetURL.String(), body)
	if err != nil {
		level.Error(logger).Log("msg", "Error creating request", "err", err)
		return
	}
	request.Host = origHost
	request = request.WithContext(ctx)

	for key, value := range web3Config.Headers {
		if textproto.CanonicalMIMEHeaderKey(key) == "Host" {
			request.Host = value
			continue
		}

		request.Header.Set(key, value)
	}

	_, hasUserAgent := request.Header["User-Agent"]
	if !hasUserAgent {
		request.Header.Set("User-Agent", userAgentDefaultHeader)
	}

	trace := &httptrace.ClientTrace{
		DNSStart:             tt.DNSStart,
		DNSDone:              tt.DNSDone,
		ConnectStart:         tt.ConnectStart,
		ConnectDone:          tt.ConnectDone,
		GotConn:              tt.GotConn,
		GotFirstResponseByte: tt.GotFirstResponseByte,
		TLSHandshakeStart:    tt.TLSHandshakeStart,
		TLSHandshakeDone:     tt.TLSHandshakeDone,
	}
	request = request.WithContext(httptrace.WithClientTrace(request.Context(), trace))

	for _, lv := range []string{"connect", "tls", "processing", "transfer"} {
		durationGaugeVec.WithLabelValues(lv)
	}

	resp, err := client.Do(request)
	// This is different from the usual err != nil you'd expect here because err won't be nil if redirects were
	// turned off. See https://github.com/golang/go/issues/3795
	//
	// If err == nil there should never be a case where resp is also nil, but better be safe than sorry, so check if
	// resp == nil first, and then check if there was an error.
	if resp == nil {
		resp = &http.Response{}
		if err != nil {
			level.Error(logger).Log("msg", "Error for HTTP request", "err", err)
		}
	} else {
		requestErrored := (err != nil)

		level.Info(logger).Log("msg", "Received HTTP response", "status_code", resp.StatusCode)
		if len(web3Config.ValidStatusCodes) != 0 {
			for _, code := range web3Config.ValidStatusCodes {
				if resp.StatusCode == code {
					success = true
					break
				}
			}
			if !success {
				level.Info(logger).Log("msg", "Invalid HTTP response status code", "status_code", resp.StatusCode,
					"valid_status_codes", fmt.Sprintf("%v", web3Config.ValidStatusCodes))
			}
		} else if 200 <= resp.StatusCode && resp.StatusCode < 300 {
			success = true
		} else {
			level.Info(logger).Log("msg", "Invalid HTTP response status code, wanted 2xx", "status_code", resp.StatusCode)
		}

		// Since the configuration specifies a compression algorithm, blindly treat the response body as a
		// compressed payload; if we cannot decompress it it's a failure because the configuration says we
		// should expect the response to be compressed in that way.
		if web3Config.Compression != "" {
			dec, err := getDecompressionReader(web3Config.Compression, resp.Body)
			if err != nil {
				level.Info(logger).Log("msg", "Failed to get decompressor for HTTP response body", "err", err)
				success = false
			} else if dec != nil {
				// Since we are replacing the original resp.Body with the decoder, we need to make sure
				// we close the original body. We cannot close it right away because the decompressor
				// might not have read it yet.
				defer func(c io.Closer) {
					err := c.Close()
					if err != nil {
						// At this point we cannot really do anything with this error, but log
						// it in case it contains useful information as to what's the problem.
						level.Info(logger).Log("msg", "Error while closing response from server", "err", err)
					}
				}(resp.Body)

				resp.Body = dec
			}
		}

		// If there's a configured body_size_limit, wrap the body in the response in a http.MaxBytesReader.
		// This will read up to BodySizeLimit bytes from the body, and return an error if the response is
		// larger. It forwards the Close call to the original resp.Body to make sure the TCP connection is
		// correctly shut down. The limit is applied _after decompression_ if applicable.
		if web3Config.BodySizeLimit > 0 {
			resp.Body = http.MaxBytesReader(nil, resp.Body, int64(web3Config.BodySizeLimit))
		}

		byteCounter := &byteCounter{ReadCloser: resp.Body}

		if !requestErrored {
			var resp bytes.Buffer
			_, err = io.Copy(&resp, byteCounter)
			if err != nil {
				level.Info(logger).Log("msg", "Failed to read HTTP response body", "err", err)
				success = false
			}

			if web3Config.IsEthereum {
				var block EthereumResponse
				if err := json.Unmarshal(resp.Bytes(), &block); err != nil {
					level.Info(logger).Log("msg", "Failed to unmarshal ethereum block", "err", err)
					success = false
				} else {
					blockNumber = uint64(block.Result.Number)
					blockTimestamp = uint64(block.Result.Timestamp)
				}
			} else if web3Config.IsStarknet {
				var block StarknetResponse
				if err := json.Unmarshal(resp.Bytes(), &block); err != nil {
					level.Info(logger).Log("msg", "Failed to unmarshal starknet block", "err", err)
					success = false
				} else {
					blockNumber = uint64(block.Result.Number)
					blockTimestamp = uint64(block.Result.Timestamp)
				}
			} else if web3Config.IsAptos {
				var block AptosResponse
				if err := json.Unmarshal(resp.Bytes(), &block); err != nil {
					level.Info(logger).Log("msg", "Failed to unmarshal aptos block", "err", err)
					success = false
				} else {
					blockNumber = uint64(block.Number)
					blockTimestamp = uint64(block.Timestamp) / 1e6
				}
			}

			respBodyBytes = byteCounter.n

			if err := byteCounter.Close(); err != nil {
				// We have already read everything we could from the server, maybe even uncompressed the
				// body. The error here might be either a decompression error or a TCP error. Log it in
				// case it contains useful information as to what's the problem.
				level.Info(logger).Log("msg", "Error while closing response from server", "error", err.Error())
			}
		}

		// At this point body is fully read and we can write end time.
		tt.current.end = time.Now()

		// Check if there is a Last-Modified HTTP response header.
		if t, err := http.ParseTime(resp.Header.Get("Last-Modified")); err == nil {
			registry.MustRegister(probeHTTPLastModified)
			probeHTTPLastModified.Set(float64(t.Unix()))
		}

		var httpVersionNumber float64
		httpVersionNumber, err = strconv.ParseFloat(strings.TrimPrefix(resp.Proto, "HTTP/"), 64)
		if err != nil {
			level.Error(logger).Log("msg", "Error parsing version number from HTTP version", "err", err)
		}
		probeHTTPVersionGauge.Set(httpVersionNumber)

		if len(web3Config.ValidHTTPVersions) != 0 {
			found := false
			for _, version := range web3Config.ValidHTTPVersions {
				if version == resp.Proto {
					found = true
					break
				}
			}
			if !found {
				level.Error(logger).Log("msg", "Invalid HTTP version number", "version", resp.Proto)
				success = false
			}
		}
	}

	tt.mu.Lock()
	defer tt.mu.Unlock()
	for i, trace := range tt.traces {
		level.Info(logger).Log(
			"msg", "Response timings for roundtrip",
			"roundtrip", i,
			"start", trace.start,
			"dnsDone", trace.dnsDone,
			"connectDone", trace.connectDone,
			"gotConn", trace.gotConn,
			"responseStart", trace.responseStart,
			"tlsStart", trace.tlsStart,
			"tlsDone", trace.tlsDone,
			"end", trace.end,
		)
		// We get the duration for the first request from chooseProtocol.
		if i != 0 {
			durationGaugeVec.WithLabelValues("resolve").Add(trace.dnsDone.Sub(trace.start).Seconds())
		}
		// Continue here if we never got a connection because a request failed.
		if trace.gotConn.IsZero() {
			continue
		}
		if trace.tls {
			// dnsDone must be set if gotConn was set.
			durationGaugeVec.WithLabelValues("connect").Add(trace.connectDone.Sub(trace.dnsDone).Seconds())
			durationGaugeVec.WithLabelValues("tls").Add(trace.tlsDone.Sub(trace.tlsStart).Seconds())
		} else {
			durationGaugeVec.WithLabelValues("connect").Add(trace.gotConn.Sub(trace.dnsDone).Seconds())
		}

		// Continue here if we never got a response from the server.
		if trace.responseStart.IsZero() {
			continue
		}
		durationGaugeVec.WithLabelValues("processing").Add(trace.responseStart.Sub(trace.gotConn).Seconds())

		// Continue here if we never read the full response from the server.
		// Usually this means that request either failed or was redirected.
		if trace.end.IsZero() {
			continue
		}
		durationGaugeVec.WithLabelValues("transfer").Add(trace.end.Sub(trace.responseStart).Seconds())
	}

	if resp.TLS != nil {
		isSSLGauge.Set(float64(1))
		registry.MustRegister(probeSSLEarliestCertExpiryGauge, probeTLSVersion, probeSSLLastChainExpiryTimestampSeconds, probeSSLLastInformation)
		probeSSLEarliestCertExpiryGauge.Set(float64(getEarliestCertExpiry(resp.TLS).Unix()))
		probeTLSVersion.WithLabelValues(getTLSVersion(resp.TLS)).Set(1)
		probeSSLLastChainExpiryTimestampSeconds.Set(float64(getLastChainExpiry(resp.TLS).Unix()))
		probeSSLLastInformation.WithLabelValues(getFingerprint(resp.TLS), getSubject(resp.TLS), getIssuer(resp.TLS), getDNSNames(resp.TLS)).Set(1)
		if web3Config.FailIfSSL {
			level.Error(logger).Log("msg", "Final request was over SSL")
			success = false
		}
	} else if web3Config.FailIfNotSSL {
		level.Error(logger).Log("msg", "Final request was not over SSL")
		success = false
	}

	statusCodeGauge.Set(float64(resp.StatusCode))
	contentLengthGauge.Set(float64(resp.ContentLength))
	bodyUncompressedLengthGauge.Set(float64(respBodyBytes))
	redirectsGauge.Set(float64(redirects))
	blockNumberGauge.Set(float64(blockNumber))
	blockTimestampGauge.Set(float64(blockTimestamp))
	return
}
