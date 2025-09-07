// Package rtsp contains the RTSP static source.
package rtsp

import (
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/bluenviron/gortsplib/v4"
	"github.com/bluenviron/gortsplib/v4/pkg/base"
	"github.com/bluenviron/gortsplib/v4/pkg/headers"

	"github.com/bluenviron/mediamtx/internal/conf"
	"github.com/bluenviron/mediamtx/internal/counterdumper"
	"github.com/bluenviron/mediamtx/internal/defs"
	"github.com/bluenviron/mediamtx/internal/logger"
	"github.com/bluenviron/mediamtx/internal/protocols/rtsp"
	"github.com/bluenviron/mediamtx/internal/protocols/tls"
)

// processRTSPURL processes an RTSP URL based on configuration settings
func processRTSPURL(rawURL string, autoAddPort bool) (string, error) {
	// If auto-add port is disabled, return URL as-is
	if !autoAddPort {
		return rawURL, nil
	}

	// Parse the URL to check if port is already specified
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL, err
	}

	// If port is already specified, return as-is
	if u.Port() != "" {
		return rawURL, nil
	}

	// Add default port 554 for RTSP
	if strings.Contains(u.Host, ":") {
		// IPv6 address - use net.JoinHostPort for proper formatting
		u.Host = net.JoinHostPort(u.Host, "554")
	} else {
		// IPv4 address or hostname
		u.Host = u.Host + ":554"
	}

	return u.String(), nil
}

func createRangeHeader(cnf *conf.Path) (*headers.Range, error) {
	switch cnf.RTSPRangeType {
	case conf.RTSPRangeTypeClock:
		start, err := time.Parse("20060102T150405Z", cnf.RTSPRangeStart)
		if err != nil {
			return nil, err
		}

		return &headers.Range{
			Value: &headers.RangeUTC{
				Start: start,
			},
		}, nil

	case conf.RTSPRangeTypeNPT:
		start, err := time.ParseDuration(cnf.RTSPRangeStart)
		if err != nil {
			return nil, err
		}

		return &headers.Range{
			Value: &headers.RangeNPT{
				Start: start,
			},
		}, nil

	case conf.RTSPRangeTypeSMPTE:
		start, err := time.ParseDuration(cnf.RTSPRangeStart)
		if err != nil {
			return nil, err
		}

		return &headers.Range{
			Value: &headers.RangeSMPTE{
				Start: headers.RangeSMPTETime{
					Time: start,
				},
			},
		}, nil

	default:
		return nil, nil
	}
}

type parent interface {
	logger.Writer
	SetReady(req defs.PathSourceStaticSetReadyReq) defs.PathSourceStaticSetReadyRes
	SetNotReady(req defs.PathSourceStaticSetNotReadyReq)
}

// Source is a RTSP static source.
type Source struct {
	ReadTimeout    conf.Duration
	WriteTimeout   conf.Duration
	WriteQueueSize int
	Parent         parent
}

// Log implements logger.Writer.
func (s *Source) Log(level logger.Level, format string, args ...interface{}) {
	s.Parent.Log(level, "[RTSP source] "+format, args...)
}

// Run implements StaticSource.
func (s *Source) Run(params defs.StaticSourceRunParams) error {
	s.Log(logger.Debug, "connecting")

	packetsLost := &counterdumper.CounterDumper{
		OnReport: func(val uint64) {
			s.Log(logger.Warn, "%d RTP %s lost",
				val,
				func() string {
					if val == 1 {
						return "packet"
					}
					return "packets"
				}())
		},
	}

	packetsLost.Start()
	defer packetsLost.Stop()

	decodeErrors := &counterdumper.CounterDumper{
		OnReport: func(val uint64) {
			s.Log(logger.Warn, "%d decode %s",
				val,
				func() string {
					if val == 1 {
						return "error"
					}
					return "errors"
				}())
		},
	}

	decodeErrors.Start()
	defer decodeErrors.Stop()

	// Process the RTSP URL based on configuration
	autoAddPort := true
	if params.Conf.RTSPAutoAddDefaultPort != nil {
		autoAddPort = *params.Conf.RTSPAutoAddDefaultPort
	}

	processedURL, err := processRTSPURL(params.ResolvedSource, autoAddPort)
	if err != nil {
		return err
	}

	u, err := base.ParseURL(processedURL)
	if err != nil {
		return err
	}

	c := &gortsplib.Client{
		Scheme:            u.Scheme,
		Host:              u.Host,
		Transport:         params.Conf.RTSPTransport.Transport,
		TLSConfig:         tls.ConfigForFingerprint(params.Conf.SourceFingerprint),
		ReadTimeout:       time.Duration(s.ReadTimeout),
		WriteTimeout:      time.Duration(s.WriteTimeout),
		WriteQueueSize:    s.WriteQueueSize,
		UDPReadBufferSize: int(params.Conf.RTSPUDPReadBufferSize),
		AnyPortEnable:     params.Conf.RTSPAnyPort,
		OnRequest: func(req *base.Request) {
			s.Log(logger.Debug, "[c->s] %v", req)
		},
		OnResponse: func(res *base.Response) {
			s.Log(logger.Debug, "[s->c] %v", res)
		},
		OnTransportSwitch: func(err error) {
			s.Log(logger.Warn, err.Error())
		},
		OnPacketsLost: func(lost uint64) {
			packetsLost.Add(lost)
		},
		OnDecodeError: func(_ error) {
			decodeErrors.Increase()
		},
	}

	err = c.Start2()
	if err != nil {
		return err
	}
	defer c.Close()

	readErr := make(chan error)
	go func() {
		readErr <- func() error {
			desc, _, err2 := c.Describe(u)
			if err2 != nil {
				return err2
			}

			err2 = c.SetupAll(desc.BaseURL, desc.Medias)
			if err2 != nil {
				return err2
			}

			res := s.Parent.SetReady(defs.PathSourceStaticSetReadyReq{
				Desc:               desc,
				GenerateRTPPackets: false,
			})
			if res.Err != nil {
				return res.Err
			}

			defer s.Parent.SetNotReady(defs.PathSourceStaticSetNotReadyReq{})

			rtsp.ToStream(
				c,
				desc.Medias,
				params.Conf,
				res.Stream,
				s)

			rangeHeader, err2 := createRangeHeader(params.Conf)
			if err2 != nil {
				return err2
			}

			_, err2 = c.Play(rangeHeader)
			if err2 != nil {
				return err2
			}

			return c.Wait()
		}()
	}()

	for {
		select {
		case err = <-readErr:
			return err

		case <-params.ReloadConf:

		case <-params.Context.Done():
			c.Close()
			<-readErr
			return nil
		}
	}
}

// APISourceDescribe implements StaticSource.
func (*Source) APISourceDescribe() defs.APIPathSourceOrReader {
	return defs.APIPathSourceOrReader{
		Type: "rtspSource",
		ID:   "",
	}
}
