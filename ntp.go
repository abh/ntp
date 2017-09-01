// Copyright 2015 Brett Vickers.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package ntp provides a simple mechanism for querying the current time from
// a remote NTP server. See RFC 5905. Approach inspired by go-nuts post by
// Michael Hofmann:
//
// https://groups.google.com/forum/?fromgroups#!topic/golang-nuts/FlcdMU5fkLQ
package ntp

import (
	"encoding/binary"
	"errors"
	"net"
	"time"

	"golang.org/x/net/ipv4"
)

type mode uint8

const (
	reserved mode = 0 + iota
	symmetricActive
	symmetricPassive
	client
	server
	broadcast
	controlMessage
	reservedPrivate
)

// The LeapIndicator is used to warn if a leap second should be inserted
// or deleted in the last minute of the current month.
type LeapIndicator uint8

const (
	// LeapNoWarning indicates no impending leap second
	LeapNoWarning LeapIndicator = 0

	// LeapAddSecond indicates the last minute of the day has 61 seconds
	LeapAddSecond = 1

	// LeapDelSecond indicates the last minute of the day has 59 seconds
	LeapDelSecond = 2

	// LeapNotInSync indicates an unsynchronized leap second.
	LeapNotInSync = 3
)

const (
	// MaxStratum is the largest allowable NTP stratum value
	MaxStratum = 16

	defaultNTPVersion = 4
	defaultTimeout    = 5 * time.Second
	maxDispersion     = 16
	maxPoll           = 17 // log2 max poll interval (~36 h)
	nanoPerSec        = 1000000000
)

var (
	ntpEpoch = time.Date(1900, 1, 1, 0, 0, 0, 0, time.UTC)
)

// An ntpTime is a 64-bit fixed-point (Q32.32) representation of the number of
// seconds elapsed since the NTP epoch.
type ntpTime uint64

// Duration interprets the fixed-point ntpTime as a number of elapsed seconds
// and returns the corresponding time.Duration value.
func (t ntpTime) Duration() time.Duration {
	sec := (t >> 32) * nanoPerSec
	frac := (t & 0xffffffff) * nanoPerSec >> 32
	return time.Duration(sec + frac)
}

// Time interprets the fixed-point ntpTime as a an absolute time and returns
// the corresponding time.Time value.
func (t ntpTime) Time() time.Time {
	return ntpEpoch.Add(t.Duration())
}

// toNtpTime converts the time.Time value t into its 64-bit fixed-point
// ntpTime representation.
func toNtpTime(t time.Time) ntpTime {
	nsec := uint64(t.Sub(ntpEpoch))
	sec := nsec / nanoPerSec
	frac := (nsec - sec*nanoPerSec) << 32 / nanoPerSec
	return ntpTime(sec<<32 | frac)
}

// An ntpTimeShort is a 32-bit fixed-point (Q16.16) representation of the
// number of seconds elapsed since the NTP epoch.
type ntpTimeShort uint32

// Duration interprets the fixed-point ntpTimeShort as a number of elapsed
// seconds and returns the corresponding time.Duration value.
func (t ntpTimeShort) Duration() time.Duration {
	t64 := uint64(t)
	sec := (t64 >> 16) * nanoPerSec
	frac := (t64 & 0xffff) * nanoPerSec >> 16
	return time.Duration(sec + frac)
}

// msg is an internal representation of an NTP packet.
type msg struct {
	LiVnMode       uint8 // Leap Indicator (2) + Version (3) + Mode (3)
	Stratum        uint8
	Poll           int8
	Precision      int8
	RootDelay      ntpTimeShort
	RootDispersion ntpTimeShort
	ReferenceID    uint32
	ReferenceTime  ntpTime
	OriginTime     ntpTime
	ReceiveTime    ntpTime
	TransmitTime   ntpTime
}

// setVersion sets the NTP protocol version on the message.
func (m *msg) setVersion(v int) {
	m.LiVnMode = (m.LiVnMode & 0xc7) | uint8(v)<<3
}

// setMode sets the NTP protocol mode on the message.
func (m *msg) setMode(md mode) {
	m.LiVnMode = (m.LiVnMode & 0xf8) | uint8(md)
}

// setLeapIndicator modifies the leap indicator on the message.
func (m *msg) setLeapIndicator(li LeapIndicator) {
	m.LiVnMode = (m.LiVnMode & 0x3f) | uint8(li)<<6
}

// getLeapIndicator returns the leap indicator on the message.
func (m *msg) getLeapIndicator() LeapIndicator {
	return LeapIndicator((m.LiVnMode >> 6) & 0x03)
}

// QueryOptions contains the list of configurable options that may be used with
// the QueryWithOptions function.
type QueryOptions struct {
	Timeout time.Duration // defaults to 5 seconds
	Version int           // NTP protocol version, defaults to 4
	Port    int           // NTP Server port for UDPAddr.Port, defaults to 123
	TTL     int           // IP TTL to use for outgoing UDP packets, defaults to system default
}

// A Response contains time data, some of which is returned by the NTP server
// and some of which is calculated by the client.
type Response struct {
	// Time is the "transmit time" reported by the server.
	Time time.Time

	// RTT is the calculated round-trip-time between the client and the
	// server.
	RTT time.Duration

	// ClockOffset is the calculated offset of the local clock relative to
	// the server.
	ClockOffset time.Duration

	// Poll is the maximum polling interval between successive messages.
	Poll time.Duration

	// Precision describes the precision of the server's clock.
	Precision time.Duration

	// Leap indicates whether the time requires a leap second adjustment.
	// See https://tools.ietf.org/html/rfc5905#section-7.3.
	Leap LeapIndicator

	// Stratum is the 8-bit value identifying the server's stratum.
	Stratum uint8

	// ReferenceID is a 32-bit code identifying the particular server or
	// reference clock. See https://tools.ietf.org/html/rfc5905#section-7.3
	// for interpretation of this value.
	ReferenceID uint32

	// Reference time is the time when the server's system clock was last
	// set or updated.
	ReferenceTime time.Time

	// RootDelay is the server's round-trip-time to the reference clock.
	RootDelay time.Duration

	// RootDispersion is the dispersion to the server's reference clock.
	RootDispersion time.Duration

	// RootDistance is the calculated single-packet estimate of the root
	// synchronization distance. Some SNTP clients limit-check this value
	// before using the response. For example, systemd-timesyncd uses 5.0s
	// as an upper bound. See https://tools.ietf.org/html/rfc5905#appendix-A.5.5.2
	RootDistance time.Duration

	// CausalityViolation is a time duration representing the amount of
	// causality violation between two sets of timestamps. It may be used as a
	// lower bound on the current time synchronization error between the local
	// and server clock. A leap second may contribute as much as 1 second of
	// causality violation.
	CausalityViolation time.Duration
}

// Validate the response to determine if it can be used for the purpose of
// time synchronization.
func (r *Response) Validate() bool {
	// Reference Timestamp: Time when the system clock was last set or
	// corrected. Semantics of this value seems to vary across NTP server
	// implementations: it may be both NTP-clock time and system wall-clock
	// time of this event. :-( So (T3 - ReferenceTime) is not true
	// "freshness" as it may be actually NEGATIVE sometimes.
	freshness := r.Time.Sub(r.ReferenceTime)

	// (Lambda := RootDelay/2 + RootDispersion) check against MAXDISP (16s)
	// is required as ntp.org ntpd may report sane other fields while
	// giving quite erratic clock. The check is declared in packet() at
	// https://tools.ietf.org/html/rfc5905#appendix-A.5.1.1.
	lambda := r.RootDelay/2 + r.RootDispersion

	// `r.RTT > 0` check is not included as it does not depend on the
	// packet itself, but also depends on clock _speed_. It's indicator
	// that local clock run faster than remote one, so (T4-T1) < (T3-T2),
	// but it may be local clock issue.
	// E.g. T1/T2/T3/T4 = 0/10/20/1 leads to RTT = -9s.

	return r.Leap != LeapNotInSync && // RFC5905, packet()
		0 < r.Stratum && r.Stratum < MaxStratum && // RFC5905, packet()
		lambda < maxDispersion*time.Second && // RFC5905, packet()
		!r.Time.Before(r.ReferenceTime) && // RFC5905, packet(), reftime <= xmt ~~ !(xmt < reftime)
		freshness <= (1<<maxPoll)*time.Second && // ntpdate uses 24h as a heuristics instead of ~36h derived from MAXPOLL
		ntpEpoch.Before(r.Time) && // sanity
		ntpEpoch.Before(r.ReferenceTime) // sanity
}

// Query returns the current time from the remote server host. It also returns
// additional information about the exchanged time information.
func Query(host string) (*Response, error) {
	return QueryWithOptions(host, QueryOptions{})
}

// QueryWithOptions returns the current time from the remote server host.
// It also returns additional information about the exchanged time
// information. It allows the specification of additional query options.
func QueryWithOptions(host string, opt QueryOptions) (*Response, error) {
	m, now, err := getTime(host, opt)
	if err != nil {
		return nil, err
	}
	return parseTime(m, now), nil
}

// parseTime parses an SNTP packet and uses the packet arrival time to
// generate a Response record.
func parseTime(m *msg, dst ntpTime) *Response {
	r := &Response{
		Time:           m.TransmitTime.Time(),
		RTT:            rtt(m.OriginTime, m.ReceiveTime, m.TransmitTime, dst),
		ClockOffset:    offset(m.OriginTime, m.ReceiveTime, m.TransmitTime, dst),
		Poll:           toInterval(m.Poll),
		Precision:      toInterval(m.Precision),
		Leap:           m.getLeapIndicator(),
		Stratum:        m.Stratum,
		ReferenceID:    m.ReferenceID,
		ReferenceTime:  m.ReferenceTime.Time(),
		RootDelay:      m.RootDelay.Duration(),
		RootDispersion: m.RootDispersion.Duration(),
	}

	// These fields are calculated using other calculated fields.
	r.RootDistance = rootDistance(r.RTT, r.RootDelay, r.RootDispersion)
	r.CausalityViolation = causalityViolation(r.RTT, r.ClockOffset)

	// https://tools.ietf.org/html/rfc5905#section-7.3
	if r.Stratum == 0 {
		r.Stratum = MaxStratum
	}

	return r
}

// getTime performs the SNTP request over UDP and returns the SNTP
// message and DestinationTime.
func getTime(host string, opt QueryOptions) (*msg, ntpTime, error) {
	if opt.Version == 0 {
		opt.Version = defaultNTPVersion
	}

	if opt.Version < 2 || opt.Version > 4 {
		panic("ntp: invalid version number")
	}

	if opt.Timeout == 0 {
		opt.Timeout = defaultTimeout
	}

	raddr, err := net.ResolveUDPAddr("udp", host+":123")
	if err != nil {
		return nil, 0, err
	}

	if opt.Port != 0 {
		raddr.Port = opt.Port
	}

	con, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		return nil, 0, err
	}
	defer con.Close()

	if opt.TTL != 0 {
		ipcon := ipv4.NewConn(con)
		err = ipcon.SetTTL(opt.TTL)
		if err != nil {
			return nil, 0, err
		}
	}

	con.SetDeadline(time.Now().Add(opt.Timeout))

	req := new(msg)
	req.setMode(client)
	req.setVersion(opt.Version)
	req.setLeapIndicator(LeapNotInSync)

	resp := new(msg)

	// Use the current time as the request's transmit time. Using a random
	// value would provide better privacy and resistance to spoofing, but
	// math/rand is not secure and crypto/rand is not available on every
	// platform.
	transmitTime := time.Now()
	req.TransmitTime = toNtpTime(transmitTime)

	// Issue the request.
	err = binary.Write(con, binary.BigEndian, req)
	if err != nil {
		return nil, 0, err
	}

	// Await the response.
	err = binary.Read(con, binary.BigEndian, resp)
	if err != nil {
		return nil, 0, err
	}

	delta := time.Since(transmitTime)
	dst := toNtpTime(transmitTime.Add(delta))

	// A packet is bogus if the response's origin timestamp doesn't match the
	// request's transmit timestamp.
	// See https://tools.ietf.org/html/rfc5905#section-8
	if resp.OriginTime != req.TransmitTime {
		return nil, 0, errors.New("response OriginTime != request TransmitTime")
	}

	// Go 1.9 has a monotonic clock preventing this, but 1.8 doesn't.
	if resp.OriginTime > dst {
		return nil, 0, errors.New("client clock tick backwards")
	}

	if resp.ReceiveTime > resp.TransmitTime {
		return nil, 0, errors.New("server clock tick backwards")
	}

	return resp, dst, nil
}

// TimeV returns the current time from the remote server host using the
// requested version of the NTP protocol. On error, it returns the local time.
// The version may be 2, 3, or 4.
func TimeV(host string, version int) (time.Time, error) {
	m, dst, err := getTime(host, QueryOptions{Version: version})
	if err != nil {
		return time.Now(), err
	}
	r := parseTime(m, dst)
	if !r.Validate() {
		return time.Now(), errors.New("invalid SNTP reply")
	}
	// An SNTP client implementing the on-wire protocol has a single server
	// and no dependent clients.  It can operate with any subset of the NTP
	// on-wire protocol, the simplest approach using only the transmit
	// timestamp of the server packet and ignoring all other fields.
	// -- https://tools.ietf.org/html/rfc5905#section-14
	return time.Now().Add(r.ClockOffset), nil
}

// Time returns the current time from the remote server host using version 4 of
// the NTP protocol. On error, it returns the local time.
func Time(host string) (time.Time, error) {
	return TimeV(host, defaultNTPVersion)
}

func rtt(t1, t2, t3, t4 ntpTime) time.Duration {
	// round trip delay time (https://tools.ietf.org/html/rfc5905#section-8)
	//   T1 = client send time
	//   T2 = server receive time
	//   T3 = server reply time
	//   T4 = client receive time
	//
	// RTT d:
	//   d = (T4-T1) - (T3-T2)
	a := t4.Time().Sub(t1.Time())
	b := t3.Time().Sub(t2.Time())
	return a - b
}

func offset(t1, t2, t3, t4 ntpTime) time.Duration {
	// local offset equation (https://tools.ietf.org/html/rfc5905#section-8)
	//   T1 = client send time
	//   T2 = server receive time
	//   T3 = server reply time
	//   T4 = client receive time
	//
	// Local clock offset t:
	//   t = ((T2-T1) + (T3-T4)) / 2
	a := t2.Time().Sub(t1.Time())
	b := t3.Time().Sub(t4.Time())
	return (a + b) / time.Duration(2)
}

func rootDistance(rtt, rootDelay, rootDispersion time.Duration) time.Duration {
	// RFC5905 suggests more strict check against _peer_ in fit(), that
	// root_dist should be less than MAXDIST + PHI * LOG2D(s.poll).
	// MAXPOLL is 17, so it is approximately at most (1s + 15e-6 * 2**17) =
	// 2.96608 s, but MAXDIST and MAXPOLL are confugurable values in the
	// reference implementation, so only MAXDISP check has hardcoded value
	// in Validate().
	//
	// root_dist should also have following summands
	// + Dispersion towards the peer
	// + jitter of the link to the peer
	// + PHI * (current_uptime - peer->uptime_of_last_update)
	// but all these values are 0 if only single NTP packet was sent.
	if rtt < 0 {
		rtt = 0
	}
	return (rtt+rootDelay)/2 + rootDispersion
}

func causalityViolation(rtt, clockOffset time.Duration) time.Duration {
	// SNTP query has four timestamps for consecutive events: T1, T2, T3
	// and T4. T1 and T4 use local clock, T2 and T3 use NTP clock.
	// RTT    = (T4 - T1) - (T3 - T2)     =   T4 - T3 + T2 - T1
	// Offset = (T2 + T3)/2 - (T4 + T1)/2 = (-T4 + T3 + T2 - T1) / 2
	// => T2 - T1 = RTT/2 + Offset && T4 - T3 = RTT/2 - Offset
	// If system wall-clock is synced to NTP-clock then T2 >= T1 && T4 >= T3.
	// This check may be useful against chrony NTP daemon as it starts
	// relaying sane NTP clock before system wall-clock is actually adjusted.
	violation := rtt / 2
	if clockOffset > 0 {
		violation -= clockOffset
	} else {
		violation += clockOffset
	}

	if violation < 0 {
		return -violation
	}
	return time.Duration(0)
}

func toInterval(t int8) time.Duration {
	switch {
	case t > 0:
		return time.Duration(uint64(time.Second) << uint(t))
	case t < 0:
		return time.Duration(uint64(time.Second) >> uint(-t))
	default:
		return time.Second
	}
}
