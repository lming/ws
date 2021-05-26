package ws

import (
	"bytes"
	"errors"
	"io"
	"net/http"

	"github.com/gobwas/pool/pbufio"
)

var ErrInvalidHTTPUpgradeRequest = errors.New("incomplete http upgrade request")

type HTTPReqBufAndWriter interface {
	io.Writer
	// Get the entire HTTP request buf that ends with two CRLFs
	GetHTTPRequestBuf() []byte
}

// Upgrade zero-copy upgrades connection to WebSocket. It interprets given http
// request in a buf w/o further reading from network.
//
// Non-nil error means that request for the WebSocket upgrade is invalid or
// malformed and usually connection should be closed.
// Even when error is non-nil Upgrade will write appropriate response into
// connection in compliance with RFC.
func (u Upgrader) UpgradeWithReqBuf(conn HTTPReqBufAndWriter) (hs Handshake, err error) {
	// Get the full http request buf ends with double CRLF is provided here
	inbuf := conn.GetHTTPRequestBuf()

	readLine := func() ([]byte, error) {
		if pos := bytes.IndexByte(inbuf, '\n'); pos >= 0 {
			line := inbuf[:pos]
			// caller expects no CRLF in the line
			if pos >= 1 && line[pos-1] == '\r' {
				line = inbuf[:pos-1]
			}
			inbuf = inbuf[pos+1:]
			return line, nil
		}
		return nil, ErrInvalidHTTPUpgradeRequest
	}

	// headerSeen constants helps to report whether or not some header was seen
	// during reading request bytes.
	const (
		headerSeenHost = 1 << iota
		headerSeenUpgrade
		headerSeenConnection
		headerSeenSecVersion
		headerSeenSecKey

		// headerSeenAll is the value that we expect to receive at the end of
		// headers read/parse loop.
		headerSeenAll = 0 |
			headerSeenHost |
			headerSeenUpgrade |
			headerSeenConnection |
			headerSeenSecVersion |
			headerSeenSecKey
	)

	// Prepare I/O buffers.
	// TODO(gobwas): make it configurable.
	//br := pbufio.GetReader(conn,
	//	nonZero(u.ReadBufferSize, DefaultServerReadBufferSize),
	//)
	bw := pbufio.GetWriter(conn,
		nonZero(u.WriteBufferSize, DefaultServerWriteBufferSize),
	)
	defer func() {
		//	pbufio.PutReader(br)
		pbufio.PutWriter(bw)
	}()

	// Read HTTP request line like "GET /ws HTTP/1.1".
	rl, err := readLine()
	if err != nil {
		return
	}
	// Parse request line data like HTTP version, uri and method.
	req, err := httpParseRequestLine(rl)
	if err != nil {
		return
	}

	// Prepare stack-based handshake header list.
	header := handshakeHeader{
		0: u.Header,
	}

	// Parse and check HTTP request.
	// As RFC6455 says:
	//   The client's opening handshake consists of the following parts. If the
	//   server, while reading the handshake, finds that the client did not
	//   send a handshake that matches the description below (note that as per
	//   [RFC2616], the order of the header fields is not important), including
	//   but not limited to any violations of the ABNF grammar specified for
	//   the components of the handshake, the server MUST stop processing the
	//   client's handshake and return an HTTP response with an appropriate
	//   error code (such as 400 Bad Request).
	//
	// See https://tools.ietf.org/html/rfc6455#section-4.2.1

	// An HTTP/1.1 or higher GET request, including a "Request-URI".
	//
	// Even if RFC says "1.1 or higher" without mentioning the part of the
	// version, we apply it only to minor part.
	switch {
	case req.major != 1 || req.minor < 1:
		// Abort processing the whole request because we do not even know how
		// to actually parse it.
		err = ErrHandshakeBadProtocol

	case btsToString(req.method) != http.MethodGet:
		err = ErrHandshakeBadMethod

	default:
		if onRequest := u.OnRequest; onRequest != nil {
			err = onRequest(req.uri)
		}
	}
	// Start headers read/parse loop.
	var (
		// headerSeen reports which header was seen by setting corresponding
		// bit on.
		headerSeen byte

		nonce = make([]byte, nonceSize)
	)
	for err == nil {
		line, e := readLine()
		if e != nil {
			return hs, e
		}
		if len(line) == 0 {
			// Blank line, no more lines to read.
			break
		}

		k, v, ok := httpParseHeaderLine(line)
		if !ok {
			err = ErrMalformedRequest
			break
		}

		switch btsToString(k) {
		case headerHostCanonical:
			headerSeen |= headerSeenHost
			if onHost := u.OnHost; onHost != nil {
				err = onHost(v)
			}

		case headerUpgradeCanonical:
			headerSeen |= headerSeenUpgrade
			if !bytes.Equal(v, specHeaderValueUpgrade) && !bytes.EqualFold(v, specHeaderValueUpgrade) {
				err = ErrHandshakeBadUpgrade
			}

		case headerConnectionCanonical:
			headerSeen |= headerSeenConnection
			if !bytes.Equal(v, specHeaderValueConnection) && !btsHasToken(v, specHeaderValueConnectionLower) {
				err = ErrHandshakeBadConnection
			}

		case headerSecVersionCanonical:
			headerSeen |= headerSeenSecVersion
			if !bytes.Equal(v, specHeaderValueSecVersion) {
				err = ErrHandshakeUpgradeRequired
			}

		case headerSecKeyCanonical:
			headerSeen |= headerSeenSecKey
			if len(v) != nonceSize {
				err = ErrHandshakeBadSecKey
			} else {
				copy(nonce[:], v)
			}

		case headerSecProtocolCanonical:
			if custom, check := u.ProtocolCustom, u.Protocol; hs.Protocol == "" && (custom != nil || check != nil) {
				var ok bool
				if custom != nil {
					hs.Protocol, ok = custom(v)
				} else {
					hs.Protocol, ok = btsSelectProtocol(v, check)
				}
				if !ok {
					err = ErrMalformedRequest
				}
			}

		case headerSecExtensionsCanonical:
			if f := u.Negotiate; err == nil && f != nil {
				hs.Extensions, err = negotiateExtensions(v, hs.Extensions, f)
			}
			// DEPRECATED path.
			if custom, check := u.ExtensionCustom, u.Extension; u.Negotiate == nil && (custom != nil || check != nil) {
				var ok bool
				if custom != nil {
					hs.Extensions, ok = custom(v, hs.Extensions)
				} else {
					hs.Extensions, ok = btsSelectExtensions(v, hs.Extensions, check)
				}
				if !ok {
					err = ErrMalformedRequest
				}
			}

		default:
			if onHeader := u.OnHeader; onHeader != nil {
				err = onHeader(k, v)
			}
		}
	}
	switch {
	case err == nil && headerSeen != headerSeenAll:
		switch {
		case headerSeen&headerSeenHost == 0:
			// As RFC2616 says:
			//   A client MUST include a Host header field in all HTTP/1.1
			//   request messages. If the requested URI does not include an
			//   Internet host name for the service being requested, then the
			//   Host header field MUST be given with an empty value. An
			//   HTTP/1.1 proxy MUST ensure that any request message it
			//   forwards does contain an appropriate Host header field that
			//   identifies the service being requested by the proxy. All
			//   Internet-based HTTP/1.1 servers MUST respond with a 400 (Bad
			//   Request) status code to any HTTP/1.1 request message which
			//   lacks a Host header field.
			err = ErrHandshakeBadHost
		case headerSeen&headerSeenUpgrade == 0:
			err = ErrHandshakeBadUpgrade
		case headerSeen&headerSeenConnection == 0:
			err = ErrHandshakeBadConnection
		case headerSeen&headerSeenSecVersion == 0:
			// In case of empty or not present version we do not send 426 status,
			// because it does not meet the ABNF rules of RFC6455:
			//
			// version = DIGIT | (NZDIGIT DIGIT) |
			// ("1" DIGIT DIGIT) | ("2" DIGIT DIGIT)
			// ; Limited to 0-255 range, with no leading zeros
			//
			// That is, if version is really invalid – we sent 426 status as above, if it
			// not present – it is 400.
			err = ErrHandshakeBadSecVersion
		case headerSeen&headerSeenSecKey == 0:
			err = ErrHandshakeBadSecKey
		default:
			panic("unknown headers state")
		}

	case err == nil && u.OnBeforeUpgrade != nil:
		header[1], err = u.OnBeforeUpgrade()
	}
	if err != nil {
		var code int
		if rej, ok := err.(*rejectConnectionError); ok {
			code = rej.code
			header[1] = rej.header
		}
		if code == 0 {
			code = http.StatusInternalServerError
		}
		httpWriteResponseError(bw, err, code, header.WriteTo)
		// Do not store Flush() error to not override already existing one.
		bw.Flush()
		return
	}

	httpWriteResponseUpgrade(bw, nonce, hs, header.WriteTo)
	err = bw.Flush()

	return
}
