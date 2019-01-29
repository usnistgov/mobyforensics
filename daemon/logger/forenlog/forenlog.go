// Package forenlog provides the logdriver for forwarding server logs to forenlog endpoints.
package forenlog // import "github.com/docker/docker/daemon/logger/forenlog"

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
//---------------
	"os/exec"
	"bytes"
	"log"
//---------------------
	"bufio"
	"io/ioutil"
//---------------
//	"github.com/docker/docker/api/types"	
//
	forenlog "github.com/RackSec/srslog"

	"github.com/docker/docker/daemon/logger"
	"github.com/docker/docker/daemon/logger/loggerutils"
	"github.com/docker/docker/pkg/urlutil"
	"github.com/docker/go-connections/tlsconfig"
	"github.com/sirupsen/logrus"
//--------------------------------------------
	//"github.com/docker/docker/container"
//---------------------------------------------
)

const (
	name        = "forenlog"
	secureProto = "tcp+tls"
)
//Priority is a combination of the syslog facility and severity. For example, LOG_ALERT | LOG_FTP sends an alert severity message from the FTP facility. The default severity is LOG_EMERG; the default facility is LOG_KERN.
//const LOG_KERN Priority
//From /usr/include/sys/syslog.h. These are the same up to LOG_FTP on Linux, BSD, and OS X.

var facilities = map[string]forenlog.Priority{
	"kern":     forenlog.LOG_KERN,
	"user":     forenlog.LOG_USER,
	"mail":     forenlog.LOG_MAIL,
	"daemon":   forenlog.LOG_DAEMON,
	"auth":     forenlog.LOG_AUTH,
	"forenlog":   forenlog.LOG_SYSLOG, //dont change this in forenlog.Log_FORENLOG
	"lpr":      forenlog.LOG_LPR,
	"news":     forenlog.LOG_NEWS,
	"uucp":     forenlog.LOG_UUCP,
	"cron":     forenlog.LOG_CRON,
	"authpriv": forenlog.LOG_AUTHPRIV,
	"ftp":      forenlog.LOG_FTP,
	"local0":   forenlog.LOG_LOCAL0,
	"local1":   forenlog.LOG_LOCAL1,
	"local2":   forenlog.LOG_LOCAL2,
	"local3":   forenlog.LOG_LOCAL3,
	"local4":   forenlog.LOG_LOCAL4,
	"local5":   forenlog.LOG_LOCAL5,
	"local6":   forenlog.LOG_LOCAL6,
	"local7":   forenlog.LOG_LOCAL7,
}

type forenlogger struct {
	writer *forenlog.Writer
}


//_________________________________________________________________

/*
func readNextBytes(file io.Reader, number int) []byte{
    bytes := make([]byte, number)
    _, err := file.Read(bytes)
    if err != nil {
        log.Fatal("err")
    }
    return bytes
}

func logx(){
	data,_:= ioutil.ReadFile(os.Args[1])
	buffer := bytes.NewBuffer(data)
	fmt.Println(buffer)
}
*/
func pstreeforMoby(){// this is working and updating data into pstreeforMobyOutput.txt file 29 Jan 2019
	//pid := logPID()
	//args := []string{"strace", "-p", logx()}
	args := []string{"pstree", "-p"}
	cmd := exec.Command(args[0], args[1])
	var out bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
    	fmt.Println(fmt.Sprint(err) + ": " + stderr.String())
    	return
	}
	file, err := os.Create("/var/log/p633782/pstreeforMobyOutput.txt")// writing output into file rather than standard output
	if err != nil { 
        log.Fatal("Cannot create file", err)
    }
    	defer file.Close()
	fmt.Fprintf(file, out.String())
}
//---------------------------strace output for running container--------------------
//----------ioutil.ReadFile("this is reading from inspect program output file")-----
//------------inspect.go is developed to provide process ID of running container----
//-------import : "bufio" "fmt" "os" "os/exec" "io/ioutil"-------------------------
//------program file: 05/09Readfromfiledocker .go------------------------------------------

//------------------------"function is working but result is not udating as per requirement"---
/*
strace: attach: ptrace(PTRACE_SEIZE, 2041): Operation not permitted
Output is exec: already started
Error is exec: already started
*/

var (
	reader = bufio.NewReader(os.Stdin)
)
func ReadFromFile() string {
    b, err := ioutil.ReadFile("/var/log/p633782/runningcontianerPID.txt")
    if err != nil {
        fmt.Print(err)
    }
    str := string(b)
    return str
}

func StraceforMoby(){// function is working 21 Jan 2019; need to update for desired output
	app := "strace"
	arg0 := "-p"
	s := ReadFromFile()
	cmd := exec.Command(app, arg0, s)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	fmt.Println("Output is",cmd.Run()) 
	if err != nil {
		fmt.Println("Error is",cmd.Run()) 
	}
}

//_________________________________________________________________

//RegisterLogDriver registers the given logging driver builder with given logging driver name. 
//RegisterLogOptValidator registers the logging option validator with the given logging driver name. 
func init() {
	if err := logger.RegisterLogDriver(name, New); err != nil {
		logrus.Fatal(err)
	}
	if err := logger.RegisterLogOptValidator(name, ValidateLogOpt); err != nil {
		logrus.Fatal(err)
	}
//------------------------------------function called---------------------
	pstreeforMoby()
	StraceforMoby()
//------------------------------------------------------------------------	
}

// rsyslog uses appname part of syslog message to fill in an %syslogtag% template
// attribute in rsyslog.conf. In order to be backward compatible to rfc3164
// tag will be also used as an appname
// RFC 3164 The BSD syslog Protocol
// RFC 5424 The Syslog Protocol
// time.Now() Package time provides functionality for measuring and displaying time. Now returns the current local time. 
// RFC 3339 Date and Time on the Internet: Timestamps
func rfc5424formatterWithAppNameAsTag(p forenlog.Priority, hostname, tag, content string) string {
	timestamp := time.Now().Format(time.RFC3339)
	pid := os.Getpid()
	msg := fmt.Sprintf("<%d>%d %s %s %s %d %s - %s",
		p, 1, timestamp, hostname, tag, pid, tag, content)
	return msg
}

// The timestamp field in rfc5424 is derived from rfc3339. Whereas rfc3339 makes allowances
// for multiple syntaxes, there are further restrictions in rfc5424, i.e., the maximum
// resolution is limited to "TIME-SECFRAC" which is 6 (microsecond resolution)
func rfc5424microformatterWithAppNameAsTag(p forenlog.Priority, hostname, tag, content string) string {
	timestamp := time.Now().Format("2006-01-02T15:04:05.999999Z07:00")
	pid := os.Getpid()
	msg := fmt.Sprintf("<%d>%d %s %s %s %d %s - %s",
		p, 1, timestamp, hostname, tag, pid, tag, content)
	return msg
}

// New creates a syslog logger using the configuration passed in on
// the context. Supported context configuration variables are
// syslog-address, syslog-facility, syslog-format.
// Package logger defines interfaces that logger drivers implement to log messages. 
// Logger is the interface for docker logging drivers. 
func New(info logger.Info) (logger.Logger, error) {
	tag, err := loggerutils.ParseLogTag(info, loggerutils.DefaultTemplate)
	if err != nil {
		return nil, err
	}

	proto, address, err := parseAddress(info.Config["forenlog-address"])
	if err != nil {
		return nil, err
	}

	facility, err := parseFacility(info.Config["forenlog-facility"])
	if err != nil {
		return nil, err
	}

	forenlogFormatter, forenlogFramer, err := parseLogFormat(info.Config["forenlog-format"], proto)
	if err != nil {
		return nil, err
	}

	var log *forenlog.Writer
	if proto == secureProto {
		tlsConfig, tlsErr := parseTLSConfig(info.Config)
		if tlsErr != nil {
			return nil, tlsErr
		}
		log, err = forenlog.DialWithTLSConfig(proto, address, facility, tag, tlsConfig)
	} else {
		log, err = forenlog.Dial(proto, address, facility, tag)
	}

	if err != nil {
		return nil, err
	}

	log.SetFormatter(forenlogFormatter)// SetFormatter changes the formatter function for subsequent messages. 
	log.SetFramer(forenlogFramer)// SetFramer changes the framer function for subsequent messages. 
	return &forenlogger{
		writer: log,
	}, nil
}
//type forenlogger struct
func (s *forenlogger) Log(msg *logger.Message) error {
	line := string(msg.Line)
	source := msg.Source
	logger.PutMessage(msg)
	if source == "stderr" {
		return s.writer.Err(line)
	}
	return s.writer.Info(line)
}

func (s *forenlogger) Close() error {
	return s.writer.Close()
}

func (s *forenlogger) Name() string {
	return name
}
//func IsTransportURL returns true if the provided str is a transport (tcp, tcp+tls, udp, unix) URL. 
func parseAddress(address string) (string, string, error) {
	if address == "" {
		return "", "", nil
	}
	if !urlutil.IsTransportURL(address) {
		return "", "", fmt.Errorf("forenlog-address should be in form proto://address, got %v", address)
	}
	url, err := url.Parse(address)
	if err != nil {
		return "", "", err
	}

	// unix and unixgram socket validation
	// Stat returns a FileInfo describing the named file. If there is an error, it will be of type *PathError. 
	if url.Scheme == "unix" || url.Scheme == "unixgram" {
		if _, err := os.Stat(url.Path); err != nil {
			return "", "", err
		}
		return url.Scheme, url.Path, nil
	}

	// here we process tcp|udp
	// A syslog server opens port 514 and listens for incoming syslog event notifications (carried by UDP protocol packets) generated by remote syslog clients. Any number of client devices can be programmed to send syslog event messages to whatever servers they choose.
	host := url.Host
	if _, _, err := net.SplitHostPort(host); err != nil {
		if !strings.Contains(err.Error(), "missing port in address") {
			return "", "", err
		}
		host = host + ":514"
	}
	return url.Scheme, host, nil
}

// ValidateLogOpt looks for syslog specific log options
// syslog-address, syslog-facility.
func ValidateLogOpt(cfg map[string]string) error {
	for key := range cfg {
		switch key {
		case "env":
		case "env-regex":
		case "labels":
		case "forenlog-address":
		case "forenlog-facility":
		case "forenlog-tls-ca-cert":
		case "forenlog-tls-cert":
		case "forenlog-tls-key":
		case "forenlog-tls-skip-verify":
		case "tag":
		case "forenlog-format":
		default:
			return fmt.Errorf("unknown log opt '%s' for forenlog log driver", key)
		}
	}
	if _, _, err := parseAddress(cfg["forenlog-address"]); err != nil {
		return err
	}
	if _, err := parseFacility(cfg["forenlog-facility"]); err != nil {
		return err
	}
	if _, _, err := parseLogFormat(cfg["forenlog-format"], ""); err != nil {
		return err
	}
	return nil
}

func parseFacility(facility string) (forenlog.Priority, error) {
	if facility == "" {
		return forenlog.LOG_DAEMON, nil
	}

	if forenlogFacility, valid := facilities[facility]; valid {
		return forenlogFacility, nil
	}

	fInt, err := strconv.Atoi(facility)
	if err == nil && 0 <= fInt && fInt <= 23 {
		return forenlog.Priority(fInt << 3), nil
	}
	return forenlog.Priority(0), errors.New("invalid forenlog facility")
}

func parseTLSConfig(cfg map[string]string) (*tls.Config, error) {
	_, skipVerify := cfg["forenlog-tls-skip-verify"]

	opts := tlsconfig.Options{
		CAFile:             cfg["forenlog-tls-ca-cert"],
		CertFile:           cfg["forenlog-tls-cert"],
		KeyFile:            cfg["forenlog-tls-key"],
		InsecureSkipVerify: skipVerify,
	}
	return tlsconfig.Client(opts)
}

func parseLogFormat(logFormat, proto string) (forenlog.Formatter, forenlog.Framer, error) {
	switch logFormat {
	case "":
		return forenlog.UnixFormatter, forenlog.DefaultFramer, nil
	case "rfc3164":
		return forenlog.RFC3164Formatter, forenlog.DefaultFramer, nil
	case "rfc5424":
		if proto == secureProto {
			return rfc5424formatterWithAppNameAsTag, forenlog.RFC5425MessageLengthFramer, nil
		}
		return rfc5424formatterWithAppNameAsTag, forenlog.DefaultFramer, nil
	case "rfc5424micro":
		if proto == secureProto {
			return rfc5424microformatterWithAppNameAsTag, forenlog.RFC5425MessageLengthFramer, nil
		}
		return rfc5424microformatterWithAppNameAsTag, forenlog.DefaultFramer, nil
	default:
		return nil, nil, errors.New("Invalid forenlog format")
	}
}
