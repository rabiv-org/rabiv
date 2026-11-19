// Package tetragon normalizes bounded native JSON export records. The producer
// remains an independent privileged service; this adapter installs no policies.
package tetragon

import (
	"encoding/json"
	"errors"
	"net/netip"
	"time"

	"github.com/rabiv-org/rabiv/internal/app/correlate"
	"github.com/rabiv-org/rabiv/internal/domain/build"
	"github.com/rabiv-org/rabiv/internal/platform/jsoninput"
)

var ErrRecord = errors.New("malformed or unsupported Tetragon record")

type process struct {
	ExecID string `json:"exec_id"`
	PID    uint32 `json:"pid"`
	Binary string `json:"binary"`
	Docker string `json:"docker"`
}
type event struct {
	Process  process `json:"process"`
	Parent   process `json:"parent"`
	Function string  `json:"function_name"`
	Args     []struct {
		File *struct {
			Path string `json:"path"`
		} `json:"file_arg"`
		Int  *int64 `json:"int_arg"`
		Sock *struct {
			Address  string `json:"daddr"`
			Port     uint16 `json:"dport"`
			Protocol string `json:"protocol"`
		} `json:"sock_arg"`
	} `json:"args"`
}

// Normalize supports process_exec/exit and the explicit security_file_permission
// MAY_WRITE / tcp_connect profile. Argument type/order are checked, not a made-up
// wire index. Unsupported event kinds remain explicit, without policy conclusions.
func Normalize(data []byte, maxRecord int64) (correlate.Event, error) {
	var zero correlate.Event
	if maxRecord <= 0 || int64(len(data)) > maxRecord {
		return zero, ErrRecord
	}
	var raw map[string]json.RawMessage
	if jsoninput.Decode(data, &raw, false) != nil {
		return zero, ErrRecord
	}
	var at time.Time
	if json.Unmarshal(raw["time"], &at) != nil || build.ValidateTime(at) != nil {
		return zero, ErrRecord
	}
	result := correlate.Event{At: at, Source: "TETRAGON", Kind: correlate.Unsupported}
	selected := ""
	for _, k := range []string{"process_exec", "process_exit", "process_kprobe"} {
		if v, ok := raw[k]; ok && string(v) != "null" {
			if selected != "" {
				return zero, ErrRecord
			}
			selected = k
		}
	}
	if selected == "" {
		return result, nil
	}
	var e event
	if json.Unmarshal(raw[selected], &e) != nil {
		return zero, ErrRecord
	}
	result.ContainerID = e.Process.Docker
	result.ExecID = e.Process.ExecID
	result.ParentExecID = e.Parent.ExecID
	result.PID = e.Process.PID
	result.Binary = e.Process.Binary
	if result.ContainerID != "" && (build.ObservedContainerID{Runtime: "DOCKER", Value: result.ContainerID}).Validate() != nil {
		return zero, ErrRecord
	}
	switch selected {
	case "process_exec":
		result.Kind = correlate.ProcessExec
	case "process_exit":
		result.Kind = correlate.ProcessExit
	case "process_kprobe":
		switch e.Function {
		case "security_file_permission":
			if len(e.Args) != 2 || e.Args[0].File == nil || e.Args[1].Int == nil || *e.Args[1].Int < 0 || *e.Args[1].Int > 1<<32-1 {
				return zero, ErrRecord
			}
			if *e.Args[1].Int&2 == 0 {
				return result, nil
			}
			result.Kind = correlate.FileWriteIntent
			result.FilePath = e.Args[0].File.Path
			result.WriteMask = uint32(*e.Args[1].Int)
		case "tcp_connect":
			if len(e.Args) != 1 || e.Args[0].Sock == nil || e.Args[0].Sock.Protocol != "IPPROTO_TCP" {
				return zero, ErrRecord
			}
			addr, err := netip.ParseAddr(e.Args[0].Sock.Address)
			if err != nil || e.Args[0].Sock.Port == 0 {
				return zero, ErrRecord
			}
			result.Kind = correlate.TCPConnect
			result.DestinationAddress = addr.String()
			result.DestinationPort = e.Args[0].Sock.Port
		}
	}
	if result.ExecID == "" || len(result.ExecID) > 1024 {
		return zero, ErrRecord
	}
	return result, nil
}
