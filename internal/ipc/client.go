//go:build windows

package ipc

import (
	"bufio"
	"encoding/json"
	"fmt"
	"time"

	"github.com/Microsoft/go-winio"
)

// Call dials the pipe, sends one request, and returns the response.
func Call(pipeName string, req Request, timeout time.Duration) (Response, error) {
	conn, err := winio.DialPipe(pipeName, &timeout)
	if err != nil {
		return Response{}, fmt.Errorf("dial pipe: %w", err)
	}
	defer conn.Close()
	b, err := json.Marshal(req)
	if err != nil {
		return Response{}, err
	}
	if _, err := conn.Write(append(b, '\n')); err != nil {
		return Response{}, fmt.Errorf("write request: %w", err)
	}
	line, err := bufio.NewReader(conn).ReadBytes('\n')
	if err != nil && len(line) == 0 {
		return Response{}, fmt.Errorf("read response: %w", err)
	}
	var resp Response
	if err := json.Unmarshal(line, &resp); err != nil {
		return Response{}, fmt.Errorf("decode response: %w", err)
	}
	return resp, nil
}
