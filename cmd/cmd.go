package cmd

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"

	"github.com/fgouteroux/acme_manager/config"
)

func Execute(logger log.Logger, globalConfig config.Config) {
	if globalConfig.Common.CmdEnabled {
		cmdArr := strings.Split(globalConfig.Common.CmdRun, " ")
		cmdPath := cmdArr[0]
		cmdArgs := cmdArr[1:]

		out, err := run(cmdPath, cmdArgs, globalConfig.Common.CmdTimeout)
		if err != nil {
			level.Error(logger).Log("msg", out, "err", err) // #nosec G104
		} else {
			level.Info(logger).Log("msg", fmt.Sprintf("Command '%s %s' successfully executed", cmdPath, strings.Join(cmdArgs, " "))) // #nosec G104
		}
	}
}

func run(cmdPath string, cmdArgs []string, cmdTimeout int) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(cmdTimeout)*time.Second)
	defer cancel()

	var out bytes.Buffer

	cmd := exec.CommandContext(ctx, cmdPath, cmdArgs...)
	cmd.Stdout = &out

	return out.String(), cmd.Run()
}
