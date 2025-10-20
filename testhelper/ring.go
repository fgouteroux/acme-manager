package testhelper

import (
	"flag"
	"os"

	"github.com/go-kit/log"
	"github.com/grafana/dskit/flagext"

	"github.com/fgouteroux/acme-manager/ring"
)

func GetTestRing(logger log.Logger) ring.AcmeManagerRing {
	// Create a test config
	config := ring.Config{
		InstanceID:             "test-instance",
		InstanceAddr:           "127.0.0.1",
		InstancePort:           7946,
		InstanceInterfaceNames: "",
		JoinMembers:            "",
	}

	// Initialize MemberlistKV config with defaults
	flagext.DefaultValues(&config.MemberlistKV)

	// Create a test flag set (empty since we're not parsing any flags)
	fs := flag.NewFlagSet("test", flag.ContinueOnError)

	// Register flags (even though we won't parse any)
	config.RegisterFlagsWithPrefix(fs, "")

	// Create ring with empty flag set and no prefix
	amRing, err := ring.NewWithConfig(config, logger, fs, "")
	if err != nil {
		_ = logger.Log("error", err)
		os.Exit(1)
	}
	return amRing
}
