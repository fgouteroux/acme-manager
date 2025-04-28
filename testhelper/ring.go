package testhelper

import (
	"github.com/go-kit/log"
	"os"

	"github.com/fgouteroux/acme_manager/ring"
)

func GetTestRing(logger log.Logger) ring.AcmeManagerRing {
	instanceID := "test-instance"
	instanceAddr := "127.0.0.1"
	instancePort := 7946
	joinMembers := ""
	instanceInterfaceNames := ""

	amRing, err := ring.New(instanceID, instanceAddr, joinMembers, instanceInterfaceNames, instancePort, logger)
	if err != nil {
		_ = logger.Log("error", err)
		os.Exit(1)
	}
	return amRing
}
