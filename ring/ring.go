package ring

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/grafana/dskit/dns"
	"github.com/grafana/dskit/flagext"
	"github.com/grafana/dskit/kv"
	"github.com/grafana/dskit/kv/codec"
	"github.com/grafana/dskit/kv/memberlist"
	"github.com/grafana/dskit/ring"
	"github.com/grafana/dskit/services"
	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/fgouteroux/acme-manager/models"
)

const (
	// ringKey is the key under which we store the acme-manager's ring in the KVStore.
	ringKey = "acme-manager"

	// ringNumTokens is how many tokens each acme-manager should have in the
	// ring. acme-manager uses tokens to establish a ring leader, therefore
	// only one token is needed.
	ringNumTokens = 1

	// ringAutoForgetUnhealthyPeriods is how many consecutive timeout periods an
	// unhealthy instance in the ring will be automatically removed after.
	ringAutoForgetUnhealthyPeriods = 3

	heartbeatPeriod  = 15 * time.Second
	heartbeatTimeout = 30 * time.Second

	// leaderToken is the special token that makes the owner the ring leader.
	leaderToken = 0
)

// ringOp is used as an instance state filter when obtaining instances from the
// ring. Instances in the LEAVING state are included to help minimise the number
// of leader changes during rollout and scaling operations. These instances will
// be forgotten after ringAutoForgetUnhealthyPeriods (see
// `KeepInstanceInTheRingOnShutdown`).
var ringOp = ring.NewOp([]ring.InstanceState{ring.ACTIVE, ring.LEAVING}, nil)

type AcmeManagerRing struct {
	Client            *ring.Ring
	Lifecycler        *ring.BasicLifecycler
	Memberlistsvc     *memberlist.KVInitService
	KvStore           *memberlist.KV
	CertificateClient *memberlist.Client
	TokenClient       *memberlist.Client
	ChallengeClient   *memberlist.Client
	RateLimitClient   *memberlist.Client
}

// Config holds all ring-related configuration
type Config struct {
	// Memberlist configuration
	MemberlistKV memberlist.KVConfig

	// Instance configuration (not covered by memberlist config)
	InstanceID             string
	InstanceAddr           string
	InstancePort           int
	InstanceInterfaceNames string
	JoinMembers            string

	// Ring lifecycler configuration
	KeepInstanceInTheRingOnShutdown bool
	HeartbeatPeriod                 time.Duration
	HeartbeatTimeout                time.Duration
}

// RegisterFlagsWithPrefix registers all ring flags with the given prefix
func (cfg *Config) RegisterFlagsWithPrefix(fs *flag.FlagSet, prefix string) {
	// Register memberlist KV configuration flags
	cfg.MemberlistKV.RegisterFlagsWithPrefix(fs, prefix)

	// Register instance-specific flags that aren't part of memberlist config
	fs.StringVar(&cfg.InstanceID, prefix+"instance-id", "", "Instance ID to register in the ring.")
	fs.StringVar(&cfg.InstanceAddr, prefix+"instance-addr", "", "IP address to advertise in the ring. Default is auto-detected.")
	fs.IntVar(&cfg.InstancePort, prefix+"instance-port", 7946, "Port to advertise in the ring.")
	fs.StringVar(&cfg.InstanceInterfaceNames, prefix+"instance-interface-names", "", "List of network interface names to look up when finding the instance IP address.")
	fs.StringVar(&cfg.JoinMembers, prefix+"join-members", "", "Other cluster members to join. Comma-separated list of addresses.")

	// Register ring lifecycler flags
	fs.BoolVar(&cfg.KeepInstanceInTheRingOnShutdown, prefix+"keep-instance-in-ring-on-shutdown", true, "Keep the instance in the ring when shutting down. If false, instance will be removed from ring immediately.")
	fs.DurationVar(&cfg.HeartbeatPeriod, prefix+"heartbeat-period", 15*time.Second, "Period at which to heartbeat to the ring.")
	fs.DurationVar(&cfg.HeartbeatTimeout, prefix+"heartbeat-timeout", 30*time.Second, "The heartbeat timeout after which instances are assumed unhealthy.")
}

// Helper function to check if specific flags were set
func checkSetFlags(fs *flag.FlagSet, prefix string) map[string]bool {
	setFlags := make(map[string]bool)

	fs.Visit(func(f *flag.Flag) {
		switch f.Name {
		case prefix + "memberlist.packet-dial-timeout":
			setFlags["PacketDialTimeout"] = true
		case prefix + "memberlist.packet-write-timeout":
			setFlags["PacketWriteTimeout"] = true
		case prefix + "memberlist.max-concurrent-writes":
			setFlags["MaxConcurrentWrites"] = true
		case prefix + "memberlist.acquire-writer-timeout":
			setFlags["AcquireWriterTimeout"] = true
		}
	})

	return setFlags
}

// NewWithConfig creates a new AcmeManagerRing using the Config struct
func NewWithConfig(ringConfig Config, logger log.Logger, flagSet *flag.FlagSet, flagPrefix string) (AcmeManagerRing, error) {
	var config AcmeManagerRing
	ctx := context.Background()

	joinMembersSlice := make([]string, 0)
	if ringConfig.JoinMembers != "" {
		joinMembersSlice = strings.Split(ringConfig.JoinMembers, ",")
	}

	instanceInterfaceNamesSlice := make([]string, 0)
	if ringConfig.InstanceInterfaceNames != "" {
		instanceInterfaceNamesSlice = strings.Split(ringConfig.InstanceInterfaceNames, ",")
	}

	instanceID := ringConfig.InstanceID
	if instanceID == "" {
		var err error
		instanceID, err = os.Hostname()
		if err != nil {
			_ = level.Error(logger).Log("msg", "failed to get hostname", "err", err)
			os.Exit(1)
		}
	}

	reg := prometheus.DefaultRegisterer
	reg = prometheus.WrapRegistererWithPrefix("acme_manager_", reg)

	// Use the structured configuration instead of hardcoded values
	memberlistsvc := NewMemberlistKVWithConfig(ringConfig, instanceID, joinMembersSlice, logger, reg, flagSet, flagPrefix)
	if err := services.StartAndAwaitRunning(ctx, memberlistsvc); err != nil {
		return config, err
	}

	store, err := memberlistsvc.GetMemberlistKV()
	if err != nil {
		return config, err
	}

	ringClient, err := memberlist.NewClient(store, ring.GetCodec())
	if err != nil {
		return config, err
	}

	certificateClient, err := memberlist.NewClient(store, models.GetCertificateCodec())
	if err != nil {
		return config, err
	}

	tokenClient, err := memberlist.NewClient(store, models.GetTokenCodec())
	if err != nil {
		return config, err
	}

	challengeClient, err := memberlist.NewClient(store, models.GetChallengeCodec())
	if err != nil {
		return config, err
	}

	rateLimitClient, err := memberlist.NewClient(store, models.GetRateLimitCodec())
	if err != nil {
		return config, err
	}

	lfc, err := SimpleRingLifecyclerWithConfig(ringClient, ringConfig, instanceID, instanceInterfaceNamesSlice, logger, reg)
	if err != nil {
		return config, err
	}

	// start lifecycler service
	if err := services.StartAndAwaitRunning(ctx, lfc); err != nil {
		return config, err
	}

	ringsvc, err := SimpleRing(ringClient, logger, reg)
	if err != nil {
		return config, err
	}
	// start the ring service
	if err := services.StartAndAwaitRunning(ctx, ringsvc); err != nil {
		return config, err
	}

	return AcmeManagerRing{
		Client:            ringsvc,
		Lifecycler:        lfc,
		Memberlistsvc:     memberlistsvc,
		KvStore:           store,
		CertificateClient: certificateClient,
		TokenClient:       tokenClient,
		ChallengeClient:   challengeClient,
		RateLimitClient:   rateLimitClient,
	}, nil
}

// NewMemberlistKVWithConfig creates memberlist KV using the structured config
func NewMemberlistKVWithConfig(ringConfig Config, instanceID string, joinMembers []string, logger log.Logger, reg prometheus.Registerer, flagSet *flag.FlagSet, flagPrefix string) *memberlist.KVInitService {
	// Start with the provided configuration (which includes all the flags that were set)
	config := ringConfig.MemberlistKV

	// Check which TCP transport flags were explicitly set
	setFlags := checkSetFlags(flagSet, flagPrefix)

	// These defaults perform better but may cause long-running packets to be dropped in high-latency networks.
	// Only apply these defaults if they haven't been explicitly set via command line flags
	if !setFlags["PacketDialTimeout"] {
		config.TCPTransport.PacketDialTimeout = 500 * time.Millisecond
	}
	if !setFlags["PacketWriteTimeout"] {
		config.TCPTransport.PacketWriteTimeout = 500 * time.Millisecond
	}
	if !setFlags["MaxConcurrentWrites"] {
		config.TCPTransport.MaxConcurrentWrites = 5
	}
	if !setFlags["AcquireWriterTimeout"] {
		config.TCPTransport.AcquireWriterTimeout = 1 * time.Second
	}

	// Codecs is used to tell memberlist library how to serialize/de-serialize the messages between peers.
	// `ring.GetCode()` uses default, which is protobuf.
	config.Codecs = []codec.Codec{ring.GetCodec(), models.GetCertificateCodec(), models.GetTokenCodec(), models.GetChallengeCodec(), models.GetRateLimitCodec()}

	// TCPTransport defines what addr and port this particular peer should listen for.
	// These may have been set via flags, but ensure they're set
	if config.TCPTransport.BindPort == 0 {
		config.TCPTransport.BindPort = ringConfig.InstancePort
	}
	if len(config.TCPTransport.BindAddrs) == 0 && ringConfig.InstanceAddr != "" {
		config.TCPTransport.BindAddrs = []string{ringConfig.InstanceAddr}
	}
	if len(config.TCPTransport.BindAddrs) == 0 {
		config.TCPTransport.BindAddrs = []string{"127.0.0.1"}
	}

	// joinMembers is the address of peer who is already in the memberlist group.
	if len(joinMembers) > 0 {
		config.JoinMembers = joinMembers
		// Set sensible defaults if not configured via flags
		if config.MinJoinBackoff == 0 {
			config.MinJoinBackoff = 1 * time.Second
		}
		if config.MaxJoinBackoff == 0 {
			config.MaxJoinBackoff = 1 * time.Minute
		}
		if config.MaxJoinRetries == 0 {
			config.MaxJoinRetries = 10
		}
	}

	// resolver defines how each peers IP address should be resolved.
	resolver := dns.NewProvider(log.With(logger, "component", "dns"), reg, dns.GolangResolverType)

	// Set remaining defaults if not configured via flags
	if config.NodeName == "" {
		config.NodeName = instanceID
	}
	if config.StreamTimeout == 0 {
		config.StreamTimeout = 10 * time.Second
	}
	if config.GossipToTheDeadTime == 0 {
		config.GossipToTheDeadTime = 30 * time.Second
	}

	return memberlist.NewKVInitService(
		&config,
		log.With(logger, "component", "memberlist"),
		resolver,
		reg,
	)
}

// Keep the original New function for backward compatibility
func New(instanceID, instanceAddr, joinMembers, instanceInterfaceNames string, instancePort int, logger log.Logger, flagSet *flag.FlagSet, flagPrefix string) (AcmeManagerRing, error) {
	// Convert old parameters to new config structure
	config := Config{
		InstanceID:             instanceID,
		InstanceAddr:           instanceAddr,
		InstancePort:           instancePort,
		InstanceInterfaceNames: instanceInterfaceNames,
		JoinMembers:            joinMembers,
	}

	// Initialize MemberlistKV config with defaults
	flagext.DefaultValues(&config.MemberlistKV)

	return NewWithConfig(config, logger, flagSet, flagPrefix)
}

// SimpleRing returns an instance of `ring.Ring` as a service. Starting and Stopping the service is upto the caller.
func SimpleRing(store kv.Client, logger log.Logger, reg prometheus.Registerer) (*ring.Ring, error) {
	var config ring.Config
	flagext.DefaultValues(&config)
	config.ReplicationFactor = 1
	config.SubringCacheDisabled = true

	return ring.NewWithStoreClientAndStrategy(
		config,
		ringKey,           // ring name
		"collectors/ring", // prefix key where peers are stored
		store,
		ring.NewDefaultReplicationStrategy(),
		reg,
		log.With(logger, "component", "ring"),
	)
}

// SimpleRingLifecyclerWithConfig returns an instance lifecycler using the Config values
func SimpleRingLifecyclerWithConfig(store kv.Client, ringConfig Config, instanceID string, instanceInterfaceNames []string, logger log.Logger, reg prometheus.Registerer) (*ring.BasicLifecycler, error) {
	var config ring.BasicLifecyclerConfig
	instanceAddr, err := ring.GetInstanceAddr(ringConfig.InstanceAddr, instanceInterfaceNames, logger, false)
	if err != nil {
		return nil, err
	}

	config.ID = instanceID
	config.Addr = fmt.Sprintf("%s:%d", instanceAddr, ringConfig.InstancePort)

	config.HeartbeatPeriod = ringConfig.HeartbeatPeriod
	if config.HeartbeatPeriod == 0 {
		config.HeartbeatPeriod = heartbeatPeriod // fallback to default
	}

	config.HeartbeatTimeout = ringConfig.HeartbeatTimeout
	if config.HeartbeatTimeout == 0 {
		config.HeartbeatTimeout = heartbeatTimeout // fallback to default
	}

	config.TokensObservePeriod = 0
	config.NumTokens = ringNumTokens
	config.KeepInstanceInTheRingOnShutdown = ringConfig.KeepInstanceInTheRingOnShutdown

	var delegate ring.BasicLifecyclerDelegate

	delegate = ring.NewInstanceRegisterDelegate(ring.ACTIVE, config.NumTokens)
	delegate = ring.NewLeaveOnStoppingDelegate(delegate, logger)
	delegate = ring.NewAutoForgetDelegate(ringAutoForgetUnhealthyPeriods*config.HeartbeatPeriod, delegate, logger)

	return ring.NewBasicLifecycler(
		config,
		ringKey,
		"collectors/ring",
		store,
		delegate,
		log.With(logger, "component", "lifecycler"),
		reg,
	)
}

// IsLeader checks whether this instance is the leader replica
func IsLeader(amRing AcmeManagerRing) (bool, error) {
	// Get the leader from the ring and check whether it's this replica.
	rl, err := ringLeader(amRing.Client)
	if err != nil {
		return false, err
	}

	return rl.Addr == amRing.Lifecycler.GetInstanceAddr(), nil
}

// ringLeader returns the ring member that owns the special token.
func ringLeader(r ring.ReadRing) (*ring.InstanceDesc, error) {
	rs, err := r.Get(leaderToken, ringOp, nil, nil, nil)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to get a healthy instance for token %d", leaderToken)
	}
	if len(rs.Instances) != 1 {
		return nil, fmt.Errorf("got %d instances for token %d (but expected 1)", len(rs.Instances), leaderToken)
	}

	return &rs.Instances[0], nil
}

func GetLeader(amRing AcmeManagerRing) (string, error) {
	// Get the leader from the ring and check whether it's this replica.
	rl, err := ringLeader(amRing.Client)
	if err != nil {
		return "", err
	}
	return rl.Id, nil
}

func GetLeaderIP(amRing AcmeManagerRing) (string, error) {
	// Get the leader from the ring and check whether it's this replica.
	rl, err := ringLeader(amRing.Client)
	if err != nil {
		return "", err
	}
	return strings.Split(rl.Addr, ":")[0], nil
}
