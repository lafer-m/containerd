package netpolicy

const (
	maxPort = 1<<16 - 1
)

type Config struct {
	TickDuration int `toml:"tick_duration"` // per seconds

}
