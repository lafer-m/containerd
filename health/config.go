package health

type Config struct {
	Enable       bool     `toml:"enable"`        // turn health check on or off
	TickDuration string   `toml:"tick_duration"` // support 1ms 1s 1m 1h etc.
	TIMEOUT      string   `toml:"timeout"`       // health check timeout.
	Exclude      []string `toml:"exclude"`       // exclude health check for some service
	EchoServer   string   `toml:"echo_server"`   // echo_server ip port
	MaxRetry     int      `toml:"max_retry"`     // max retry times to change state when health check failed, default 1;
	RejectAction string   `toml:"reject_action"` // reject action in
}
