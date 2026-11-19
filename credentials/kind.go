package credentials

// Kind is the sort of caller; it sets how many tokens are kept and renewed.
type Kind int

const (
	// KindUser is an application acting for one signed-in user.
	KindUser Kind = iota
	// KindServiceAccount is an integration that proves an API key.
	KindServiceAccount
	// KindBFF is a backend acting for many users at once.
	KindBFF
	// KindAdminConsole is a console that touches many projects, mostly once.
	KindAdminConsole
)

// Limits bound the cache. A token that is not used within one renewal interval
// is not renewed; it is fetched again when it is used.
type Limits struct {
	// MaxCached is the most tokens kept; the least recently used goes first.
	MaxCached int
	// MaxProactive is the most tokens renewed in the background at a time.
	MaxProactive int
}

func (k Kind) limits() Limits {
	switch k {
	case KindServiceAccount:
		return Limits{MaxCached: 8, MaxProactive: 4}
	case KindBFF:
		return Limits{MaxCached: 2000, MaxProactive: 200}
	case KindAdminConsole:
		return Limits{MaxCached: 32, MaxProactive: 4}
	}
	return Limits{MaxCached: 16, MaxProactive: 6}
}
