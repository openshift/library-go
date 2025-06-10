package certrotation

import (
	"strconv"
	"time"
)

// durationRound formats a duration into a human-readable string.
// Unlike Go's built-in `time.Duration.String()`, which returns a string like "72h3m0s", this function returns a more concise format like "3d" or "2h30m".
// Implementation is taken from https://github.com/gomodules/sprig/blob/master/date.go#L97-L139
func durationRound(d time.Duration) string {
	u := uint64(d)
	if d < 0 {
		u = -u
	}

	var (
		year   = uint64(time.Hour) * 24 * 365
		month  = uint64(time.Hour) * 24 * 30
		day    = uint64(time.Hour) * 24
		hour   = uint64(time.Hour)
		minute = uint64(time.Minute)
		second = uint64(time.Second)
	)
	switch {
	case u > year:
		return strconv.FormatUint(u/year, 10) + "y"
	case u > month:
		return strconv.FormatUint(u/month, 10) + "mo"
	case u > day:
		return strconv.FormatUint(u/day, 10) + "d"
	case u > hour:
		return strconv.FormatUint(u/hour, 10) + "h"
	case u > minute:
		return strconv.FormatUint(u/minute, 10) + "m"
	case u > second:
		return strconv.FormatUint(u/second, 10) + "s"
	}
	return "0s"
}
