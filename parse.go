package lsmod

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/pkg/errors"
)

const (
	// ProcModules is a path to pseudo-file to parse
	ProcModules = "/proc/modules"

	minFieldsPerLine = 6
	maxFieldsPerLine = 7
	noDeps           = "-"
	delimDeps        = ","
)

func parse(fileName string) (map[string]ModInfo, error) {
	file, err := os.Open(fileName) // nolint: gosec
	if err != nil {
		return nil, errors.Wrapf(err, "Error opening %q", fileName)
	}
	defer file.Close() // nolint: errcheck

	mods := make(map[string]ModInfo)

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()

		fields := strings.Fields(line)
		if len(fields) < minFieldsPerLine || len(fields) > maxFieldsPerLine {
			return nil, fmt.Errorf("invalid input line %q", line)
		}

		info, err := parseInfo(fields) // nolint: govet
		if err != nil {
			return nil, errors.Wrapf(err, "error parsing %q", ProcModules)
		}

		mods[fields[0]] = info
	}

	err = scanner.Err()
	if err != nil {
		return nil, errors.Wrapf(err, "Error reading %q", ProcModules)
	}

	return mods, nil
}

func parseInfo(fields []string) (info ModInfo, err error) {
	info.Mem, err = parseUint(fields[1])
	if err != nil {
		return info, errors.Wrap(err, "invalid mem (field 2)")
	}

	info.Instances, err = parseUint(fields[2])
	if err != nil {
		return info, errors.Wrap(err, "invalid instances (field 3)")
	}

	info.Depends = splitDeps(fields[3])

	info.State, err = parseState(fields[4])
	if err != nil {
		return info, errors.Wrap(err, "unknown state (field 5)")
	}

	info.Offset, err = parseUint(fields[5])
	if err != nil {
		return info, errors.Wrap(err, "invalid offset (field 6)")
	}

	if len(fields) == maxFieldsPerLine {
		info.Tainted, err = parseTainted(fields[6])
		if err != nil {
			return info, errors.Wrap(err, "unknown tainted (field 7)")
		}
	}

	return info, nil
}

func splitDeps(line string) []string {
	if line == noDeps {
		return nil
	}

	return strings.Split(strings.TrimRight(line, delimDeps), delimDeps)
}

func parseUint(line string) (uint64, error) {
	if strings.HasPrefix(line, "0x") {
		return strconv.ParseUint(line[2:], 16, 64)
	}

	return strconv.ParseUint(line, 10, 64)
}
