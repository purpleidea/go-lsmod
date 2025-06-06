package lsmod

import (
	"fmt"
	"strings"
)

type modTainted uint32

// possible tainted flags of the module
const (
	TaintedNone modTainted = 0      // No tainted flag
	TaintedP    modTainted = 1      // (P): A module with a non-GPL license has been loaded, this includes modules with no license. Set by modutils >= 2.4.9 and module-init-tools.
	TaintedF    modTainted = 2      // (F): A module was force loaded by insmod -f. Set by modutils >= 2.4.9 and module-init-tools.
	TaintedS    modTainted = 4      // (S): Unsafe SMP processors: SMP with CPUs not designed for SMP.
	TaintedR    modTainted = 8      // (R): A module was forcibly unloaded from the system by rmmod -f.
	TaintedM    modTainted = 16     // (M): A hardware machine check error occurred on the system.
	TaintedB    modTainted = 32     // (B): A bad page was discovered on the system.
	TaintedU    modTainted = 64     // (U): The user has asked that the system be marked "tainted". This could be because they are running software that directly modifies the hardware, or for other reasons.
	TaintedD    modTainted = 128    // (D): The system has died.
	TaintedA    modTainted = 256    // (A): The ACPI DSDT has been overridden with one supplied by the user instead of using the one provided by the hardware.
	TaintedW    modTainted = 512    // (W): A kernel warning has occurred.
	TaintedC    modTainted = 1024   // (C): A module from drivers/staging was loaded.
	TaintedI    modTainted = 2048   // (I): The system is working around a severe firmware bug.
	TaintedO    modTainted = 4096   // (O): An out-of-tree module has been loaded.
	TaintedE    modTainted = 8192   // (E): An unsigned module has been loaded in a kernel supporting module signature.
	TaintedL    modTainted = 16384  // (L): A soft lockup has previously occurred on the system.
	TaintedK    modTainted = 32768  // (K): The kernel has been live patched.
	TaintedX    modTainted = 65536  // (X): Auxiliary taint, defined and used by for distros.
	TaintedT    modTainted = 131072 // (T): The kernel was built with the struct randomization plugin.
)

var taintFlagMap = map[string]modTainted{
	"(P)": TaintedP,
	"(F)": TaintedF,
	"(S)": TaintedS,
	"(R)": TaintedR,
	"(M)": TaintedM,
	"(B)": TaintedB,
	"(U)": TaintedU,
	"(D)": TaintedD,
	"(A)": TaintedA,
	"(W)": TaintedW,
	"(C)": TaintedC,
	"(I)": TaintedI,
	"(O)": TaintedO,
	"(E)": TaintedE,
	"(L)": TaintedL,
	"(K)": TaintedK,
	"(X)": TaintedX,
	"(T)": TaintedT,
}

var taintStringMap = map[modTainted]string{}

func init() {
	for str, val := range taintFlagMap {
		taintStringMap[val] = str
	}
}

func (t modTainted) String() string {
	if t == TaintedNone {
		return "()"
	}

	var chars []string
	for val, str := range taintStringMap {
		if t&val != 0 {
			// Extract just the letter from "(X)"
			chars = append(chars, string(str[1]))
		}
	}
	return fmt.Sprintf("(%s)", strings.Join(chars, ""))
}

func parseTainted(s string) (modTainted, error) {
	if len(s) < 2 || s[0] != '(' || s[len(s)-1] != ')' {
		return 0, fmt.Errorf("invalid format: %q", s)
	}

	var combined modTainted
	body := s[1 : len(s)-1] // extract inner characters, e.g. "OE"

	for _, c := range body {
		found := false
		for str, val := range taintFlagMap {
			if len(str) == 3 && rune(str[1]) == c { // str[1] is the flag letter inside (X)
				combined |= val
				found = true
				break
			}
		}
		if !found {
			return 0, fmt.Errorf("unknown tainted flag (%c)", c)
		}
	}

	return combined, nil
}
