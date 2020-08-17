// +build linux_bpf

package bytecode

import (
	"fmt"
	"os"
	"path"

	"github.com/DataDog/datadog-agent/pkg/util/log"
	"github.com/DataDog/ebpf/manager"
	gore "github.com/lebauce/go-re"
)

// Options consolidates all configuration params associated to the eBPF byte code management
type Options struct {
	BPFDir               string
	Debug                bool
	EnableIPv6           bool
	OffsetGuessThreshold uint64
}

// GetNetworkTracerELF obtains the eBPF bytecode used by the Network Tracer.
// First, it attempts to compile the eBPF bytecode on the fly, using the host kernel
// headers and the bundled compiler.  If this process fail for some reason
// (eg. system headers not available), we fall back to the pre-compiled ELF file
// that relies on offset guessing.
func GetNetworkTracerELF(opts Options) (AssetReader, []manager.ConstantEditor, error) {
	compiler := gore.NewEBPFCompiler(false)
	defer compiler.Close()

	var (
		in  = path.Join(opts.BPFDir, "pkg/ebpf/c/tracer-ebpf.c")
		out = path.Join(os.TempDir(), "tracer-ebpf.o")
	)

	err := compiler.CompileToObjectFile(in, out, []string{"RUNTIME_COMPILATION=1"})
	if err != nil {
		log.Errorf("failed to compile eBPF bytecode: %s. falling back to pre-compiled bytecode.", err)
		return getPrecompiledELF(opts)
	}

	f, err := os.Open(out)
	return f, nil, err
}

func getPrecompiledELF(opts Options) (AssetReader, []manager.ConstantEditor, error) {
	constants, err := GuessOffsets(opts)
	if err != nil {
		return nil, nil, fmt.Errorf("could not obtain offsets: %s", err)
	}

	elf, err := ReadBPFModule(opts.BPFDir, opts.Debug)
	if err != nil {
		return nil, nil, fmt.Errorf("could not read bpf module: %s", err)
	}

	return elf, constants, nil
}
