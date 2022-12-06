// Code generated by bpf2go; DO NOT EDIT.
//go:build 386 || amd64
// +build 386 amd64

package enricher

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
)

type socketsmapSocketsKey struct {
	Netns uint64
	Proto uint16
	Port  uint16
	_     [4]byte
}

type socketsmapSocketsValue struct {
	Mntns uint64
	Pid   uint32
	Task  [16]int8
	_     [4]byte
}

// loadSocketsmap returns the embedded CollectionSpec for socketsmap.
func loadSocketsmap() (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(_SocketsmapBytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load socketsmap: %w", err)
	}

	return spec, err
}

// loadSocketsmapObjects loads socketsmap and converts it into a struct.
//
// The following types are suitable as obj argument:
//
//	*socketsmapObjects
//	*socketsmapPrograms
//	*socketsmapMaps
//
// See ebpf.CollectionSpec.LoadAndAssign documentation for details.
func loadSocketsmapObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := loadSocketsmap()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

// socketsmapSpecs contains maps and programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type socketsmapSpecs struct {
	socketsmapProgramSpecs
	socketsmapMapSpecs
}

// socketsmapSpecs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type socketsmapProgramSpecs struct {
	IgBindIpv4E *ebpf.ProgramSpec `ebpf:"ig_bind_ipv4_e"`
	IgBindIpv4X *ebpf.ProgramSpec `ebpf:"ig_bind_ipv4_x"`
	IgBindIpv6E *ebpf.ProgramSpec `ebpf:"ig_bind_ipv6_e"`
	IgBindIpv6X *ebpf.ProgramSpec `ebpf:"ig_bind_ipv6_x"`
}

// socketsmapMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type socketsmapMapSpecs struct {
	Sockets *ebpf.MapSpec `ebpf:"sockets"`
	Start   *ebpf.MapSpec `ebpf:"start"`
}

// socketsmapObjects contains all objects after they have been loaded into the kernel.
//
// It can be passed to loadSocketsmapObjects or ebpf.CollectionSpec.LoadAndAssign.
type socketsmapObjects struct {
	socketsmapPrograms
	socketsmapMaps
}

func (o *socketsmapObjects) Close() error {
	return _SocketsmapClose(
		&o.socketsmapPrograms,
		&o.socketsmapMaps,
	)
}

// socketsmapMaps contains all maps after they have been loaded into the kernel.
//
// It can be passed to loadSocketsmapObjects or ebpf.CollectionSpec.LoadAndAssign.
type socketsmapMaps struct {
	Sockets *ebpf.Map `ebpf:"sockets"`
	Start   *ebpf.Map `ebpf:"start"`
}

func (m *socketsmapMaps) Close() error {
	return _SocketsmapClose(
		m.Sockets,
		m.Start,
	)
}

// socketsmapPrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to loadSocketsmapObjects or ebpf.CollectionSpec.LoadAndAssign.
type socketsmapPrograms struct {
	IgBindIpv4E *ebpf.Program `ebpf:"ig_bind_ipv4_e"`
	IgBindIpv4X *ebpf.Program `ebpf:"ig_bind_ipv4_x"`
	IgBindIpv6E *ebpf.Program `ebpf:"ig_bind_ipv6_e"`
	IgBindIpv6X *ebpf.Program `ebpf:"ig_bind_ipv6_x"`
}

func (p *socketsmapPrograms) Close() error {
	return _SocketsmapClose(
		p.IgBindIpv4E,
		p.IgBindIpv4X,
		p.IgBindIpv6E,
		p.IgBindIpv6X,
	)
}

func _SocketsmapClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Do not access this directly.
//
//go:embed socketsmap_bpfel_x86.o
var _SocketsmapBytes []byte
