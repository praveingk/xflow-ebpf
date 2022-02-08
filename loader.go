/*
 A Custom loader to load the XDP Flow program
 Borrowed from Palani, Sayandeep from Axon project
*/
package main

import (
	"fmt"
	"os"

	"github.com/cilium/ebpf"
	"github.com/urfave/cli/v2"
	"github.com/vishvananda/netlink"
)

func unload(ifaceName string) error {
	link, err := netlink.LinkByName(ifaceName)
	if err != nil {
		return err
	}
	if err = netlink.LinkSetXdpFd(link, -1); err != nil {
		return fmt.Errorf("netlink.LinkSetXdpFd(link, -1) failed: %v", err)
	}
	err = netlink.LinkDel(link)
	if err != nil {
		return err
	}
	return nil
}

func isXdpAttached(link netlink.Link) bool {
	if link.Attrs() != nil && link.Attrs().Xdp != nil && link.Attrs().Xdp.Attached {
		return true
	}
	return false
}

func pinMap(m *ebpf.Map, path string) error {
	if err := m.Pin(path); err != nil {
		m.Close()
		fmt.Printf("[pinMap] Error! pin map: %s\n", err)
		return err
	}
	return nil
}

func closeMap(m *ebpf.Map) error {
	m.Unpin()
	return m.Close()
}

func removeFile(path string) {
	e := os.Remove(path)
	if e != nil {
		fmt.Printf("[removeFile] Err: %v\n", e)
	}

}

const (
	pinPath     = "/sys/fs/bpf/xflow"
	progObjPath = "src/xflow.o"
)

type flags struct {
	op    string
	iface string
}

var (
	cliFlags flags
)

func main() {
	app := cli.NewApp()

	app = &cli.App{
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:        "operation",
				Value:       "",
				Usage:       "operation (load,unload)",
				Destination: &cliFlags.op,
			},
			&cli.StringFlag{
				Name:        "iface",
				Value:       "",
				Usage:       "name of interace",
				Destination: &cliFlags.iface,
			},
		},
	}
	app.Run(os.Args)
	fmt.Printf("op: %s iface: %s\n", cliFlags.op, cliFlags.iface)
	iface := cliFlags.iface

	spec, err := ebpf.LoadCollectionSpec(progObjPath)
	if err != nil {
		panic(err)
	}

	var objs struct {
		XCProg *ebpf.Program `ebpf:"xflow"`
		XCMap  *ebpf.Map     `ebpf:"xflow_map"`
	}
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		panic(err)
	}
	defer objs.XCProg.Close()
	defer objs.XCMap.Close()

	if cliFlags.op == "unload" {
		removeFile(pinPath)
		err = unload(iface)
		if err != nil {
			panic(err)
		}
	} else if cliFlags.op == "load" {
		pinMap(objs.XCMap, pinPath)
		link, err := netlink.LinkByName(iface)
		err = netlink.LinkSetXdpFdWithFlags(link, objs.XCProg.FD(), 2)
		if err != nil {
			panic(err)
		}
	}

}
