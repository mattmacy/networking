package vpc_test

import (
	"bytes"
	"net"

	"github.com/pkg/errors"
)

type _InterfaceMap map[string]net.Interface

// testGetAllInterfaces returns a set of interfaces.
func testGetAllInterfaces() (_InterfaceMap, error) {
	ifacesRaw, err := net.Interfaces()
	if err != nil {
		return nil, errors.Wrap(err, "unable to get all interfaces")
	}

	m := make(_InterfaceMap, len(ifacesRaw))
	for _, ifaceRaw := range ifacesRaw {
		ifaceRaw := ifaceRaw
		m[ifaceRaw.Name] = ifaceRaw
	}

	return m, nil
}

func (im _InterfaceMap) Difference(newIM _InterfaceMap) (onlyOrig, onlyNew, both _InterfaceMap) {
	type iface struct {
		iface net.Interface

		//   'b' == both
		//   'o' == original
		//   'n' == new
		state byte
	}

	mergedList := make(map[string]*iface, len(im))
	for _, origIface := range im {
		origIface := origIface
		mergedList[origIface.Name] = &iface{iface: origIface, state: 'o'}
	}

	for _, newIface := range newIM {
		//k := s.Key()
		newIface := newIface
		_, found := mergedList[newIface.Name]
		if found {
			mergedList[newIface.Name].state = 'b'
		} else {
			mergedList[newIface.Name] = &iface{iface: newIface, state: 'n'}
		}
	}

	onlyOrig = make(_InterfaceMap, len(mergedList))
	onlyNew = make(_InterfaceMap, len(mergedList))
	both = make(_InterfaceMap, len(mergedList))
	for k, v := range mergedList {
		switch v.state {
		case 'b':
			both[k] = v.iface
		case 'o':
			onlyOrig[k] = v.iface
		case 'n':
			onlyNew[k] = v.iface
		default:
			panic("unknown merge list state")
		}
	}

	return onlyOrig, onlyNew, both
}

func (im _InterfaceMap) FindMAC(mac net.HardwareAddr) (net.Interface, error) {
	for _, v := range im {
		if bytes.Compare(v.HardwareAddr[:], mac[:]) == 0 {
			return v, nil
		}
	}

	return net.Interface{}, errors.Errorf("unable to find MAC %q", mac)
}

func (im _InterfaceMap) First() net.Interface {
	switch len(im) {
	case 0:
		panic("First on empty list")
	case 1:
		for _, v := range im {
			return v
		}
	}

	panic("First on a list with more than 1 element")
}
