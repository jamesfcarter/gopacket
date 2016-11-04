// Copyright 2012 Google, Inc. All rights reserved.
// Copyright 2009-2011 Andreas Krennmair. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	"errors"
	"fmt"

	"github.com/jamesfcarter/gopacket"
)

// EnumMetadata keeps track of a set of metadata for each enumeration value
// for protocol enumerations.
type EnumMetadata struct {
	// DecodeWith is the decoder to use to decode this protocol's data.
	DecodeWith gopacket.Decoder
	// Name is the name of the enumeration value.
	Name string
	// LayerType is the layer type implied by the given enum.
	LayerType gopacket.LayerType
}

// errorFunc returns a decoder that spits out a specific error message.
func errorFunc(msg string) gopacket.Decoder {
	var e = errors.New(msg)
	return gopacket.DecodeFunc(func([]byte, gopacket.PacketBuilder) error {
		return e
	})
}

// EthernetType is an enumeration of ethernet type values, and acts as a decoder
// for any type it supports.
type EthernetType uint16

const (
	// EthernetTypeLLC is not an actual ethernet type.  It is instead a
	// placeholder we use in Ethernet frames that use the 802.3 standard of
	// srcmac|dstmac|length|LLC instead of srcmac|dstmac|ethertype.
	EthernetTypeLLC                         EthernetType = 0
	EthernetTypeIPv4                        EthernetType = 0x0800
	EthernetTypeARP                         EthernetType = 0x0806
	EthernetTypeIPv6                        EthernetType = 0x86DD
	EthernetTypeCiscoDiscovery              EthernetType = 0x2000
	EthernetTypeNortelDiscovery             EthernetType = 0x01a2
	EthernetTypeTransparentEthernetBridging EthernetType = 0x6558
	EthernetTypeDot1Q                       EthernetType = 0x8100
	EthernetTypePPPoEDiscovery              EthernetType = 0x8863
	EthernetTypePPPoESession                EthernetType = 0x8864
	EthernetTypeMPLSUnicast                 EthernetType = 0x8847
	EthernetTypeMPLSMulticast               EthernetType = 0x8848
	EthernetTypeEAPOL                       EthernetType = 0x888e
	EthernetTypeQinQ                        EthernetType = 0x88a8
	EthernetTypeLinkLayerDiscovery          EthernetType = 0x88cc
	EthernetTypeEthernetCTP                 EthernetType = 0x9000
)

// IPProtocol is an enumeration of IP protocol values, and acts as a decoder
// for any type it supports.
type IPProtocol uint8

const (
	IPProtocolIPv6HopByHop    IPProtocol = 0
	IPProtocolICMPv4          IPProtocol = 1
	IPProtocolIGMP            IPProtocol = 2
	IPProtocolIPv4            IPProtocol = 4
	IPProtocolTCP             IPProtocol = 6
	IPProtocolUDP             IPProtocol = 17
	IPProtocolRUDP            IPProtocol = 27
	IPProtocolIPv6            IPProtocol = 41
	IPProtocolIPv6Routing     IPProtocol = 43
	IPProtocolIPv6Fragment    IPProtocol = 44
	IPProtocolGRE             IPProtocol = 47
	IPProtocolESP             IPProtocol = 50
	IPProtocolAH              IPProtocol = 51
	IPProtocolICMPv6          IPProtocol = 58
	IPProtocolNoNextHeader    IPProtocol = 59
	IPProtocolIPv6Destination IPProtocol = 60
	IPProtocolIPIP            IPProtocol = 94
	IPProtocolEtherIP         IPProtocol = 97
	IPProtocolVRRP            IPProtocol = 112
	IPProtocolSCTP            IPProtocol = 132
	IPProtocolUDPLite         IPProtocol = 136
	IPProtocolMPLSInIP        IPProtocol = 137
)

// LinkType is an enumeration of link types, and acts as a decoder for any
// link type it supports.
type LinkType uint8

const (
	// According to pcap-linktype(7) and http://www.tcpdump.org/linktypes.html
	LinkTypeNull           LinkType = 0
	LinkTypeEthernet       LinkType = 1
	LinkTypeTokenRing      LinkType = 6
	LinkTypeArcNet         LinkType = 7
	LinkTypeSLIP           LinkType = 8
	LinkTypePPP            LinkType = 9
	LinkTypeFDDI           LinkType = 10
	LinkTypeATM_RFC1483    LinkType = 100
	LinkTypeRaw            LinkType = 101
	LinkTypePPP_HDLC       LinkType = 50
	LinkTypePPPEthernet    LinkType = 51
	LinkTypeC_HDLC         LinkType = 104
	LinkTypeIEEE802_11     LinkType = 105
	LinkTypeFRelay         LinkType = 107
	LinkTypeLoop           LinkType = 108
	LinkTypeLinuxSLL       LinkType = 113
	LinkTypeLTalk          LinkType = 104
	LinkTypePFLog          LinkType = 117
	LinkTypePrismHeader    LinkType = 119
	LinkTypeIPOverFC       LinkType = 122
	LinkTypeSunATM         LinkType = 123
	LinkTypeIEEE80211Radio LinkType = 127
	LinkTypeARCNetLinux    LinkType = 129
	LinkTypeLinuxIRDA      LinkType = 144
	LinkTypeLinuxLAPD      LinkType = 177
	LinkTypeLinuxUSB       LinkType = 220
	LinkTypeIPv4           LinkType = 228
	LinkTypeIPv6           LinkType = 229
)

// PPPoECode is the PPPoE code enum, taken from http://tools.ietf.org/html/rfc2516
type PPPoECode uint8

const (
	PPPoECodePADI    PPPoECode = 0x09
	PPPoECodePADO    PPPoECode = 0x07
	PPPoECodePADR    PPPoECode = 0x19
	PPPoECodePADS    PPPoECode = 0x65
	PPPoECodePADT    PPPoECode = 0xA7
	PPPoECodeSession PPPoECode = 0x00
)

// PPPType is an enumeration of PPP type values, and acts as a decoder for any
// type it supports.
type PPPType uint16

const (
	PPPTypeIPv4          PPPType = 0x0021
	PPPTypeIPv6          PPPType = 0x0057
	PPPTypeMPLSUnicast   PPPType = 0x0281
	PPPTypeMPLSMulticast PPPType = 0x0283
)

// SCTPChunkType is an enumeration of chunk types inside SCTP packets.
type SCTPChunkType uint8

const (
	SCTPChunkTypeData             SCTPChunkType = 0
	SCTPChunkTypeInit             SCTPChunkType = 1
	SCTPChunkTypeInitAck          SCTPChunkType = 2
	SCTPChunkTypeSack             SCTPChunkType = 3
	SCTPChunkTypeHeartbeat        SCTPChunkType = 4
	SCTPChunkTypeHeartbeatAck     SCTPChunkType = 5
	SCTPChunkTypeAbort            SCTPChunkType = 6
	SCTPChunkTypeShutdown         SCTPChunkType = 7
	SCTPChunkTypeShutdownAck      SCTPChunkType = 8
	SCTPChunkTypeError            SCTPChunkType = 9
	SCTPChunkTypeCookieEcho       SCTPChunkType = 10
	SCTPChunkTypeCookieAck        SCTPChunkType = 11
	SCTPChunkTypeShutdownComplete SCTPChunkType = 14
)

// FDDIFrameControl is an enumeration of FDDI frame control bytes.
type FDDIFrameControl uint8

const (
	FDDIFrameControlLLC FDDIFrameControl = 0x50
)

// EAPOLType is an enumeration of EAPOL packet types.
type EAPOLType uint8

const (
	EAPOLTypeEAP      EAPOLType = 0
	EAPOLTypeStart    EAPOLType = 1
	EAPOLTypeLogOff   EAPOLType = 2
	EAPOLTypeKey      EAPOLType = 3
	EAPOLTypeASFAlert EAPOLType = 4
)

// ProtocolFamily is the set of values defined as PF_* in sys/socket.h
type ProtocolFamily uint8

const (
	ProtocolFamilyIPv4 ProtocolFamily = 2
	// BSDs use different values for INET6... glory be.  These values taken from
	// tcpdump 4.3.0.
	ProtocolFamilyIPv6BSD     ProtocolFamily = 24
	ProtocolFamilyIPv6FreeBSD ProtocolFamily = 28
	ProtocolFamilyIPv6Darwin  ProtocolFamily = 30
	ProtocolFamilyIPv6Linux   ProtocolFamily = 10
)

// Dot11Type is a combination of IEEE 802.11 frame's Type and Subtype fields.
// By combining these two fields together into a single type, we're able to
// provide a String function that correctly displays the subtype given the
// top-level type.
//
// If you just care about the top-level type, use the MainType function.
type Dot11Type uint8

// MainType strips the subtype information from the given type,
// returning just the overarching type (Mgmt, Ctrl, Data, Reserved).
func (d Dot11Type) MainType() Dot11Type {
	return d & dot11TypeMask
}

const (
	Dot11TypeMgmt     Dot11Type = 0x00
	Dot11TypeCtrl     Dot11Type = 0x01
	Dot11TypeData     Dot11Type = 0x02
	Dot11TypeReserved Dot11Type = 0x03
	dot11TypeMask               = 0x03

	// The following are type/subtype conglomerations.

	// Management
	Dot11TypeMgmtAssociationReq    Dot11Type = 0x00
	Dot11TypeMgmtAssociationResp   Dot11Type = 0x04
	Dot11TypeMgmtReassociationReq  Dot11Type = 0x08
	Dot11TypeMgmtReassociationResp Dot11Type = 0x0c
	Dot11TypeMgmtProbeReq          Dot11Type = 0x10
	Dot11TypeMgmtProbeResp         Dot11Type = 0x14
	Dot11TypeMgmtMeasurementPilot  Dot11Type = 0x18
	Dot11TypeMgmtBeacon            Dot11Type = 0x20
	Dot11TypeMgmtATIM              Dot11Type = 0x24
	Dot11TypeMgmtDisassociation    Dot11Type = 0x28
	Dot11TypeMgmtAuthentication    Dot11Type = 0x2c
	Dot11TypeMgmtDeauthentication  Dot11Type = 0x30
	Dot11TypeMgmtAction            Dot11Type = 0x34
	Dot11TypeMgmtActionNoAck       Dot11Type = 0x38

	// Control
	Dot11TypeCtrlWrapper       Dot11Type = 0x1d
	Dot11TypeCtrlBlockAckReq   Dot11Type = 0x21
	Dot11TypeCtrlBlockAck      Dot11Type = 0x25
	Dot11TypeCtrlPowersavePoll Dot11Type = 0x29
	Dot11TypeCtrlRTS           Dot11Type = 0x2d
	Dot11TypeCtrlCTS           Dot11Type = 0x31
	Dot11TypeCtrlAck           Dot11Type = 0x35
	Dot11TypeCtrlCFEnd         Dot11Type = 0x39
	Dot11TypeCtrlCFEndAck      Dot11Type = 0x3d

	// Data
	Dot11TypeDataCFAck              Dot11Type = 0x06
	Dot11TypeDataCFPoll             Dot11Type = 0x0a
	Dot11TypeDataCFAckPoll          Dot11Type = 0x0e
	Dot11TypeDataNull               Dot11Type = 0x12
	Dot11TypeDataCFAckNoData        Dot11Type = 0x16
	Dot11TypeDataCFPollNoData       Dot11Type = 0x1a
	Dot11TypeDataCFAckPollNoData    Dot11Type = 0x1e
	Dot11TypeDataQOSData            Dot11Type = 0x22
	Dot11TypeDataQOSDataCFAck       Dot11Type = 0x26
	Dot11TypeDataQOSDataCFPoll      Dot11Type = 0x2a
	Dot11TypeDataQOSDataCFAckPoll   Dot11Type = 0x2e
	Dot11TypeDataQOSNull            Dot11Type = 0x32
	Dot11TypeDataQOSCFPollNoData    Dot11Type = 0x3a
	Dot11TypeDataQOSCFAckPollNoData Dot11Type = 0x3e
)

var (
	// Each of the following arrays contains mappings of how to handle enum
	// values for various enum types in gopacket/layers.
	//
	// So, EthernetTypeMetadata[2] contains information on how to handle EthernetType
	// 2, including which name to give it and which decoder to use to decode
	// packet data of that type.  These arrays are filled by default with all of the
	// protocols gopacket/layers knows how to handle, but users of the library can
	// add new decoders or override existing ones.  For example, if you write a better
	// TCP decoder, you can override IPProtocolMetadata[IPProtocolTCP].DecodeWith
	// with your new decoder, and all gopacket/layers decoding will use your new
	// decoder whenever they encounter that IPProtocol.
	EthernetTypeMetadata     EnumMetadata
	IPProtocolMetadata       EnumMetadata
	SCTPChunkTypeMetadata    EnumMetadata
	PPPTypeMetadata          EnumMetadata
	PPPoECodeMetadata        EnumMetadata
	LinkTypeMetadata         EnumMetadata
	FDDIFrameControlMetadata EnumMetadata
	EAPOLTypeMetadata        EnumMetadata
	ProtocolFamilyMetadata   EnumMetadata
	Dot11TypeMetadata        EnumMetadata
	USBTypeMetadata          EnumMetadata
)

func (a EthernetType) Decode(data []byte, p gopacket.PacketBuilder) error {
	return EthernetTypeMetadata.DecodeWith.Decode(data, p)
}
func (a EthernetType) String() string {
	return EthernetTypeMetadata.Name
}
func (a EthernetType) LayerType() gopacket.LayerType {
	return EthernetTypeMetadata.LayerType
}
func (a IPProtocol) Decode(data []byte, p gopacket.PacketBuilder) error {
	return IPProtocolMetadata.DecodeWith.Decode(data, p)
}
func (a IPProtocol) String() string {
	return IPProtocolMetadata.Name
}
func (a IPProtocol) LayerType() gopacket.LayerType {
	return IPProtocolMetadata.LayerType
}
func (a SCTPChunkType) Decode(data []byte, p gopacket.PacketBuilder) error {
	return SCTPChunkTypeMetadata.DecodeWith.Decode(data, p)
}
func (a SCTPChunkType) String() string {
	return SCTPChunkTypeMetadata.Name
}
func (a PPPType) Decode(data []byte, p gopacket.PacketBuilder) error {
	return PPPTypeMetadata.DecodeWith.Decode(data, p)
}
func (a PPPType) String() string {
	return PPPTypeMetadata.Name
}
func (a LinkType) Decode(data []byte, p gopacket.PacketBuilder) error {
	return LinkTypeMetadata.DecodeWith.Decode(data, p)
}
func (a LinkType) String() string {
	return LinkTypeMetadata.Name
}
func (a PPPoECode) Decode(data []byte, p gopacket.PacketBuilder) error {
	return PPPoECodeMetadata.DecodeWith.Decode(data, p)
}
func (a PPPoECode) String() string {
	return PPPoECodeMetadata.Name
}
func (a FDDIFrameControl) Decode(data []byte, p gopacket.PacketBuilder) error {
	return FDDIFrameControlMetadata.DecodeWith.Decode(data, p)
}
func (a FDDIFrameControl) String() string {
	return FDDIFrameControlMetadata.Name
}
func (a EAPOLType) Decode(data []byte, p gopacket.PacketBuilder) error {
	return EAPOLTypeMetadata.DecodeWith.Decode(data, p)
}
func (a EAPOLType) String() string {
	return EAPOLTypeMetadata.Name
}
func (a EAPOLType) LayerType() gopacket.LayerType {
	return EAPOLTypeMetadata.LayerType
}
func (a ProtocolFamily) Decode(data []byte, p gopacket.PacketBuilder) error {
	return ProtocolFamilyMetadata.DecodeWith.Decode(data, p)
}
func (a ProtocolFamily) String() string {
	return ProtocolFamilyMetadata.Name
}
func (a ProtocolFamily) LayerType() gopacket.LayerType {
	return ProtocolFamilyMetadata.LayerType
}
func (a Dot11Type) Decode(data []byte, p gopacket.PacketBuilder) error {
	return Dot11TypeMetadata.DecodeWith.Decode(data, p)
}
func (a Dot11Type) String() string {
	return Dot11TypeMetadata.Name
}
func (a Dot11Type) LayerType() gopacket.LayerType {
	return Dot11TypeMetadata.LayerType
}

// Decode a raw v4 or v6 IP packet.
func decodeIPv4or6(data []byte, p gopacket.PacketBuilder) error {
	version := data[0] >> 4
	switch version {
	case 4:
		return decodeIPv4(data, p)
	case 6:
		return decodeIPv6(data, p)
	}
	return fmt.Errorf("Invalid IP packet version %v", version)
}

func init() {
	// Here we link up all enumerations with their respective names and decoders.
	EthernetTypeMetadata = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeIPv4), Name: "IPv4", LayerType: LayerTypeIPv4}
	IPProtocolMetadata = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeUDP), Name: "UDP", LayerType: LayerTypeUDP}

}
