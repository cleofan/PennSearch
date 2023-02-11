/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation;
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include "ns3/ls-message.h"
#include "ns3/log.h"

using namespace ns3;

NS_LOG_COMPONENT_DEFINE ("LSMessage");
NS_OBJECT_ENSURE_REGISTERED (LSMessage);

LSMessage::LSMessage () {}

LSMessage::~LSMessage () {}

LSMessage::LSMessage (LSMessage::MessageType messageType, uint32_t sequenceNumber, uint8_t ttl,
                      Ipv4Address originatorAddress)
{
  m_messageType = messageType;
  m_sequenceNumber = sequenceNumber;
  m_ttl = ttl;
  m_originatorAddress = originatorAddress;
}

TypeId
LSMessage::GetTypeId (void)
{
  static TypeId tid = TypeId ("LSMessage").SetParent<Header> ().AddConstructor<LSMessage> ();
  return tid;
}

TypeId
LSMessage::GetInstanceTypeId (void) const
{
  return GetTypeId ();
}

uint32_t
LSMessage::GetSerializedSize (void) const
{
  // size of messageType, sequence number, originator address, ttl
  uint32_t size = sizeof (uint8_t) + sizeof (uint32_t) + IPV4_ADDRESS_SIZE + sizeof (uint8_t);
  switch (m_messageType)
    {
    case PING_REQ:
      size += m_message.pingReq.GetSerializedSize ();
      break;
    case PING_RSP:
      size += m_message.pingRsp.GetSerializedSize ();
      break;
    case HELLO_REQ:
      size += m_message.helloReq.GetSerializedSize ();
      break;
    case HELLO_RSP:
      size += m_message.helloRsp.GetSerializedSize ();
      break;
    case ADV:
      size += m_message.lsp.GetSerializedSize();
      break;
    default:
      NS_ASSERT (false);
    }
  return size;
}

void
LSMessage::Print (std::ostream &os) const
{
  os << "\n****LSMessage Dump****\n";
  os << "messageType: " << m_messageType << "\n";
  os << "sequenceNumber: " << m_sequenceNumber << "\n";
  os << "ttl: " << m_ttl << "\n";
  os << "originatorAddress: " << m_originatorAddress << "\n";
  os << "PAYLOAD:: \n";

  switch (m_messageType)
    {
    case PING_REQ:
      m_message.pingReq.Print (os);
      break;
    case PING_RSP:
      m_message.pingRsp.Print (os);
      break;
    case HELLO_REQ:
      m_message.helloReq.Print(os);
      break;
    case HELLO_RSP:
      m_message.helloRsp.Print(os);
      break;
    case ADV:
      m_message.lsp.Print(os);
      break;
    default:
      break;
    }
  os << "\n****END OF MESSAGE****\n";
}

void
LSMessage::Serialize (Buffer::Iterator start) const
{
  Buffer::Iterator i = start;
  i.WriteU8 (m_messageType);
  i.WriteHtonU32 (m_sequenceNumber);
  i.WriteU8 (m_ttl);
  i.WriteHtonU32 (m_originatorAddress.Get ());

  switch (m_messageType)
    {
    case PING_REQ:
      m_message.pingReq.Serialize (i);
      break;
    case PING_RSP:
      m_message.pingRsp.Serialize (i);
      break;
    case HELLO_REQ:
      m_message.helloReq.Serialize (i);
      break;
    case HELLO_RSP:
      m_message.helloRsp.Serialize (i);
      break;
    case ADV:
      m_message.lsp.Serialize(i);
      break;
    default:
      NS_ASSERT (false);
    }
}

uint32_t
LSMessage::Deserialize (Buffer::Iterator start)
{
  uint32_t size;
  Buffer::Iterator i = start;
  m_messageType = (MessageType)i.ReadU8 ();
  m_sequenceNumber = i.ReadNtohU32 ();
  m_ttl = i.ReadU8 ();
  m_originatorAddress = Ipv4Address (i.ReadNtohU32 ());

  size = sizeof (uint8_t) + sizeof (uint32_t) + sizeof (uint8_t) + IPV4_ADDRESS_SIZE;

  switch (m_messageType)
    {
    case PING_REQ:
      size += m_message.pingReq.Deserialize (i);
      break;
    case PING_RSP:
      size += m_message.pingRsp.Deserialize (i);
      break;
    case HELLO_REQ:
      size += m_message.helloReq.Deserialize (i);
      break;
    case HELLO_RSP:
      size += m_message.helloRsp.Deserialize (i);
      break;
    case ADV:
      size += m_message.lsp.Deserialize(i);
      break;
    default:
      NS_ASSERT (false);
    }
  return size;
}

/* PING_REQ */

uint32_t
LSMessage::PingReq::GetSerializedSize (void) const
{
  uint32_t size;
  size = IPV4_ADDRESS_SIZE + sizeof (uint16_t) + pingMessage.length ();
  return size;
}

void
LSMessage::PingReq::Print (std::ostream &os) const
{
  os << "PingReq:: Message: " << pingMessage << "\n";
}

void
LSMessage::PingReq::Serialize (Buffer::Iterator &start) const
{
  start.WriteHtonU32 (destinationAddress.Get ());
  start.WriteU16 (pingMessage.length ());
  start.Write ((uint8_t *)(const_cast<char *> (pingMessage.c_str ())), pingMessage.length ());
}

uint32_t
LSMessage::PingReq::Deserialize (Buffer::Iterator &start)
{
  destinationAddress = Ipv4Address (start.ReadNtohU32 ());
  uint16_t length = start.ReadU16 ();
  char *str = (char *)malloc (length);
  start.Read ((uint8_t *)str, length);
  pingMessage = std::string (str, length);
  free (str);
  return PingReq::GetSerializedSize ();
}

void
LSMessage::SetPingReq (Ipv4Address destinationAddress, std::string pingMessage)
{
  if (m_messageType == 0)
    {
      m_messageType = PING_REQ;
    }
  else
    {
      NS_ASSERT (m_messageType == PING_REQ);
    }
  m_message.pingReq.destinationAddress = destinationAddress;
  m_message.pingReq.pingMessage = pingMessage;
}

LSMessage::PingReq
LSMessage::GetPingReq ()
{
  return m_message.pingReq;
}


/* PING_RSP */

uint32_t
LSMessage::PingRsp::GetSerializedSize (void) const
{
  uint32_t size;
  size = IPV4_ADDRESS_SIZE + sizeof (uint16_t) + pingMessage.length ();
  return size;
}

void
LSMessage::PingRsp::Print (std::ostream &os) const
{
  os << "PingReq:: Message: " << pingMessage << "\n";
}

void
LSMessage::PingRsp::Serialize (Buffer::Iterator &start) const
{
  start.WriteHtonU32 (destinationAddress.Get ());
  start.WriteU16 (pingMessage.length ());
  start.Write ((uint8_t *)(const_cast<char *> (pingMessage.c_str ())), pingMessage.length ());
}

uint32_t
LSMessage::PingRsp::Deserialize (Buffer::Iterator &start)
{
  destinationAddress = Ipv4Address (start.ReadNtohU32 ());
  uint16_t length = start.ReadU16 ();
  char *str = (char *)malloc (length);
  start.Read ((uint8_t *)str, length);
  pingMessage = std::string (str, length);
  free (str);
  return PingRsp::GetSerializedSize ();
}

void
LSMessage::SetPingRsp (Ipv4Address destinationAddress, std::string pingMessage)
{
  if (m_messageType == 0)
    {
      m_messageType = PING_RSP;
    }
  else
    {
      NS_ASSERT (m_messageType == PING_RSP);
    }
  m_message.pingRsp.destinationAddress = destinationAddress;
  m_message.pingRsp.pingMessage = pingMessage;
}

LSMessage::PingRsp
LSMessage::GetPingRsp ()
{
  return m_message.pingRsp;
}

// TODO: You can put your own Rsp/Req related function here
/* HELLO_REQ */

uint32_t
LSMessage::HelloReq::GetSerializedSize (void) const
{
  uint32_t size;
  size = IPV4_ADDRESS_SIZE + sizeof (uint16_t) + helloMessage.length ();
  return size;
}

void
LSMessage::HelloReq::Print (std::ostream &os) const
{
  os << "HelloReq:: Message: " << helloMessage << "\n";
}

void
LSMessage::HelloReq::Serialize (Buffer::Iterator &start) const
{
  // start.WriteHtonU32 (destinationAddress.Get ());
  start.WriteU16 (helloMessage.length ());
  start.Write ((uint8_t *)(const_cast<char *> (helloMessage.c_str ())), helloMessage.length ());
}

uint32_t
LSMessage::HelloReq::Deserialize (Buffer::Iterator &start)
{
  // destinationAddress = Ipv4Address (start.ReadNtohU32 ());
  uint16_t length = start.ReadU16 ();
  char *str = (char *)malloc (length);
  start.Read ((uint8_t *)str, length);
  helloMessage = std::string (str, length);
  free (str);
  return HelloReq::GetSerializedSize ();
}

void
LSMessage::SetHelloReq (std::string helloMessage)
{
  if (m_messageType == 0)
    {
      m_messageType = HELLO_REQ;
    }
  else
    {
      NS_ASSERT (m_messageType == HELLO_REQ);
    }
  m_message.helloReq.helloMessage = helloMessage;
}

LSMessage::HelloReq
LSMessage::GetHelloReq ()
{
  return m_message.helloReq;
}


/* HELLO_RSP */

uint32_t
LSMessage::HelloRsp::GetSerializedSize (void) const
{
  uint32_t size;
  size = IPV4_ADDRESS_SIZE + sizeof (uint16_t) + helloMessage.length ();
  return size;
}

void
LSMessage::HelloRsp::Print (std::ostream &os) const
{
  os << "HelloReq:: Message: " << helloMessage << "\n";
}

void
LSMessage::HelloRsp::Serialize (Buffer::Iterator &start) const
{
  start.WriteHtonU32 (destinationAddress.Get ());
  start.WriteU16 (helloMessage.length ());
  start.Write ((uint8_t *)(const_cast<char *> (helloMessage.c_str ())), helloMessage.length ());
}

uint32_t
LSMessage::HelloRsp::Deserialize (Buffer::Iterator &start)
{
  destinationAddress = Ipv4Address (start.ReadNtohU32 ());
  uint16_t length = start.ReadU16 ();
  char *str = (char *)malloc (length);
  start.Read ((uint8_t *)str, length);
  helloMessage = std::string (str, length);
  free (str);
  return HelloRsp::GetSerializedSize ();
}

void
LSMessage::SetHelloRsp (Ipv4Address destinationAddress, std::string helloMessage)
{
  if (m_messageType == 0)
    {
      m_messageType = HELLO_RSP;
    }
  else
    {
      NS_ASSERT (m_messageType == HELLO_RSP);
    }
  m_message.helloRsp.helloMessage = helloMessage;
  m_message.helloRsp.destinationAddress = destinationAddress;
}

LSMessage::HelloRsp
LSMessage::GetHelloRsp ()
{
  return m_message.helloRsp;
}

/* LSP */

uint32_t
LSMessage::Adv::GetSerializedSize (void) const
{
  // size of node num, size of string length, and the string 
  uint32_t size;
  size = sizeof(uint32_t) +  3 * sizeof (uint16_t) + neighbors.length ();
  return size;
}

void
LSMessage::Adv::Print (std::ostream &os) const
{
  // os << "DV:: dest node: " << destNodeNum << "\n" << "DV::cost" << cost << "\n" << "DV:: next hop: " << nextHopNum << "\n";
 os << "Adv:: Neighbors: " << neighbors << "\n";
}

void
LSMessage::Adv::Serialize (Buffer::Iterator &start) const
{
  // start.WriteHtonU32 (destinationAddress.Get ());
  start.WriteU32(nodeNum);
  start.WriteU16(ifAdded);
  start.WriteU16(ifRemoved);
  start.WriteU16 (neighbors.length ());
  start.Write ((uint8_t *)(const_cast<char *> (neighbors.c_str ())), neighbors.length ());
  
}

uint32_t
LSMessage::Adv::Deserialize (Buffer::Iterator &start)
{
   // destinationAddress = Ipv4Address (start.ReadNtohU32 ());
  uint32_t nodeno = start.ReadU32();
  ifAdded = start.ReadU16();
  ifRemoved = start.ReadU16();
  uint16_t length = start.ReadU16 ();
  char *str = (char *)malloc (length);
  start.Read ((uint8_t *)str, length);
  nodeNum = nodeno;
  neighbors = std::string (str, length);
  free (str);
  return Adv::GetSerializedSize ();
}

void
LSMessage::SetAdv (uint32_t nodenum, std::string arr, std::uint16_t added, std::uint16_t removed)
{
  if (m_messageType == 0)
    {
      m_messageType = ADV;
    }
  else
    {
      NS_ASSERT (m_messageType == ADV);
    }
  m_message.lsp.nodeNum = nodenum;
  m_message.lsp.neighbors = arr;
  m_message.lsp.ifAdded = added;
  m_message.lsp.ifRemoved = removed;
  // std::cout << "set distance size: " << m_message.distanceVec.distances.size() << std::endl;
}

LSMessage::Adv
LSMessage::GetAdv ()
{
  // std::cout << "current distance size: " << m_message.distanceVec.distances.size() << std::endl;
  return m_message.lsp;
}




void
LSMessage::SetMessageType (MessageType messageType)
{
  m_messageType = messageType;
}

LSMessage::MessageType
LSMessage::GetMessageType () const
{
  return m_messageType;
}

void
LSMessage::SetSequenceNumber (uint32_t sequenceNumber)
{
  m_sequenceNumber = sequenceNumber;
}

uint32_t
LSMessage::GetSequenceNumber (void) const
{
  return m_sequenceNumber;
}

void
LSMessage::SetTTL (uint8_t ttl)
{
  m_ttl = ttl;
}

uint8_t
LSMessage::GetTTL (void) const
{
  return m_ttl;
}

void
LSMessage::SetOriginatorAddress (Ipv4Address originatorAddress)
{
  m_originatorAddress = originatorAddress;
}

Ipv4Address
LSMessage::GetOriginatorAddress (void) const
{
  return m_originatorAddress;
}
