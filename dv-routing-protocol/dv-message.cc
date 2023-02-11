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

#include "ns3/dv-message.h"
#include "ns3/log.h"
#include <vector>

using namespace ns3;

NS_LOG_COMPONENT_DEFINE ("DVMessage");
NS_OBJECT_ENSURE_REGISTERED (DVMessage);

DVMessage::DVMessage ()
{
}

DVMessage::~DVMessage ()
{
}

DVMessage::DVMessage (DVMessage::MessageType messageType, uint32_t sequenceNumber, uint8_t ttl, Ipv4Address originatorAddress)
{
  m_messageType = messageType;
  m_sequenceNumber = sequenceNumber;
  m_ttl = ttl;
  m_originatorAddress = originatorAddress;
}

TypeId 
DVMessage::GetTypeId (void)
{
  static TypeId tid = TypeId ("DVMessage")
    .SetParent<Header> ()
    .AddConstructor<DVMessage> ()
  ;
  return tid;
}

TypeId
DVMessage::GetInstanceTypeId (void) const
{
  return GetTypeId ();
}


uint32_t
DVMessage::GetSerializedSize (void) const
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
        size += m_message.distanceVec.GetSerializedSize();
        break;
      case PATHVEC:
        size += m_message.pathVec.GetSerializedSize();
        break;
      default:
        NS_ASSERT (false);
    }
  return size;
}

void
DVMessage::Print (std::ostream &os) const
{
  os << "\n****DVMessage Dump****\n" ;
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
        m_message.distanceVec.Print(os);
        break;
      case PATHVEC:
        m_message.pathVec.Print(os);
        break;
      default:
        break;  
    }
  os << "\n****END OF MESSAGE****\n";
}

void
DVMessage::Serialize (Buffer::Iterator start) const
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
        m_message.distanceVec.Serialize(i);
        break;
      case PATHVEC:
        m_message.pathVec.Serialize(i);
        break;
      default:
        NS_ASSERT (false);   
    }
}

uint32_t 
DVMessage::Deserialize (Buffer::Iterator start)
{
  uint32_t size;
  Buffer::Iterator i = start;
  m_messageType = (MessageType) i.ReadU8 ();
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
        size += m_message.distanceVec.Deserialize(i);
        break;
      case PATHVEC:
        size += m_message.pathVec.Deserialize(i);
        break;
      default:
        NS_ASSERT (false);
    }
  return size;
}

/* PING_REQ */

uint32_t 
DVMessage::PingReq::GetSerializedSize (void) const
{
  uint32_t size;
  size = IPV4_ADDRESS_SIZE + sizeof(uint16_t) + pingMessage.length();
  return size;
}

void
DVMessage::PingReq::Print (std::ostream &os) const
{
  os << "PingReq:: Message: " << pingMessage << "\n";
}

void
DVMessage::PingReq::Serialize (Buffer::Iterator &start) const
{
  start.WriteHtonU32 (destinationAddress.Get ());
  start.WriteU16 (pingMessage.length ());
  start.Write ((uint8_t *) (const_cast<char*> (pingMessage.c_str())), pingMessage.length());
}

uint32_t
DVMessage::PingReq::Deserialize (Buffer::Iterator &start)
{  
  destinationAddress = Ipv4Address (start.ReadNtohU32 ());
  uint16_t length = start.ReadU16 ();
  char* str = (char*) malloc (length);
  start.Read ((uint8_t*)str, length);
  pingMessage = std::string (str, length);
  free (str);
  return PingReq::GetSerializedSize ();
}

void
DVMessage::SetPingReq (Ipv4Address destinationAddress, std::string pingMessage)
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

DVMessage::PingReq
DVMessage::GetPingReq ()
{
  return m_message.pingReq;
}

/* PING_RSP */

uint32_t 
DVMessage::PingRsp::GetSerializedSize (void) const
{
  uint32_t size;
  size = IPV4_ADDRESS_SIZE + sizeof(uint16_t) + pingMessage.length();
  return size;
}

void
DVMessage::PingRsp::Print (std::ostream &os) const
{
  os << "PingReq:: Message: " << pingMessage << "\n";
}

void
DVMessage::PingRsp::Serialize (Buffer::Iterator &start) const
{
  start.WriteHtonU32 (destinationAddress.Get ());
  start.WriteU16 (pingMessage.length ());
  start.Write ((uint8_t *) (const_cast<char*> (pingMessage.c_str())), pingMessage.length());
}

uint32_t
DVMessage::PingRsp::Deserialize (Buffer::Iterator &start)
{  
  destinationAddress = Ipv4Address (start.ReadNtohU32 ());
  uint16_t length = start.ReadU16 ();
  char* str = (char*) malloc (length);
  start.Read ((uint8_t*)str, length);
  pingMessage = std::string (str, length);
  free (str);
  return PingRsp::GetSerializedSize ();
}

void
DVMessage::SetPingRsp (Ipv4Address destinationAddress, std::string pingMessage)
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

DVMessage::PingRsp
DVMessage::GetPingRsp ()
{
  return m_message.pingRsp;
}


//
//
//
// TODO: You can put your own Rsp/Req related function here
/* HELLO_REQ */

uint32_t
DVMessage::HelloReq::GetSerializedSize (void) const
{
  uint32_t size;
  size = IPV4_ADDRESS_SIZE + sizeof (uint16_t) + helloMessage.length ();
  return size;
}

void
DVMessage::HelloReq::Print (std::ostream &os) const
{
  os << "HelloReq:: Message: " << helloMessage << "\n";
}

void
DVMessage::HelloReq::Serialize (Buffer::Iterator &start) const
{
  // start.WriteHtonU32 (destinationAddress.Get ());
  start.WriteU16 (helloMessage.length ());
  start.Write ((uint8_t *)(const_cast<char *> (helloMessage.c_str ())), helloMessage.length ());
}

uint32_t
DVMessage::HelloReq::Deserialize (Buffer::Iterator &start)
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
DVMessage::SetHelloReq (std::string helloMessage)
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

DVMessage::HelloReq
DVMessage::GetHelloReq ()
{
  return m_message.helloReq;
}


/* HELLO_RSP */

uint32_t
DVMessage::HelloRsp::GetSerializedSize (void) const
{
  uint32_t size;
  size = IPV4_ADDRESS_SIZE + sizeof (uint16_t) + helloMessage.length ();
  return size;
}

void
DVMessage::HelloRsp::Print (std::ostream &os) const
{
  os << "HelloReq:: Message: " << helloMessage << "\n";
}

void
DVMessage::HelloRsp::Serialize (Buffer::Iterator &start) const
{
  start.WriteHtonU32 (destinationAddress.Get ());
  start.WriteU16 (helloMessage.length ());
  start.Write ((uint8_t *)(const_cast<char *> (helloMessage.c_str ())), helloMessage.length ());
}

uint32_t
DVMessage::HelloRsp::Deserialize (Buffer::Iterator &start)
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
DVMessage::SetHelloRsp (Ipv4Address destinationAddress, std::string helloMessage)
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

DVMessage::HelloRsp
DVMessage::GetHelloRsp ()
{
  return m_message.helloRsp;
}


/* DV */

uint32_t
DVMessage::Adv::GetSerializedSize (void) const
{
  // size of dest node number, next hop node number, cost
  uint32_t size;
  size = IPV4_ADDRESS_SIZE + sizeof (uint16_t) + distances.length ();
  return size;
  // return 50;
}

void
DVMessage::Adv::Print (std::ostream &os) const
{
  // os << "DV:: dest node: " << destNodeNum << "\n" << "DV::cost" << cost << "\n" << "DV:: next hop: " << nextHopNum << "\n";
 os << "Adv:: distanceVec: " << distances << "\n";
}

void
DVMessage::Adv::Serialize (Buffer::Iterator &start) const
{
  // start.WriteHtonU32 (destinationAddress.Get ());

  start.WriteU16 (distances.length ());
  start.Write ((uint8_t *)(const_cast<char *> (distances.c_str ())), distances.length ());
  
}

uint32_t
DVMessage::Adv::Deserialize (Buffer::Iterator &start)
{
   // destinationAddress = Ipv4Address (start.ReadNtohU32 ());
  uint16_t length = start.ReadU16 ();
  char *str = (char *)malloc (length);
  start.Read ((uint8_t *)str, length);
  distances = std::string (str, length);
  free (str);
  return Adv::GetSerializedSize ();
}

void
DVMessage::SetAdv (std::string arr)
{
  if (m_messageType == 0)
    {
      m_messageType = ADV;
    }
  else
    {
      NS_ASSERT (m_messageType == ADV);
    }
  m_message.distanceVec.distances = arr;
  // std::cout << "set distance size: " << m_message.distanceVec.distances.size() << std::endl;
}

DVMessage::Adv
DVMessage::GetAdv ()
{
  // std::cout << "current distance size: " << m_message.distanceVec.distances.size() << std::endl;
  return m_message.distanceVec;
}


/* Path Vector */

uint32_t
DVMessage::PathVec::GetSerializedSize (void) const
{
  // each node is uint8_t, total string size, number of Keys, number of paths * size of (uint16_t)
  
  // uint32_t size;
  // size = sizeof (uint16_t) + paths.size() * sizeof(uint16_t) + totalSerializedSize;
  // return size;
  return 1000;
}

void
DVMessage::PathVec::Print (std::ostream &os) const
{
  // os << "DV:: dest node: " << destNodeNum << "\n" << "DV::cost" << cost << "\n" << "DV:: next hop: " << nextHopNum << "\n";
 os << "Adv:: distanceVec: " << totalSerializedSize << "\n";
}

void
DVMessage::PathVec::Serialize (Buffer::Iterator &start) const
{
  // start.WriteHtonU32 (destinationAddress.Get ());
  start.WriteU16(paths.size());
  for (uint16_t i = 0; i < paths.size(); i++) {
    start.WriteU16(paths[i].size());
    for (auto iter = paths[i].begin(); iter != paths[i].end(); iter++) {
      start.WriteU8(*iter);
    }
    // start.Write ((uint8_t *)(const_cast<char *> (paths[i].c_str ())), paths[i].length ());
  }
  // start.WriteU16 (distances.length ());
  // start.Write ((uint8_t *)(const_cast<char *> (distances.c_str ())), distances.length ());

  
}

uint32_t
DVMessage::PathVec::Deserialize (Buffer::Iterator &start)
{
  // uint16_t length = start.ReadU16 ();
  // char *str = (char *)malloc (length);
  // start.Read ((uint8_t *)str, length);
  // distances = std::string (str, length);
  // free (str);
  uint16_t pathNum = start.ReadU16();
  for (uint16_t i = 0; i < pathNum; i++) {
    std::vector<uint8_t> path;
    std::unordered_set<uint8_t> set;
    paths.push_back(path);
    pathsets.push_back(set);
    uint16_t pathsize = start.ReadU16();
    // std::cout << "pathsize in deserialized is " << pathsize << std::endl;
    for (uint16_t j = 0; j < pathsize; j++) {
      uint8_t node = start.ReadU8();
      paths[i].push_back(node);
      // std::cout << "pushed node is " << node << std::endl;
      pathsets[i].insert(node);
    }
    // uint16_t length = start.ReadU16();
    // char *str = (char *)malloc (length);
    // start.Read ((uint8_t *)str, length);
    // destNodes.push_back(node);
    // paths.push_back(std::string(str, length));
    // free(str);
  }
  
  return PathVec::GetSerializedSize ();
}

void
DVMessage::SetPathVec (std::vector<std::vector<uint8_t>> arr, uint32_t totalSize)
{
  if (m_messageType == 0)
    {
      m_messageType = PATHVEC;
    }
  else
    {
      NS_ASSERT (m_messageType == PATHVEC);
    }
  m_message.pathVec.paths = arr;
  m_message.pathVec.totalSerializedSize = totalSize;
  // std::cout << "set distance size: " << m_message.distanceVec.distances.size() << std::endl;
}

DVMessage::PathVec
DVMessage::GetPathVec ()
{
  // std::cout << "current distance size: " << m_message.distanceVec.distances.size() << std::endl;
  return m_message.pathVec;
}



void
DVMessage::SetMessageType (MessageType messageType)
{
  m_messageType = messageType;
}

DVMessage::MessageType
DVMessage::GetMessageType () const
{
  return m_messageType;
}

void
DVMessage::SetSequenceNumber (uint32_t sequenceNumber)
{
  m_sequenceNumber = sequenceNumber;
}

uint32_t 
DVMessage::GetSequenceNumber (void) const
{
  return m_sequenceNumber;
}

void
DVMessage::SetTTL (uint8_t ttl)
{
  m_ttl = ttl;
}

uint8_t 
DVMessage::GetTTL (void) const
{
  return m_ttl;
}

void
DVMessage::SetOriginatorAddress (Ipv4Address originatorAddress)
{
  m_originatorAddress = originatorAddress;
}

Ipv4Address
DVMessage::GetOriginatorAddress (void) const
{
  return m_originatorAddress;
}
