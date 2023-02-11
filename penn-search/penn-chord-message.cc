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

#include "ns3/penn-chord-message.h"
#include "ns3/log.h"

using namespace ns3;

NS_LOG_COMPONENT_DEFINE ("PennChordMessage");
NS_OBJECT_ENSURE_REGISTERED (PennChordMessage);

PennChordMessage::PennChordMessage ()
{
}

PennChordMessage::~PennChordMessage ()
{
}

PennChordMessage::PennChordMessage (PennChordMessage::MessageType messageType, uint32_t transactionId)
{
  m_messageType = messageType;
  m_transactionId = transactionId;
}

TypeId 
PennChordMessage::GetTypeId (void)
{
  static TypeId tid = TypeId ("PennChordMessage")
    .SetParent<Header> ()
    .AddConstructor<PennChordMessage> ()
  ;
  return tid;
}

TypeId
PennChordMessage::GetInstanceTypeId (void) const
{
  return GetTypeId ();
}


uint32_t
PennChordMessage::GetSerializedSize (void) const
{
  // size of messageType, transaction id
  uint32_t size = sizeof (uint8_t) + sizeof (uint32_t);
  switch (m_messageType)
    {
      case PING_REQ:
        size += m_message.pingReq.GetSerializedSize ();
        break;
      case PING_RSP:
        size += m_message.pingRsp.GetSerializedSize ();
        break;
      case JOIN_REQ:
        size += m_message.joinReq.GetSerializedSize ();
        break;
      case JOIN_RSP:
        size += m_message.joinRsp.GetSerializedSize();
        break;
      case NOTIFY:
        size += m_message.notify.GetSerializedSize();
        break;
      case STABILIZE:
        size += m_message.stabilize.GetSerializedSize();
        break;
      case STABILIZE_RSP:
        size += m_message.stabilizeRsp.GetSerializedSize();
        break;
      case RINGSTATE:
        size += m_message.ringState.GetSerializedSize();
        break;
      case LEAVE_NOTICE_SUCC:
        size += m_message.leaveNoticeSucc.GetSerializedSize();
        break;
      case LEAVE_NOTICE_PRED:
        size += m_message.leaveNoticePred.GetSerializedSize();
        break;
      case LOOKUP:
        size += m_message.lookup.GetSerializedSize();
        break;
      case LOOKUP_RSP:
        size += m_message.lookupRsp.GetSerializedSize();
        break;
      case FIXFINGER:
        size += m_message.fixFinger.GetSerializedSize();
        break;
      case FIXFINGER_RSP:
        size += m_message.fixFingerRsp.GetSerializedSize();
        break;
      default:
        NS_ASSERT (false);
    }
  return size;
}

void
PennChordMessage::Print (std::ostream &os) const
{
  os << "\n****PennChordMessage Dump****\n" ;
  os << "messageType: " << m_messageType << "\n";
  os << "transactionId: " << m_transactionId << "\n";
  os << "PAYLOAD:: \n";
  
  switch (m_messageType)
    {
      case PING_REQ:
        m_message.pingReq.Print (os);
        break;
      case PING_RSP:
        m_message.pingRsp.Print (os);
        break;
      case JOIN_REQ:
        m_message.joinReq.Print(os);
        break;
      case JOIN_RSP:
        m_message.joinRsp.Print(os);
        break;
      case NOTIFY:
        m_message.notify.Print(os);
        break;
      case STABILIZE:
        m_message.stabilize.Print(os);
        break;
      case STABILIZE_RSP:
        m_message.stabilizeRsp.Print(os);
        break;
      case RINGSTATE:
        m_message.ringState.Print(os);
        break;
      case LEAVE_NOTICE_PRED:
        m_message.leaveNoticePred.Print(os);
        break;
      case LEAVE_NOTICE_SUCC:
        m_message.leaveNoticeSucc.Print(os);
        break;
      case LOOKUP:
        m_message.lookup.Print(os);
        break;
      case LOOKUP_RSP:
        m_message.lookupRsp.Print(os);
        break;
      case FIXFINGER:
        m_message.fixFinger.Print(os);
        break;
      case FIXFINGER_RSP:
        m_message.fixFingerRsp.Print(os);
        break;
      default:
        break;  
    }
  os << "\n****END OF MESSAGE****\n";
}

void
PennChordMessage::Serialize (Buffer::Iterator start) const
{
  Buffer::Iterator i = start;
  i.WriteU8 (m_messageType);
  i.WriteHtonU32 (m_transactionId);

  switch (m_messageType)
    {
      case PING_REQ:
        m_message.pingReq.Serialize (i);
        break;
      case PING_RSP:
        m_message.pingRsp.Serialize (i);
        break;
      case JOIN_REQ:
        m_message.joinReq.Serialize (i);
        break;
      case JOIN_RSP:
        m_message.joinRsp.Serialize (i);
        break;
      case NOTIFY:
        m_message.notify.Serialize (i);
        break;
      case STABILIZE:
        m_message.stabilize.Serialize (i);
        break;
      case STABILIZE_RSP:
        m_message.stabilizeRsp.Serialize (i);
        break;
      case RINGSTATE:
        m_message.ringState.Serialize (i);
        break;
      case LEAVE_NOTICE_SUCC:
        m_message.leaveNoticeSucc.Serialize (i);
        break;
      case LEAVE_NOTICE_PRED:
        m_message.leaveNoticePred.Serialize (i);
        break;
      case LOOKUP:
        m_message.lookup.Serialize(i);
        break;
      case LOOKUP_RSP:
        m_message.lookupRsp.Serialize(i);
        break;
      case FIXFINGER:
        m_message.fixFinger.Serialize (i);
        break;
      case FIXFINGER_RSP:
        m_message.fixFingerRsp.Serialize (i);
        break;
      default:
        NS_ASSERT (false);   
    }
}

uint32_t 
PennChordMessage::Deserialize (Buffer::Iterator start)
{
  uint32_t size;
  Buffer::Iterator i = start;
  m_messageType = (MessageType) i.ReadU8 ();
  m_transactionId = i.ReadNtohU32 ();

  size = sizeof (uint8_t) + sizeof (uint32_t);

  switch (m_messageType)
    {
      case PING_REQ:
        size += m_message.pingReq.Deserialize (i);
        break;
      case PING_RSP:
        size += m_message.pingRsp.Deserialize (i);
        break;
      case JOIN_REQ:
        size += m_message.joinReq.Deserialize (i);
        break;
      case JOIN_RSP:
        size += m_message.joinRsp.Deserialize (i);
        break;
      case NOTIFY:
        size += m_message.notify.Deserialize (i);
        break;
      case STABILIZE:
        size += m_message.stabilize.Deserialize (i);
        break;
      case STABILIZE_RSP:
        size += m_message.stabilizeRsp.Deserialize (i);
        break;
      case RINGSTATE:
        size += m_message.ringState.Deserialize (i);
        break;
      case LEAVE_NOTICE_SUCC:
        size += m_message.leaveNoticeSucc.Deserialize (i);
        break;
      case LEAVE_NOTICE_PRED:
        size += m_message.leaveNoticePred.Deserialize (i);
        break;
      case LOOKUP:
        size += m_message.lookup.Deserialize (i);
        break;
      case LOOKUP_RSP:
        size += m_message.lookupRsp.Deserialize (i);
        break;
      case FIXFINGER:
        size += m_message.fixFinger.Deserialize (i);
        break;
      case FIXFINGER_RSP:
        size += m_message.fixFingerRsp.Deserialize (i);
        break;
      default:
        NS_ASSERT (false);
    }
  return size;
}

/* PING_REQ */

uint32_t 
PennChordMessage::PingReq::GetSerializedSize (void) const
{
  uint32_t size;
  size = sizeof(uint16_t) + pingMessage.length();
  return size;
}

void
PennChordMessage::PingReq::Print (std::ostream &os) const
{
  os << "PingReq:: Message: " << pingMessage << "\n";
}

void
PennChordMessage::PingReq::Serialize (Buffer::Iterator &start) const
{
  start.WriteU16 (pingMessage.length ());
  start.Write ((uint8_t *) (const_cast<char*> (pingMessage.c_str())), pingMessage.length());
}

uint32_t
PennChordMessage::PingReq::Deserialize (Buffer::Iterator &start)
{  
  uint16_t length = start.ReadU16 ();
  char* str = (char*) malloc (length);
  start.Read ((uint8_t*)str, length);
  pingMessage = std::string (str, length);
  free (str);
  return PingReq::GetSerializedSize ();
}

void
PennChordMessage::SetPingReq (std::string pingMessage)
{
  if (m_messageType == 0)
    {
      m_messageType = PING_REQ;
    }
  else
    {
      NS_ASSERT (m_messageType == PING_REQ);
    }
  m_message.pingReq.pingMessage = pingMessage;
}

PennChordMessage::PingReq
PennChordMessage::GetPingReq ()
{
  return m_message.pingReq;
}

/* PING_RSP */

uint32_t 
PennChordMessage::PingRsp::GetSerializedSize (void) const
{
  uint32_t size;
  size = sizeof(uint16_t) + pingMessage.length();
  return size;
}

void
PennChordMessage::PingRsp::Print (std::ostream &os) const
{
  os << "PingReq:: Message: " << pingMessage << "\n";
}

void
PennChordMessage::PingRsp::Serialize (Buffer::Iterator &start) const
{
  start.WriteU16 (pingMessage.length ());
  start.Write ((uint8_t *) (const_cast<char*> (pingMessage.c_str())), pingMessage.length());
}

uint32_t
PennChordMessage::PingRsp::Deserialize (Buffer::Iterator &start)
{  
  uint16_t length = start.ReadU16 ();
  char* str = (char*) malloc (length);
  start.Read ((uint8_t*)str, length);
  pingMessage = std::string (str, length);
  free (str);
  return PingRsp::GetSerializedSize ();
}

void
PennChordMessage::SetPingRsp (std::string pingMessage)
{
  if (m_messageType == 0)
    {
      m_messageType = PING_RSP;
    }
  else
    {
      NS_ASSERT (m_messageType == PING_RSP);
    }
  m_message.pingRsp.pingMessage = pingMessage;
}

PennChordMessage::PingRsp
PennChordMessage::GetPingRsp ()
{
  return m_message.pingRsp;
}


/* JOIN_REQ */

uint32_t 
PennChordMessage::JoinReq::GetSerializedSize (void) const
{
  uint32_t size;
  size = IPV4_ADDRESS_SIZE;
  return size;
}

void
PennChordMessage::JoinReq::Print (std::ostream &os) const
{
  os << "JoinReq:: From address: " << originatorAddress << "\n";
}

void
PennChordMessage::JoinReq::Serialize (Buffer::Iterator &start) const
{
  start.WriteHtonU32 (originatorAddress.Get ());
}

uint32_t
PennChordMessage::JoinReq::Deserialize (Buffer::Iterator &start)
{  
  originatorAddress = Ipv4Address (start.ReadNtohU32 ());
  return JoinReq::GetSerializedSize ();
}

void
PennChordMessage::SetJoinReq (Ipv4Address newAddress)
{
  if (m_messageType == 0)
    {
      m_messageType = JOIN_REQ;
    }
  else
    {
      NS_ASSERT (m_messageType == JOIN_REQ);
    }
  m_message.joinReq.originatorAddress = newAddress;
}

PennChordMessage::JoinReq
PennChordMessage::GetJoinReq ()
{
  return m_message.joinReq;
}


/* JOIN_RSP */

uint32_t 
PennChordMessage::JoinRsp::GetSerializedSize (void) const
{
  uint32_t size;
  size = IPV4_ADDRESS_SIZE;
  return size;
}

void
PennChordMessage::JoinRsp::Print (std::ostream &os) const
{
  os << "JoinReq:: Successor address: " << successorAddress << "\n";
}

void
PennChordMessage::JoinRsp::Serialize (Buffer::Iterator &start) const
{
  start.WriteHtonU32 (successorAddress.Get ());
}

uint32_t
PennChordMessage::JoinRsp::Deserialize (Buffer::Iterator &start)
{  
  successorAddress = Ipv4Address (start.ReadNtohU32 ());
  return JoinRsp::GetSerializedSize ();
}

void
PennChordMessage::SetJoinRsp (Ipv4Address succAddress)
{
  if (m_messageType == 0)
    {
      m_messageType = JOIN_RSP;
    }
  else
    {
      NS_ASSERT (m_messageType == JOIN_RSP);
    }
  m_message.joinRsp.successorAddress = succAddress;
}

PennChordMessage::JoinRsp
PennChordMessage::GetJoinRsp ()
{
  return m_message.joinRsp;
}


/* LEAVE_NOTICE_SUCC*/

uint32_t 
PennChordMessage::LeaveNoticeSucc::GetSerializedSize (void) const
{
  uint32_t size;
  size = IPV4_ADDRESS_SIZE + IPV4_ADDRESS_SIZE;
  return size;
}

void
PennChordMessage::LeaveNoticeSucc::Print (std::ostream &os) const
{
  os << "LeaveNoticeSucc:: Pred address: " << predAddress << "; " << "LeaveNotice:: cur address: " << curAddress << "\n";
}

void
PennChordMessage::LeaveNoticeSucc::Serialize (Buffer::Iterator &start) const
{
  start.WriteHtonU32 (predAddress.Get ());
  start.WriteHtonU32 (curAddress.Get ());
}

uint32_t
PennChordMessage::LeaveNoticeSucc::Deserialize (Buffer::Iterator &start)
{  
  predAddress = Ipv4Address (start.ReadNtohU32 ());
  curAddress = Ipv4Address (start.ReadNtohU32 ());
  return LeaveNoticeSucc::GetSerializedSize ();
}

void
PennChordMessage::SetLeaveNoticeSucc (Ipv4Address nodePredAddress, Ipv4Address nodeAddress)
{
  if (m_messageType == 0)
    {
      m_messageType = LEAVE_NOTICE_SUCC;
    }
  else
    {
      NS_ASSERT (m_messageType == LEAVE_NOTICE_SUCC);
    }
  m_message.leaveNoticeSucc.predAddress = nodePredAddress;
  m_message.leaveNoticeSucc.curAddress = nodeAddress;

}

PennChordMessage::LeaveNoticeSucc
PennChordMessage::GetLeaveNoticeSucc ()
{
  return m_message.leaveNoticeSucc;
}



/* LEAVE_NOTICE_Pred */

uint32_t 
PennChordMessage::LeaveNoticePred::GetSerializedSize (void) const
{
  uint32_t size;
  size = IPV4_ADDRESS_SIZE + IPV4_ADDRESS_SIZE;
  return size;
}

void
PennChordMessage::LeaveNoticePred::Print (std::ostream &os) const
{
  os << "LeaveNotice:: Cur address: " << curAddress << "; " << "LeaveNotice:: Succ address: " << succAddress << "\n";
}

void
PennChordMessage::LeaveNoticePred::Serialize (Buffer::Iterator &start) const
{
  start.WriteHtonU32 (curAddress.Get ());
  start.WriteHtonU32 (succAddress.Get ());
}

uint32_t
PennChordMessage::LeaveNoticePred::Deserialize (Buffer::Iterator &start)
{  
  curAddress = Ipv4Address (start.ReadNtohU32 ());
  succAddress = Ipv4Address (start.ReadNtohU32 ());
  return LeaveNoticePred::GetSerializedSize ();
}

void
PennChordMessage::SetLeaveNoticePred (Ipv4Address nodeAddress, Ipv4Address nodeSuccAddress)
{
  if (m_messageType == 0)
    {
      m_messageType = LEAVE_NOTICE_PRED;
    }
  else
    {
      NS_ASSERT (m_messageType == LEAVE_NOTICE_PRED);
    }
  m_message.leaveNoticePred.curAddress = nodeAddress;
  m_message.leaveNoticePred.succAddress = nodeSuccAddress;

}

PennChordMessage::LeaveNoticePred
PennChordMessage::GetLeaveNoticePred ()
{
  return m_message.leaveNoticePred;
}

/*NOTIFY */

uint32_t 
PennChordMessage::Notify::GetSerializedSize (void) const
{
  uint32_t size;
  size = IPV4_ADDRESS_SIZE;
  return size;
}

void
PennChordMessage::Notify::Print (std::ostream &os) const
{
  os << "Notify:: Predecessor address: " << predecessorAddress << "\n";
}

void
PennChordMessage::Notify::Serialize (Buffer::Iterator &start) const
{
  start.WriteHtonU32 (predecessorAddress.Get ());
}

uint32_t
PennChordMessage::Notify::Deserialize (Buffer::Iterator &start)
{  
  predecessorAddress = Ipv4Address (start.ReadNtohU32 ());
  return Notify::GetSerializedSize ();
}

void
PennChordMessage::SetNotify (Ipv4Address predAddress)
{
  if (m_messageType == 0)
    {
      m_messageType = NOTIFY;
    }
  else
    {
      NS_ASSERT (m_messageType == NOTIFY);
    }
  m_message.notify.predecessorAddress = predAddress;
}

PennChordMessage::Notify
PennChordMessage::GetNotify ()
{
  return m_message.notify;
}


/* STABILIZE */

uint32_t 
PennChordMessage::Stabilize::GetSerializedSize (void) const
{
  uint32_t size;
  size = IPV4_ADDRESS_SIZE;
  return size;
}

void
PennChordMessage::Stabilize::Print (std::ostream &os) const
{
  os << "Stabilize:: From address: " << curAddress << "\n";
}

void
PennChordMessage::Stabilize::Serialize (Buffer::Iterator &start) const
{
  start.WriteHtonU32 (curAddress.Get ());
}

uint32_t
PennChordMessage::Stabilize::Deserialize (Buffer::Iterator &start)
{  
  curAddress = Ipv4Address (start.ReadNtohU32 ());
  return Stabilize::GetSerializedSize ();
}

void
PennChordMessage::SetStabilize (Ipv4Address newAddress)
{
  if (m_messageType == 0)
    {
      m_messageType = STABILIZE;
    }
  else
    {
      NS_ASSERT (m_messageType == STABILIZE);
    }
  m_message.stabilize.curAddress = newAddress;
}

PennChordMessage::Stabilize
PennChordMessage::GetStabilize ()
{
  return m_message.stabilize;
}


/* STABILIZE_RSP */

uint32_t 
PennChordMessage::StabilizeRsp::GetSerializedSize (void) const
{
  uint32_t size;
  size = IPV4_ADDRESS_SIZE;
  return size;
}

void
PennChordMessage::StabilizeRsp::Print (std::ostream &os) const
{
  os << "StabilizeRsp:: From address: " << predAddress << "\n";
}

void
PennChordMessage::StabilizeRsp::Serialize (Buffer::Iterator &start) const
{
  start.WriteHtonU32 (predAddress.Get ());
}

uint32_t
PennChordMessage::StabilizeRsp::Deserialize (Buffer::Iterator &start)
{  
  predAddress = Ipv4Address (start.ReadNtohU32 ());
  return StabilizeRsp::GetSerializedSize ();
}

void
PennChordMessage::SetStabilizeRsp (Ipv4Address pAddress)
{
  if (m_messageType == 0)
    {
      m_messageType = STABILIZE_RSP;
    }
  else
    {
      NS_ASSERT (m_messageType == STABILIZE_RSP);
    }
  m_message.stabilizeRsp.predAddress = pAddress;
}

PennChordMessage::StabilizeRsp
PennChordMessage::GetStabilizeRsp ()
{
  return m_message.stabilizeRsp;
}


/* RingState */

uint32_t 
PennChordMessage::RingState::GetSerializedSize (void) const
{
  uint32_t size;
  size = IPV4_ADDRESS_SIZE;
  return size;
}

void
PennChordMessage::RingState::Print (std::ostream &os) const
{
  os << "RingState:: From address: " << originatorAddress << "\n";
}

void
PennChordMessage::RingState::Serialize (Buffer::Iterator &start) const
{
  start.WriteHtonU32 (originatorAddress.Get ());
}

uint32_t
PennChordMessage::RingState::Deserialize (Buffer::Iterator &start)
{  
  originatorAddress = Ipv4Address (start.ReadNtohU32 ());
  return RingState::GetSerializedSize ();
}

void
PennChordMessage::SetRingState (Ipv4Address newAddress)
{
  if (m_messageType == 0)
    {
      m_messageType = RINGSTATE;
    }
  else
    {
      NS_ASSERT (m_messageType == RINGSTATE);
    }
  m_message.ringState.originatorAddress = newAddress;
}

PennChordMessage::RingState
PennChordMessage::GetRingState ()
{
  return m_message.ringState;
}

/* FIXFINGER */
uint32_t 
PennChordMessage::FixFinger::GetSerializedSize (void) const
{
  uint32_t size;
  size = sizeof(uint32_t) + IPV4_ADDRESS_SIZE;
  return size;
}

void
PennChordMessage::FixFinger::Print (std::ostream &os) const
{
  os << "PublishReq:: idVal: " << number << "\n";
}

void
PennChordMessage::FixFinger::Serialize (Buffer::Iterator &start) const
{
  start.WriteHtonU32 (originatorAddress.Get ());
  start.WriteU32 (number);
}

uint32_t
PennChordMessage::FixFinger::Deserialize (Buffer::Iterator &start)
{ 
  originatorAddress = Ipv4Address (start.ReadNtohU32 ());
  number = start.ReadU32();
  return FixFinger::GetSerializedSize ();
}

void
PennChordMessage::SetFixFinger (Ipv4Address address, uint32_t idVal)
{
  if (m_messageType == 0)
    {
      m_messageType = FIXFINGER;
    }
  else
    {
      NS_ASSERT (m_messageType == FIXFINGER);
    }
  m_message.fixFinger.originatorAddress = address;
  m_message.fixFinger.number = idVal;
}

PennChordMessage::FixFinger
PennChordMessage::GetFixFinger ()
{
  return m_message.fixFinger;
}



/* FIXFINGER_RSP */
uint32_t 
PennChordMessage::FixFingerRsp::GetSerializedSize (void) const
{
  uint32_t size;
  size = IPV4_ADDRESS_SIZE;
  return size;
}

void
PennChordMessage::FixFingerRsp::Print (std::ostream &os) const
{
  os << "Fix Finger Rsp:: successor Address: " << successorAddress << "\n";
}

void
PennChordMessage::FixFingerRsp::Serialize (Buffer::Iterator &start) const
{
  start.WriteHtonU32 (successorAddress.Get ());
}

uint32_t
PennChordMessage::FixFingerRsp::Deserialize (Buffer::Iterator &start)
{ 
  successorAddress = Ipv4Address (start.ReadNtohU32 ());
  return FixFingerRsp::GetSerializedSize ();
}

void
PennChordMessage::SetFixFingerRsp (Ipv4Address address)
{
  if (m_messageType == 0)
    {
      m_messageType = FIXFINGER_RSP;
    }
  else
    {
      NS_ASSERT (m_messageType == FIXFINGER_RSP);
    }
  m_message.fixFingerRsp.successorAddress = address;
}

PennChordMessage::FixFingerRsp
PennChordMessage::GetFixFingerRsp ()
{
  return m_message.fixFingerRsp;
}



/* LOOKUP */
uint32_t 
PennChordMessage::Lookup::GetSerializedSize (void) const
{
  uint32_t size;
  size = IPV4_ADDRESS_SIZE + sizeof(uint8_t) + sizeof(uint32_t);
  return size;
}

void
PennChordMessage::Lookup::Print (std::ostream &os) const
{
  os << "Lookup:: originatorAddress: " << originatorAddress << "\n";
}

void
PennChordMessage::Lookup::Serialize (Buffer::Iterator &start) const
{
  start.WriteHtonU32 (originatorAddress.Get ());
  start.WriteU8(type);
  start.WriteHtonU32 (idVal);
}

uint32_t
PennChordMessage::Lookup::Deserialize (Buffer::Iterator &start)
{ 
  originatorAddress = Ipv4Address (start.ReadNtohU32 ());
  type = start.ReadU8 ();
  idVal = start.ReadNtohU32 ();

  return Lookup::GetSerializedSize ();
}

void
PennChordMessage::SetLookup (uint32_t hashKey, uint8_t type, Ipv4Address address)
{
  if (m_messageType == 0)
    {
      m_messageType = LOOKUP;
    }
  else
    {
      NS_ASSERT (m_messageType == LOOKUP);
    }
  m_message.lookup.originatorAddress = address;
  m_message.lookup.idVal = hashKey;
  m_message.lookup.type = type;
}

PennChordMessage::Lookup
PennChordMessage::GetLookup ()
{
  return m_message.lookup;
}


/* LOOKUP_RSP */
uint32_t 
PennChordMessage::LookupRsp::GetSerializedSize (void) const
{
  uint32_t size;
  size = IPV4_ADDRESS_SIZE + sizeof(uint8_t) + sizeof(uint32_t);
  return size;
}

void
PennChordMessage::LookupRsp::Print (std::ostream &os) const
{
  os << "Lookup:: originatorAddress: " << originatorAddress << "\n";
}

void
PennChordMessage::LookupRsp::Serialize (Buffer::Iterator &start) const
{
  start.WriteHtonU32 (originatorAddress.Get ());
  start.WriteU8 (type);
  start.WriteHtonU32 (idVal);
}

uint32_t
PennChordMessage::LookupRsp::Deserialize (Buffer::Iterator &start)
{ 
  originatorAddress = Ipv4Address (start.ReadNtohU32 ());
  type = start.ReadU8 ();
  idVal = start.ReadNtohU32 ();

  return LookupRsp::GetSerializedSize ();
}

void
PennChordMessage::SetLookupRsp (Ipv4Address address, uint8_t type, uint32_t idVal)
{
  if (m_messageType == 0)
    {
      m_messageType = LOOKUP_RSP;
    }
  else
    {
      NS_ASSERT (m_messageType == LOOKUP_RSP);
    }
  m_message.lookupRsp.originatorAddress = address;
  m_message.lookupRsp.type = type;
  m_message.lookupRsp.idVal = idVal;
}

PennChordMessage::LookupRsp
PennChordMessage::GetLookupRsp ()
{
  return m_message.lookupRsp;
}

void
PennChordMessage::SetMessageType (MessageType messageType)
{
  m_messageType = messageType;
}

PennChordMessage::MessageType
PennChordMessage::GetMessageType () const
{
  return m_messageType;
}

void
PennChordMessage::SetTransactionId (uint32_t transactionId)
{
  m_transactionId = transactionId;
}

uint32_t 
PennChordMessage::GetTransactionId (void) const
{
  return m_transactionId;
}

