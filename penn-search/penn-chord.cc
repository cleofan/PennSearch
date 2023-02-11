/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2010 University of Pennsylvania
 *
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


#include "penn-chord.h"

#include "ns3/inet-socket-address.h"
#include "ns3/random-variable-stream.h"
#include <openssl/sha.h>
#include <vector>

using namespace ns3;

TypeId
PennChord::GetTypeId ()
{

  static TypeId tid
      = TypeId ("PennChord")
            .SetParent<PennApplication> ()
            .AddConstructor<PennChord> ()
            .AddAttribute ("AppPort", "Listening port for Application", UintegerValue (10001),
                           MakeUintegerAccessor (&PennChord::m_appPort), MakeUintegerChecker<uint16_t> ())
            .AddAttribute ("PingTimeout", "Timeout value for PING_REQ in milliseconds", TimeValue (MilliSeconds (2000)),
                           MakeTimeAccessor (&PennChord::m_pingTimeout), MakeTimeChecker ())
            .AddAttribute ("stabilizeTimeout", "Timeout value for stabilize in milliseconds", TimeValue (MilliSeconds (6000)),
                           MakeTimeAccessor (&PennChord::m_stabilizeTimeout), MakeTimeChecker ())
            .AddAttribute ("fixFingerTimeout", "Timeout value for fixfinger in milliseconds", TimeValue (MilliSeconds (2000)),
                           MakeTimeAccessor (&PennChord::m_fixFingerTimeout), MakeTimeChecker ())
            

                           
  ;
  return tid;
}

PennChord::PennChord ()
    : m_auditPingsTimer (Timer::CANCEL_ON_DESTROY), m_stabilizeTimer(Timer::CANCEL_ON_DESTROY), m_fixFingerTimer(Timer::CANCEL_ON_DESTROY)
{
  Ptr<UniformRandomVariable> m_uniformRandomVariable = CreateObject<UniformRandomVariable> ();
  m_currentTransactionId = m_uniformRandomVariable->GetValue (0x00000000, 0xFFFFFFFF);
}

PennChord::~PennChord ()
{

}

void
PennChord::DoDispose ()
{
  StopApplication ();
  PennApplication::DoDispose ();
}


void
PennChord::StartApplication (void)
{
  std::cout << "PennChord::StartApplication()!!!!!" << std::endl;
  if (m_socket == 0)
    { 
      TypeId tid = TypeId::LookupByName ("ns3::UdpSocketFactory");
      m_socket = Socket::CreateSocket (GetNode (), tid);
      InetSocketAddress local = InetSocketAddress (Ipv4Address::GetAny(), m_appPort);
      m_socket->Bind (local);
      m_socket->SetRecvCallback (MakeCallback (&PennChord::RecvMessage, this));
      // std::cout << "reset m_socekt to not null, now is " << m_socket << std::endl;
    }  
  m_successorAddress = Ipv4Address::GetAny();
  m_predecessorAddress = Ipv4Address::GetAny();
  m_address = GetLocalAddress();
  m_node = ReverseLookup (m_address);
  m_value = PennKeyHelper::CreateShaKey(m_address);
  m_next = 0;
  // Configure timers
  m_auditPingsTimer.SetFunction (&PennChord::AuditPings, this);
  // Start timers
  m_auditPingsTimer.Schedule (m_pingTimeout);
  
  m_stabilizeTimer.SetFunction(&PennChord::Stabilize, this);
  m_stabilizeTimer.Schedule(m_stabilizeTimeout);

  m_fixFingerTimer.SetFunction(&PennChord::FixFingers, this);
  m_fixFingerTimer.Schedule(m_fixFingerTimeout);


  InitializeFingerTable();

}

void
PennChord::StopApplication (void)
{
  // Close socket
  if (m_socket)
    {
      m_socket->Close ();
      m_socket->SetRecvCallback (MakeNullCallback<void, Ptr<Socket> > ());
      m_socket = 0;
    }

  // Cancel timers
  m_auditPingsTimer.Cancel ();

  m_pingTracker.clear ();

  m_stabilizeTimer.Cancel ();

  m_fixFingerTimer.Cancel ();
}

void
PennChord::ProcessCommand (std::vector<std::string> tokens)
{
  std::vector<std::string>::iterator iterator = tokens.begin();
  std::string command = *iterator;
  // std::cout << command << std::endl;
  if (command == "PING")
  {
    if (tokens.size() < 3)
    {
      ERROR_LOG("Insufficient PING params...");
      return;
    }
    iterator++;
    std::string destNodeNumber = *iterator;
    iterator++;
    std::string pingMessage = *iterator;
    Ipv4Address destAddress = ResolveNodeIpAddress(destNodeNumber);

    SendPing(destAddress, pingMessage);
    
  }

 
  else if (command == "JOIN") {
    
    iterator++;
    std::string nodeNumber = (*iterator);
    Ipv4Address local = GetLocalAddress();
    std::string curNodeNum = ReverseLookup (local);
    if (curNodeNum == nodeNumber) {
      CreateChord();
    }
    else {
      JoinChord(nodeNumber);
    }
      }
  else if (command == "RINGSTATE") {
    SendRingState(GetLocalAddress());
  }
    
  

}

void
PennChord::InitializeFingerTable() {
    // InitializeFingerTable();
  for (uint8_t i = 0; i < 32; i++) {
    m_fingerTable.push_back(m_address);
  }

}

void
PennChord::SendPing (Ipv4Address destAddress, std::string pingMessage)
{
  
  if (destAddress != Ipv4Address::GetAny ())
    {
      uint32_t transactionId = GetNextTransactionId ();
      CHORD_LOG ("Sending PING_REQ to Node: " << ReverseLookup(destAddress) << " IP: " << destAddress << " Message: " << pingMessage << " transactionId: " << transactionId);
      Ptr<PingRequest> pingRequest = Create<PingRequest> (transactionId, Simulator::Now(), destAddress, pingMessage);
      // Add to ping-tracker
      m_pingTracker.insert (std::make_pair (transactionId, pingRequest));
      Ptr<Packet> packet = Create<Packet> ();
      PennChordMessage message = PennChordMessage (PennChordMessage::PING_REQ, transactionId);
      message.SetPingReq (pingMessage);
      packet->AddHeader (message);
      m_socket->SendTo (packet, 0 , InetSocketAddress (destAddress, m_appPort));
      
    }
  else
    {
      // Report failure   
      m_pingFailureFn (destAddress, pingMessage);
    }
}

void
PennChord::RecvMessage (Ptr<Socket> socket)
{
  Address sourceAddr;
  Ptr<Packet> packet = socket->RecvFrom (sourceAddr);
  InetSocketAddress inetSocketAddr = InetSocketAddress::ConvertFrom (sourceAddr);
  Ipv4Address sourceAddress = inetSocketAddr.GetIpv4 ();
  uint16_t sourcePort = inetSocketAddr.GetPort ();
  PennChordMessage message;
  packet->RemoveHeader (message);

  switch (message.GetMessageType ())
    {
      case PennChordMessage::PING_REQ:
        ProcessPingReq (message, sourceAddress, sourcePort);
        break;
      case PennChordMessage::PING_RSP:
        ProcessPingRsp (message, sourceAddress, sourcePort);
        break;
      case PennChordMessage::JOIN_REQ:
        ProcessJoinReq (message);
        break;
      case PennChordMessage::JOIN_RSP:
        ProcessJoinRsp (message);
        break;
      case PennChordMessage::NOTIFY:
        ProcessNotify (message);
        break;
      case PennChordMessage::STABILIZE:
        ProcessStabilize (message, sourceAddress, sourcePort);
        break;
      case PennChordMessage::STABILIZE_RSP:
        ProcessStabilizeRsp (message);
        break;
      case PennChordMessage::LEAVE_NOTICE_SUCC:
        ProcessLeaveNoticeSucc (message);
        break;
      case PennChordMessage::LEAVE_NOTICE_PRED:
        ProcessLeaveNoticePred (message);
        break;
      case PennChordMessage::RINGSTATE:
        ProcessRingState (message);
        break;
      case PennChordMessage::LOOKUP:
        ProcessLookup (message);
        break;
      case PennChordMessage::LOOKUP_RSP:
        ProcessLookupRsp(message, sourceAddress, sourcePort);
        break;
      case PennChordMessage::FIXFINGER:
        ProcessFixFinger (message);
        break;
      case PennChordMessage::FIXFINGER_RSP:
        ProcessFixFingerRsp (message);
        break;
      default:
        ERROR_LOG ("Unknown Message Type!");
        break;
    }
}

void
PennChord::ProcessPingReq (PennChordMessage message, Ipv4Address sourceAddress, uint16_t sourcePort)
{

    // Use reverse lookup for ease of debug
    std::string fromNode = ReverseLookup (sourceAddress);
    CHORD_LOG ("Received PING_REQ, From Node: " << fromNode << ", Message: " << message.GetPingReq().pingMessage);
    // Send Ping Response
    PennChordMessage resp = PennChordMessage (PennChordMessage::PING_RSP, message.GetTransactionId());
    resp.SetPingRsp (message.GetPingReq().pingMessage);
    Ptr<Packet> packet = Create<Packet> ();
    packet->AddHeader (resp);
    m_socket->SendTo (packet, 0 , InetSocketAddress (sourceAddress, sourcePort));
    // Send indication to application layer
    m_pingRecvFn (sourceAddress, message.GetPingReq().pingMessage);
}

void
PennChord::ProcessPingRsp (PennChordMessage message, Ipv4Address sourceAddress, uint16_t sourcePort)
{
  // Remove from pingTracker
  std::map<uint32_t, Ptr<PingRequest> >::iterator iter;
  iter = m_pingTracker.find (message.GetTransactionId ());
  if (iter != m_pingTracker.end ())
    {
      std::string fromNode = ReverseLookup (sourceAddress);
      CHORD_LOG ("Received PING_RSP, From Node: " << fromNode << ", Message: " << message.GetPingRsp().pingMessage);
      m_pingTracker.erase (iter);
      // Send indication to application layer
      m_pingSuccessFn (sourceAddress, message.GetPingRsp().pingMessage);
    }
  else
    {
      DEBUG_LOG ("Received invalid PING_RSP!");
    }
}

void
PennChord::ProcessJoinReq (PennChordMessage message)
{ 
  // std::cout << "join request" << std::endl;
  Ipv4Address newAddress =  message.GetJoinReq().originatorAddress;
  //check if on another side of ring
  uint32_t succVal = PennKeyHelper::CreateShaKey(m_successorAddress);
  uint32_t curVal = PennKeyHelper::CreateShaKey(GetLocalAddress());
  uint32_t newVal = PennKeyHelper::CreateShaKey(newAddress);
  if (succVal < curVal) {
    if (newVal > curVal || newVal < succVal) {
      RspJoinReq (newAddress, message);
    }
    else if (newVal < curVal && newVal >=  succVal) {
      ForwardJoinReq (message);
    }
  }
  else if (succVal == curVal) {
    RspJoinReq (newAddress, message);
  }
  else {
    if (newVal <= succVal && newVal > curVal) {
      RspJoinReq (newAddress, message);
    }
    else {
      ForwardJoinReq (message);
    }
  }
}

void
PennChord::ForwardJoinReq (PennChordMessage message) {
  Ptr<Packet> packet = Create<Packet> ();
  packet->AddHeader (message);
  // std::cout << "join request2" << std::endl;
  m_socket->SendTo (packet, 0 , InetSocketAddress (m_successorAddress, m_appPort)); 

}

void
PennChord::RspJoinReq (Ipv4Address newAddress, PennChordMessage message) {
  PennChordMessage resp = PennChordMessage (PennChordMessage::JOIN_RSP, message.GetTransactionId());
  resp.SetJoinRsp (m_successorAddress);
  Ptr<Packet> packet = Create<Packet> ();
  packet->AddHeader (resp);
  // std::cout << "join request5" << std::endl;
  m_socket->SendTo (packet, 0 , InetSocketAddress (newAddress, m_appPort));  

}


void
PennChord::ProcessJoinRsp (PennChordMessage message)
{
  // std::cout << "join rsp" << std::endl;
  m_successorAddress = message.GetJoinRsp().successorAddress;
  // std::cout << m_fingerTable.size() << std::endl;
  m_fingerTable[0] = m_successorAddress;
  // m_fingerTable
  // UpdateFingerTable();
}


void
PennChord::ProcessStabilize (PennChordMessage message, Ipv4Address sourceAddress, uint16_t sourcePort)
{
  PennChordMessage resp = PennChordMessage (PennChordMessage::STABILIZE_RSP, message.GetTransactionId());
  resp.SetStabilizeRsp (m_predecessorAddress);
  Ptr<Packet> packet = Create<Packet> ();
  packet->AddHeader (resp);
  m_socket->SendTo (packet, 0 , InetSocketAddress (sourceAddress, sourcePort));

  

}

void
PennChord::ProcessStabilizeRsp (PennChordMessage message)
{
  Ipv4Address newPredAddress = message.GetStabilizeRsp().predAddress;
  uint32_t newPredVal = PennKeyHelper::CreateShaKey(newPredAddress);
  uint32_t curVal = PennKeyHelper::CreateShaKey(GetLocalAddress());
  uint32_t succVal = PennKeyHelper::CreateShaKey(m_successorAddress);
  if (newPredAddress != Ipv4Address::GetAny()) {

    if (curVal < succVal) {
      if (newPredVal > curVal && newPredVal < succVal) {
        m_successorAddress = newPredAddress;
      }
    }
    else {
      if (newPredVal > curVal || newPredVal < succVal) {
        m_successorAddress = newPredAddress;
      }
    }
  }

  uint32_t transactionId = GetNextTransactionId ();
  Ptr<Packet> packet = Create<Packet> ();
  PennChordMessage message_notify = PennChordMessage (PennChordMessage::NOTIFY, transactionId);
  message_notify.SetNotify (GetLocalAddress());
  packet->AddHeader (message_notify);
  // std::cout << "new predecessor address" << newPredAddress << std::endl;
  // std::cout << "success address in process stabilize" << m_successorAddress << std::endl;
  m_socket->SendTo (packet, 0 , InetSocketAddress (m_successorAddress, m_appPort)); 
}

void
PennChord::ProcessNotify(PennChordMessage message)
{
  Ipv4Address newPredAddress = message.GetNotify().predecessorAddress;
  uint32_t newPredVal = PennKeyHelper::CreateShaKey(newPredAddress);
  uint32_t curPredVal = PennKeyHelper::CreateShaKey(m_predecessorAddress);
  uint32_t curVal = PennKeyHelper::CreateShaKey(GetLocalAddress());
  if (m_predecessorAddress != Ipv4Address::GetAny ()) {
    curPredVal = PennKeyHelper::CreateShaKey(m_predecessorAddress);
  }

  if (m_predecessorAddress == Ipv4Address::GetAny ()) {
    m_predecessorAddress = newPredAddress;

  }
  else if (curPredVal < curVal) {
    if (newPredVal > curPredVal && newPredVal < curVal) {
      m_predecessorAddress = newPredAddress;
      // std::cout << "update to new pred node" << ReverseLookup(newPredAddress) << std::endl;
    }
  }
  else if (curPredVal > curVal) {
    if (newPredVal > curPredVal || newPredVal <  curVal) {
      m_predecessorAddress = newPredAddress;
      // std::cout << "update to new pred node" << ReverseLookup(newPredAddress) << std::endl;
    }
  }
  else if (curPredVal == curVal) {
    m_predecessorAddress = newPredAddress;
  }
}


void
PennChord::ProcessRingState (PennChordMessage message)
{ 
  Ipv4Address local = GetLocalAddress();
  std::string curNodeNum = ReverseLookup (local);
  std::string predNodeNum = ReverseLookup (m_predecessorAddress);
  std::string succNodeNum = ReverseLookup (m_successorAddress);
  uint32_t predVal = PennKeyHelper::CreateShaKey(m_predecessorAddress);
  uint32_t curVal = PennKeyHelper::CreateShaKey(local);
  uint32_t succVal = PennKeyHelper::CreateShaKey(m_successorAddress);

  Ipv4Address terminatingAddress =  message.GetRingState().originatorAddress;
  if (local != terminatingAddress) {
    std::ostringstream buffer;
    buffer << "Ring State" << std::endl;
    buffer << "Curr<" <<"Node " << curNodeNum << ", " << local << ", " << std::hex << curVal << ">" << std::endl;
    buffer << "Pred<" << "Node " << std::dec << predNodeNum << ", " << m_predecessorAddress << ", " << std::hex << predVal << ">" << std::endl;
    buffer << "Succ<" << "Node " << std::dec << succNodeNum << ", " << m_successorAddress << ", " << std::hex << succVal << ">" << std::endl;
    PRINT_LOG(buffer.str());
    Ptr<Packet> packet = Create<Packet> ();
    packet->AddHeader (message);
    m_socket->SendTo (packet, 0 , InetSocketAddress (m_successorAddress, m_appPort)); 
  }
}



void
PennChord::ProcessLeaveNoticeSucc (PennChordMessage message)
{
  if (m_predecessorAddress ==  message.GetLeaveNoticeSucc().curAddress) {
    m_predecessorAddress = message.GetLeaveNoticeSucc().predAddress;
  }
}

void
PennChord::ProcessLeaveNoticePred (PennChordMessage message)
{
    if (m_successorAddress ==  message.GetLeaveNoticePred().curAddress) {
    m_successorAddress = message.GetLeaveNoticePred().succAddress;
  }
}






void
PennChord::AuditPings ()
{
  std::map<uint32_t, Ptr<PingRequest> >::iterator iter;
  for (iter = m_pingTracker.begin () ; iter != m_pingTracker.end();)
    {
      Ptr<PingRequest> pingRequest = iter->second;
      if (pingRequest->GetTimestamp().GetMilliSeconds() + m_pingTimeout.GetMilliSeconds() <= Simulator::Now().GetMilliSeconds())
        {
          DEBUG_LOG ("Ping expired. Message: " << pingRequest->GetPingMessage () << " Timestamp: " << pingRequest->GetTimestamp().GetMilliSeconds () << " CurrentTime: " << Simulator::Now().GetMilliSeconds ());
          // Remove stale entries
          m_pingTracker.erase (iter++);
          // Send indication to application layer
          m_pingFailureFn (pingRequest->GetDestinationAddress(), pingRequest->GetPingMessage ());
        }
      else
        {
          ++iter;
        }
    }
  // Rechedule timer
  m_auditPingsTimer.Schedule (m_pingTimeout); 
}

uint32_t
PennChord::GetNextTransactionId ()
{
  return m_currentTransactionId++;
}

void
PennChord::StopChord ()
{
  StopApplication ();
}

void
PennChord::SetPingSuccessCallback (Callback <void, Ipv4Address, std::string> pingSuccessFn)
{
  m_pingSuccessFn = pingSuccessFn;
}


void
PennChord::SetPingFailureCallback (Callback <void, Ipv4Address, std::string> pingFailureFn)
{
  m_pingFailureFn = pingFailureFn;
}

void
PennChord::SetPingRecvCallback (Callback <void, Ipv4Address, std::string> pingRecvFn)
{
  m_pingRecvFn = pingRecvFn;
}

void
PennChord::SetLookupSuccessCallback(Callback <void, Ipv4Address, LookupType, uint32_t> lookupSuccessFn)
{
  m_lookupSuccessFn = lookupSuccessFn;
}

// void InitializeFingerTable() {
//   for (uint8_t i = 0; i <= 32; i++) {
//     m_fingerTable[i] = m_address;
//   }
// }

void PennChord::CreateChord () {
  m_predecessorAddress = Ipv4Address::GetAny ();
  Ipv4Address local = GetLocalAddress();
  m_successorAddress = local;
}

void PennChord::JoinChord (std::string target) {
  m_predecessorAddress = Ipv4Address::GetAny ();
  FindNodeSuccessor(target);
}

void PennChord::FindNodeSuccessor(std::string target) {
  Ipv4Address targetAddress = ResolveNodeIpAddress(target);
  uint32_t transactionId = GetNextTransactionId();
  Ptr<Packet> packet = Create<Packet> ();
  PennChordMessage message = PennChordMessage (PennChordMessage::JOIN_REQ, transactionId);
  message.SetJoinReq (GetLocalAddress());
  packet->AddHeader (message);
  m_socket->SendTo (packet, 0 , InetSocketAddress (targetAddress, m_appPort)); 

}

void PennChord::HandleLeave () {
  uint32_t transactionId1 = GetNextTransactionId();
  Ptr<Packet> packet1 = Create<Packet> ();
  PennChordMessage message1 = PennChordMessage (PennChordMessage::LEAVE_NOTICE_SUCC, transactionId1);
  message1.SetLeaveNoticeSucc (m_predecessorAddress, GetLocalAddress());
  packet1->AddHeader (message1);
  m_socket->SendTo (packet1, 0 , InetSocketAddress (m_predecessorAddress, m_appPort)); 

  uint32_t transactionId2 = GetNextTransactionId();
  Ptr<Packet> packet2 = Create<Packet> ();
  PennChordMessage message2 = PennChordMessage (PennChordMessage::LEAVE_NOTICE_PRED, transactionId2);
  message2.SetLeaveNoticePred (GetLocalAddress(), m_successorAddress);
  packet2->AddHeader (message2);
  m_socket->SendTo (packet2, 0 , InetSocketAddress (m_successorAddress, m_appPort)); 
}

void PennChord::SendRingState(Ipv4Address originatorAddress) {
  Ipv4Address local = GetLocalAddress();
  std::string curNodeNum = ReverseLookup (local);
  std::string predNodeNum = ReverseLookup (m_predecessorAddress);
  std::string succNodeNum = ReverseLookup (m_successorAddress);
  uint32_t predVal = PennKeyHelper::CreateShaKey(m_predecessorAddress);
  uint32_t curVal = PennKeyHelper::CreateShaKey(local);
  uint32_t succVal = PennKeyHelper::CreateShaKey(m_successorAddress);
  std::ostringstream buffer;
  buffer << "Ring State" << std::endl;
  buffer << "Curr<" << "Node " << curNodeNum << ", " << local << ", " << std::hex << curVal << ">" << std::endl;
  buffer << "Pred<" << "Node " << std::dec << predNodeNum << ", " << m_predecessorAddress << ", " << std::hex << predVal << ">" << std::endl;
  buffer << "Succ<" << "Node " << std::dec << succNodeNum << ", " << m_successorAddress << ", " << std::hex <<succVal << ">" << std::endl;
  PRINT_LOG(buffer.str());

  uint32_t transactionId = GetNextTransactionId ();
  Ptr<Packet> packet = Create<Packet> ();
  PennChordMessage message = PennChordMessage (PennChordMessage::RINGSTATE, transactionId);
  message.SetRingState (GetLocalAddress());
  packet->AddHeader (message);
  m_socket->SendTo (packet, 0 , InetSocketAddress (m_successorAddress, m_appPort)); 
}


void PennChord::Stabilize()
{ 
  if (m_successorAddress != Ipv4Address::GetAny()) {
    uint32_t transactionId = GetNextTransactionId ();
    Ptr<Packet> packet = Create<Packet> ();
    PennChordMessage message = PennChordMessage (PennChordMessage::STABILIZE, transactionId);
    message.SetStabilize (GetLocalAddress());
    packet->AddHeader (message);
    m_socket->SendTo (packet, 0 , InetSocketAddress (m_successorAddress, m_appPort)); 
  }
  
  m_stabilizeTimer.Schedule(m_stabilizeTimeout);
}


void PennChord::ProcessFixFinger(PennChordMessage message) {
  uint32_t idVal = message.GetFixFinger().number;
  uint32_t sucVal = PennKeyHelper::CreateShaKey(m_successorAddress);
  Ipv4Address rspAddress = message.GetFixFinger().originatorAddress;
  if (InRange(idVal, m_value, sucVal)) {
    Ptr<Packet> packet = Create<Packet> ();
    PennChordMessage message2 = PennChordMessage (PennChordMessage::FIXFINGER_RSP, message.GetTransactionId());
    message2.SetFixFingerRsp (m_successorAddress);
    packet->AddHeader (message2);
    m_socket->SendTo (packet, 0 , InetSocketAddress (rspAddress, m_appPort)); 
  }
  else {
    FindSuccessor(idVal, message);
  }
}

void PennChord::ProcessFixFingerRsp(PennChordMessage message) {
  Ipv4Address newAddress = message.GetFixFingerRsp().successorAddress;
  m_fingerTable[m_next - 1] = newAddress;
  
}


void PennChord::FixFingers()
{ 
  // if (m_node == "5") {
  //   std::cout << "running fix fingers on node " << m_node << std::endl;
  //   std::cout << "m_next = " << std::dec << m_next << std::endl;
  //   uint16_t i = 0;
  //   for (auto iter = m_fingerTable.begin(); iter != m_fingerTable.end(); iter++) {
  //     std::cout << "entry " << i << ": " << ReverseLookup(*iter) << "ip address: " << *iter << std::endl;
  //     i++;
  //   }
  // }
  m_next++;
  if (m_next > 32) {
    m_next = 1;
  }
  // if (m_node == "5") {
  //   std::cout << "current m_next value: " << std::dec << m_next << std::endl;
  // }
  
  uint32_t idVal = (m_value + (uint32_t) pow(2, m_next - 1)) % ((uint32_t) pow (2, 32));
  // if (m_node == "5") {
  //   // uint32_t mx = pow(2, 31);
  //   // std::cout << "maximum increase: " << std::hex << mx << std::endl;
  //   // std::cout << "current node value: " << std::hex << m_value << std::endl;
  //   std::cout << "added value" << std::dec << (uint32_t) pow(2, m_next - 1) << std::endl;
  //   // std::cout << "idVal = " << std::dec << idVal << std::endl;
  //   // if (idVal == 23402221 ) {
  //   //   std::cout << "yes begining" << std::endl;
  //   // }
  // }
  uint32_t sucVal = PennKeyHelper::CreateShaKey(m_successorAddress);
  if (InRange(idVal, m_value, sucVal)) {
    m_fingerTable[m_next - 1] = m_successorAddress;
  }
  else {
    uint32_t transactionId = GetNextTransactionId();
    PennChordMessage message = PennChordMessage (PennChordMessage::FIXFINGER, transactionId);
    message.SetFixFinger (GetLocalAddress(), idVal);
    FindSuccessor(idVal, message);
  }

  m_fixFingerTimer.Schedule(m_fixFingerTimeout);
}


void PennChord::ProcessLookup(PennChordMessage message) {
  uint32_t idVal = message.GetLookup().idVal;
  uint32_t sucVal = PennKeyHelper::CreateShaKey(m_successorAddress);
  if (InRange(idVal, m_value, sucVal)) {
    // uint32_t transactionId = GetNextTransactionId();
    Ptr<Packet> packet2 = Create<Packet> ();
    PennChordMessage message2 = PennChordMessage (PennChordMessage::LOOKUP_RSP, message.GetTransactionId());
    message2.SetLookupRsp (m_successorAddress, message.GetLookup().type, idVal);
    // std::cout << "in process lookup the transactionID is: " << message.GetTransactionId() << std::endl;
    // std::cout << "In process lookup the lookup type is " << (uint32_t) (message.GetLookup().type) << std::endl; 
    packet2->AddHeader (message2);
    // if (idVal == 3092139357) {
    //     std::cout << "in processLookup return successor node: " << ReverseLookup(m_successorAddress) << std::endl;
    //   }
    m_socket->SendTo (packet2, 0 , InetSocketAddress (message.GetLookup().originatorAddress, m_appPort)); 
    // m_pingRecvFn (sourceAddress, message.GetPingReq().pingMessage);
  }
  else {
    Ptr<Packet> packet = Create<Packet> ();
    packet->AddHeader (message);
    Ipv4Address nextAddress = ClosestPrecedingNode(idVal);
    CHORD_LOG ("LookupRequest<" << m_node << ">: NextHop<" << ReverseLookup(nextAddress) << "," << idVal << ">");
    if (nextAddress == m_address) {
      // if (idVal == 3092139357) {
      //   std::cout << "in processLookup to successor node: " << ReverseLookup(m_successorAddress) << std::endl;
      // }
      m_socket->SendTo (packet, 0 , InetSocketAddress (m_successorAddress, m_appPort));
    }
    else {
      // if (idVal == 3092139357) {
      //   std::cout << "in processLookup to next node: " << ReverseLookup(nextAddress) << std::endl;
      // }
      m_socket->SendTo (packet, 0 , InetSocketAddress (nextAddress, m_appPort));
    }
    
  }

}

void PennChord::ProcessLookupRsp(PennChordMessage message, Ipv4Address sourceAddress, uint16_t sourcePort) {
  
      // Send indication to application layer
  // std::cout << "transactionID: " << message.GetTransactionId() << std::endl;
  // std::cout << "cast type in chord: " << (uint32_t) message.GetLookupRsp().type << std::endl;
  // std::cout << "2nd source address is: " << sourceAddress << std::endl;
  // std::cout << message.GetLookupRsp().type << std::endl;
  CHORD_LOG ("LookupResult<" << m_node << ">");
  // uint32_t idVal = (uint32_t) message.GetLookupRsp().idVal;
  // if (idVal == 3092139357) {
  //   std::cout << "in processlookup rsp the transid: " << message.GetTransactionId();
  //   std::cout << "   find the node to sent to: " << ReverseLookup(sourceAddress) << std::endl;
  // }

  m_lookupSuccessFn (message.GetLookupRsp().originatorAddress, (LookupType) message.GetLookupRsp().type, message.GetTransactionId());
}





void PennChord::Lookup(std::string key, LookupType type, uint32_t transId) {
  // std::cout << "cast in lookup: " << (uint32_t) type << " with keyword " << key << std::endl;
  
  // std::cout << "in lookup key is: " << key << std::endl;
  
  CHORD_LOG ("LookupIssue<" << m_node << ", " << key << ">");
  uint32_t idVal = PennKeyHelper::CreateShaKey(key);
  // if (key == "Johnny-Depp") {
  //   std::cout << "idVal = " << idVal << std::endl;
  // }
  
  
  uint32_t curVal = PennKeyHelper::CreateShaKey(m_address);
  uint32_t sucVal = PennKeyHelper::CreateShaKey(m_successorAddress);
  uint32_t transactionId = transId;
  Ptr<Packet> packet = Create<Packet> ();
  PennChordMessage message = PennChordMessage (PennChordMessage::LOOKUP, transactionId);
  message.SetLookup(idVal, type, m_address);
  packet->AddHeader (message);
  if (InRange(idVal, curVal, sucVal) && m_successorAddress != Ipv4Address::GetAny()) {
    // std::cout << "send back to application layer" << std::endl;
    // m_socket->SendTo (packet, 0 , InetSocketAddress (m_successorAddress, m_appPort)); 
    // if (key == "Johnny-Depp") {
    //   uint32_t i = 0;
    //   for (auto it = m_fingerTable.begin(); it != m_fingerTable.end(); it++) {
    //     std::cout << "entry " << i << ": " << ReverseLookup(*it) << std::endl;
    //     i++;
    //     }
    // }
      // if (key == "Johnny-Depp") {
      //   std::cout << "in lookup return directly with node address " << ReverseLookup(m_successorAddress) << std::endl;
          
      //   std::cout << "in processlookup rsp the transid: " << message.GetTransactionId();
      // }
    m_lookupSuccessFn (m_successorAddress, type, transId);
    }
  else {
    Ipv4Address nextAddress = ClosestPrecedingNode(idVal);
    // std::cout << "for key " << key << " next node is " << ReverseLookup(nextAddress) << " with id Val "  << idVal << std::endl;
    CHORD_LOG ("LookupRequest<" << m_node << ">: NextHop<" << ReverseLookup(nextAddress) << "," << key << ">");
    if (nextAddress == m_address) {
      // if (key == "Johnny-Depp") {
      //   std::cout << "to successor node: " << ReverseLookup(m_successorAddress) << std::endl;
      // }
       m_socket->SendTo (packet, 0 , InetSocketAddress (m_successorAddress, m_appPort)); 
    }
    else {
      // if (key == "Johnny-Depp") {
      //   std::cout << "to next node: " << ReverseLookup(nextAddress) << std::endl;
      // }
      m_socket->SendTo (packet, 0 , InetSocketAddress (nextAddress, m_appPort)); 
    }
  }
}

void PennChord::FindSuccessor(uint32_t idVal, PennChordMessage message) {
  uint32_t curVal = PennKeyHelper::CreateShaKey(GetLocalAddress());
  uint32_t sucVal = PennKeyHelper::CreateShaKey(m_successorAddress);
  // uint32_t idVal = PennKeyHelper::CreateShaKey(id);
  Ptr<Packet> packet = Create<Packet> ();
  packet->AddHeader (message);
  if (InRange(idVal, curVal, sucVal)) {
    // SendPublishReq(message);
    m_socket->SendTo (packet, 0 , InetSocketAddress (m_successorAddress, m_appPort)); 
    }
  else {
    Ipv4Address nextAddress = ClosestPrecedingNode(idVal);
    if (nextAddress == m_address) {
      m_socket->SendTo (packet, 0 , InetSocketAddress (m_successorAddress, m_appPort)); 
    }
    else {
      m_socket->SendTo (packet, 0 , InetSocketAddress (nextAddress, m_appPort)); 
    }
    
  }
}

Ipv4Address PennChord::ClosestPrecedingNode(uint32_t idVal) {
  
  uint32_t curVal = m_value;
  //  std::cout << "running closestPredNode" << std::endl;
  for (uint8_t i = 31; i >= 0; i--) {
    uint32_t tableValue = PennKeyHelper::CreateShaKey(m_fingerTable[i]);
    if (curVal < idVal) {
      if (tableValue > curVal && tableValue < idVal) {
        if (m_fingerTable[i] == Ipv4Address::GetAny() && m_node == "0") {
          // std::cout << "be careful!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!" << std::endl;
          // std::cout << m_node;
        }
        return m_fingerTable[i];
      }
    }
    else {
      if (tableValue > curVal || tableValue < idVal) {
        if (m_fingerTable[i] == Ipv4Address::GetAny() && m_node == "0") {
          // std::cout << "be careful2!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!" << std::endl;
          // std::cout << m_node;
        }
        return m_fingerTable[i];
      }
    }
  }
  return GetLocalAddress();
}

bool PennChord::InRange(uint32_t id, uint32_t n, uint32_t successor) {
  if (n < successor) {
    if (id > n && id <= successor) {
      return true;
    }
    else {
      return false;
    }
  }
  else {
    if (id > n || id <= successor) {
      return true;
    }
    else return false;
  }
}

// bool PennChord::IsSuccessor(uint32_t idVal) {
//   if (m_value >= idVal) {
//     return true;
//   }
//   else {
//     uint32_t predVal = PennKeyHelper::CreateShaKey(m_predecessorAddress);
//     if (m_value <= predVal) {
//       return true;
//     }
//     else {
//       return false;
//     }
//   }

// }








