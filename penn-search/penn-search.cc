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


#include "penn-search.h"

#include "ns3/random-variable-stream.h"
#include "ns3/inet-socket-address.h"
#include <algorithm>
#include <vector>
#include <map>

using namespace ns3;

TypeId
PennSearch::GetTypeId ()
{
  static TypeId tid = TypeId ("PennSearch")
    .SetParent<PennApplication> ()
    .AddConstructor<PennSearch> ()
    .AddAttribute ("AppPort",
                   "Listening port for Application",
                   UintegerValue (10000),
                   MakeUintegerAccessor (&PennSearch::m_appPort),
                   MakeUintegerChecker<uint16_t> ())
    .AddAttribute ("ChordPort",
                   "Listening port for Application",
                   UintegerValue (10001),
                   MakeUintegerAccessor (&PennSearch::m_chordPort),
                   MakeUintegerChecker<uint16_t> ())
    .AddAttribute ("PingTimeout",
                   "Timeout value for PING_REQ in milliseconds",
                   TimeValue (MilliSeconds (2000)),
                   MakeTimeAccessor (&PennSearch::m_pingTimeout),
                   MakeTimeChecker ())
    ;
  return tid;
}

PennSearch::PennSearch ()
  : m_auditPingsTimer (Timer::CANCEL_ON_DESTROY)
{
  m_chord = NULL;

  Ptr<UniformRandomVariable> m_uniformRandomVariable = CreateObject<UniformRandomVariable> ();
  m_currentTransactionId = m_uniformRandomVariable->GetValue (0x00000000, 0xFFFFFFFF);
}

PennSearch::~PennSearch ()
{

}

void
PennSearch::DoDispose ()
{
  StopApplication ();
  PennApplication::DoDispose ();
}

void
PennSearch::StartApplication (void)
{
  std::cout << "PennSearch::StartApplication()!!!!!" << std::endl;
  // std::cout << "here is node "  << GetNodeId () << std::endl;
  // std::cout << "the address is " << m_local << std::endl;
  // Create and Configure PennChord
  ObjectFactory factory;

  factory.SetTypeId (PennChord::GetTypeId ());
  factory.Set ("AppPort", UintegerValue (m_chordPort));
  m_chord = factory.Create<PennChord> ();
  m_chord->SetNode (GetNode ());
  m_chord->SetNodeAddressMap (m_nodeAddressMap);
  m_chord->SetAddressNodeMap (m_addressNodeMap);
  m_chord->SetModuleName ("CHORD");
  std::string nodeId = GetNodeId ();
  m_chord->SetNodeId (nodeId);
  m_chord->SetLocalAddress (m_local);
   

  // Configure Callbacks with Chord
  m_chord->SetPingSuccessCallback (MakeCallback (&PennSearch::HandleChordPingSuccess, this)); 
  m_chord->SetPingFailureCallback (MakeCallback (&PennSearch::HandleChordPingFailure, this));
  m_chord->SetPingRecvCallback (MakeCallback (&PennSearch::HandleChordPingRecv, this)); 
  m_chord->SetLookupSuccessCallback (MakeCallback (&PennSearch::HandleChordLookupSuccess, this));
  // Start Chord
  m_chord->SetStartTime (Simulator::Now());
  m_chord->Initialize();

  if (m_socket == 0)
    { 
      TypeId tid = TypeId::LookupByName ("ns3::UdpSocketFactory");
      m_socket = Socket::CreateSocket (GetNode (), tid);
      InetSocketAddress local = InetSocketAddress (Ipv4Address::GetAny(), m_appPort);
      m_socket->Bind (local);
      m_socket->SetRecvCallback (MakeCallback (&PennSearch::RecvMessage, this));
    }  
  
  // Configure timers
  m_auditPingsTimer.SetFunction (&PennSearch::AuditPings, this);
  // Start timers
  m_auditPingsTimer.Schedule (m_pingTimeout);
}

void
PennSearch::StopApplication (void)
{
  //Stop chord
  m_chord->StopChord ();
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
}

void
PennSearch::ProcessCommand (std::vector<std::string> tokens)
{
  std::vector<std::string>::iterator iterator = tokens.begin();
  std::string command = *iterator;
  // std::cout << command << std::endl;
  if (command == "CHORD")
    { 
      // Send to Chord Sub-Layer
      tokens.erase (iterator);
      m_chord->ProcessCommand (tokens);
    } 
  if (command == "PING")
    {
      if (tokens.size() < 3)
        {
          ERROR_LOG ("Insufficient PING params..."); 
          return;
        }
      iterator++;
      if (*iterator != "*")
        {
          std::string nodeId = *iterator;
          iterator++;
          std::string pingMessage = *iterator;
          SendPing (nodeId, pingMessage);
        }
      else
        {
          iterator++;
          std::string pingMessage = *iterator;
          std::map<uint32_t, Ipv4Address>::iterator iter;
          for (iter = m_nodeAddressMap.begin () ; iter != m_nodeAddressMap.end (); iter++)  
            {
              std::ostringstream sin;
              uint32_t nodeNumber = iter->first;
              sin << nodeNumber;
              std::string nodeId = sin.str();    
              SendPing (nodeId, pingMessage);
            }
        }
    }
  else if (command == "PUBLISH") {
    iterator++;
    std::string filePath = *iterator;
    Publish(filePath);
  }
  else if (command == "SEARCH") {
    iterator++;
    std::string queryNode = *iterator;
    std::vector<std::string> keywords;
    iterator++;
    while (iterator != tokens.end()) {
      keywords.push_back(*iterator);
      // std::cout << "in keywords: " << *iterator << std::endl;
      iterator++;
    }
    // std::cout << "original address: " << ReverseLookup(GetLocalAddress()) << std::endl;
    Contact(queryNode, keywords, GetLocalAddress());
  }  
}

void
PennSearch::SendPing (std::string nodeId, std::string pingMessage)
{
  // Send Ping Via-Chord layer 
  SEARCH_LOG ("Sending Ping via Chord Layer to node: " << nodeId << " Message: " << pingMessage);
  Ipv4Address destAddress = ResolveNodeIpAddress(nodeId);
  m_chord->SendPing (destAddress, pingMessage);
}

void
PennSearch::SendPennSearchPing (Ipv4Address destAddress, std::string pingMessage)
{
  if (destAddress != Ipv4Address::GetAny ())
    {
      uint32_t transactionId = GetNextTransactionId ();
      SEARCH_LOG ("Sending PING_REQ to Node: " << ReverseLookup(destAddress) << " IP: " << destAddress << " Message: " << pingMessage << " transactionId: " << transactionId);
      Ptr<PingRequest> pingRequest = Create<PingRequest> (transactionId, Simulator::Now(), destAddress, pingMessage);
      // Add to ping-tracker
      m_pingTracker.insert (std::make_pair (transactionId, pingRequest));
      Ptr<Packet> packet = Create<Packet> ();
      PennSearchMessage message = PennSearchMessage (PennSearchMessage::PING_REQ, transactionId);
      message.SetPingReq (pingMessage);
      packet->AddHeader (message);
      m_socket->SendTo (packet, 0 , InetSocketAddress (destAddress, m_appPort));
    }


}

void
PennSearch::RecvMessage (Ptr<Socket> socket)
{
  Address sourceAddr;
  Ptr<Packet> packet = socket->RecvFrom (sourceAddr);
  InetSocketAddress inetSocketAddr = InetSocketAddress::ConvertFrom (sourceAddr);
  Ipv4Address sourceAddress = inetSocketAddr.GetIpv4 ();
  uint16_t sourcePort = inetSocketAddr.GetPort ();
  PennSearchMessage message;
  packet->RemoveHeader (message);

  switch (message.GetMessageType ())
    {
      case PennSearchMessage::PING_REQ:
        ProcessPingReq (message, sourceAddress, sourcePort);
        break;
      case PennSearchMessage::PING_RSP:
        ProcessPingRsp (message, sourceAddress, sourcePort);
        break;
      case PennSearchMessage::PUBLISH_REQ:
        ProcessPublish (message);
        break;
      case PennSearchMessage::SEARCH_REQ:
        ProcessSearchReq (message);
        break;
      case PennSearchMessage::SEARCH_RSP:
        ProcessSearchRsp (message);
        break;
      case PennSearchMessage::SEARCH_CONTACT:
        ProcessSearchContact (message);
        break;
      default:
        ERROR_LOG ("Unknown Message Type!");
        break;
    }
}

void
PennSearch::ProcessPingReq (PennSearchMessage message, Ipv4Address sourceAddress, uint16_t sourcePort)
{

    // Use reverse lookup for ease of debug
    std::string fromNode = ReverseLookup (sourceAddress);
    SEARCH_LOG ("Received PING_REQ, From Node: " << fromNode << ", Message: " << message.GetPingReq().pingMessage);
    // Send Ping Response
    PennSearchMessage resp = PennSearchMessage (PennSearchMessage::PING_RSP, message.GetTransactionId());
    resp.SetPingRsp (message.GetPingReq().pingMessage);
    Ptr<Packet> packet = Create<Packet> ();
    packet->AddHeader (resp);
    m_socket->SendTo (packet, 0 , InetSocketAddress (sourceAddress, sourcePort));
}

void
PennSearch::ProcessPingRsp (PennSearchMessage message, Ipv4Address sourceAddress, uint16_t sourcePort)
{
  // Remove from pingTracker
  std::map<uint32_t, Ptr<PingRequest> >::iterator iter;
  iter = m_pingTracker.find (message.GetTransactionId ());
  if (iter != m_pingTracker.end ())
    {
      std::string fromNode = ReverseLookup (sourceAddress);
      SEARCH_LOG ("Received PING_RSP, From Node: " << fromNode << ", Message: " << message.GetPingRsp().pingMessage);
      m_pingTracker.erase (iter);
    }
  else
    {
      DEBUG_LOG ("Received invalid PING_RSP!");
    }
}


void PennSearch::ProcessPublish(PennSearchMessage message) {
  
  
  std::set<std::string> valueList = message.GetPublishReq().values;
  std::string key = message.GetPublishReq().key;
  
  for (auto itLog = valueList.begin(); itLog != valueList.end(); itLog++) {
      SEARCH_LOG ("Store<" << key << ", " << *itLog << ">");
    }
  // Save();
  std::map<std::string, std::set<std::string>>::iterator iter = m_invertedList.find(key);
  if (iter == m_invertedList.end()) {
    m_invertedList.insert(std::make_pair(key, valueList));
  }
  else{
    std::set<std::string> mergedSet;
    std::set<std::string> existingSet = m_invertedList[key];
    std::set_union(valueList.begin(), valueList.end(), existingSet.begin(), existingSet.end(), std::inserter(mergedSet, mergedSet.begin()));
    // mergedSet = SetUnion(valueList, m_invertedList[])
    m_invertedList[key] = mergedSet;
  }


  // RspPublish();
  // std::ostringstream buffer;
  // for (auto it = valueList.begin(); it != valueList.end(); it++) {
  //   buffer << *it <<", ";
  // }
  // CHORD_LOG ("Store<" << key << ", {" << buffer << "}");



}



void PennSearch::ProcessSearchRsp(PennSearchMessage message) {
  std::set<std::string> searchResults = message.GetSearchRsp().searchResult;
  if (searchResults.size() == 0) {
    SEARCH_LOG ("SearchResults<Node " << ReverseLookup(GetLocalAddress()) << ", 'Empty List'>");
  }
  else {
    std::ostringstream buffer;
    buffer << "SearchResults<Node " << ReverseLookup(GetLocalAddress()) << ", {";
    uint32_t resultNum = searchResults.size();
    uint32_t count = 0;
    for (auto itLog = searchResults.begin(); itLog != searchResults.end(); itLog++) {
      if (count != resultNum - 1) {
        buffer << *itLog << ", ";
      }
      else {
        buffer << *itLog;
      }
      count++;
    }

    buffer << "}>";
    SEARCH_LOG (buffer.str());

  }



  // for (auto iter = searchResults.begin(); iter != searchResults.end(); iter++) {
  //   std::cout << *iter << std::endl;
  // }

}


void
PennSearch::AuditPings ()
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
        }
      else
        {
          ++iter;
        }
    }
  // Rechedule timer
  m_auditPingsTimer.Schedule (m_pingTimeout); 
}


void PennSearch::Publish(std::string filePath) {
  std::ifstream fileStream;
  fileStream.open(filePath);
  std::vector<std::string> out;
  std::string line;
  std::map<std::string, std::set<std::string>> invertedList;
  while(std::getline(fileStream, line)) {
    std::set<std::string> st;
    std::stringstream ss (line);
    uint32_t count = 0;
    std::string key;
    std::string token;
    while (std::getline(ss, token, ' ')) {
      // out.push_back(token);
      if (count == 0) {
        key = token;
      }
      else {
        
        std::map<std::string, std::set<std::string>>::iterator iterI = invertedList.find(token);
        if (iterI == invertedList.end()) {
          std::set<std::string> setI;
          setI.insert(key);
          invertedList.insert(std::make_pair(token, setI));
        }
        else {
          std::set<std::string> oldSet = invertedList[token];
          oldSet.insert(key);
          invertedList[token] = oldSet;
        }
        
      }
      count++;
    }

  }

  // for (auto iter = invertedList.begin(); iter != invertedList.end(); iter++) {
  //   std::cout << iter->first << ": " << std::endl;
  //   for (auto iterS = iter->second.begin(); iterS != iter->second.end(); iterS++) {
  //     std::cout << *iterS << "--";
  //   }
  //   std::cout << std::endl;
  // }
  // std::cout << std::endl;

  for (auto it = invertedList.begin(); it != invertedList.end(); it++) {
    uint32_t transactionId = GetNextTransactionId();
    PennSearchMessage message = PennSearchMessage (PennSearchMessage::PUBLISH_REQ, transactionId);
    
    for (auto itLog = it->second.begin(); itLog != it->second.end(); itLog++) {
      SEARCH_LOG ("Publish<" << it->first << ", " << *itLog << ">");
    }
    message.SetPublishReq (it->first, it->second);
    m_publishMessages.insert(std::make_pair(transactionId, message));
    m_chord->Lookup(it->first, PennChord::LookupType::PUBLISH_REQ, transactionId);
  }
}

void PennSearch::PublishPennSearch(Ipv4Address destAddress, uint32_t transactionId) {
  PennSearchMessage message =  m_publishMessages[transactionId];
  Ptr<Packet> packet = Create<Packet> ();
  packet->AddHeader (message);
  // std::cout << "should be herere before process publish" << std::endl;
  // std::cout << "publish to node " << ReverseLookup(destAddress) << std::endl;
  // std::cout << "in message the key is" << message.GetPublishReq().key << std::endl;
  m_socket->SendTo (packet, 0 , InetSocketAddress (destAddress, m_appPort)); 
}

void PennSearch::Contact(std::string node, std::vector<std::string> keywords, Ipv4Address originatorAddress) {
  // std::cout << "herer1" << std::endl;
  std::ostringstream buffer;
  buffer << "Search<";
  uint32_t keywordsNum = keywords.size();
  for (uint32_t i = 0; i < keywordsNum; i++) {
    if (i != keywordsNum - 1) {
      buffer << keywords[i] << ", ";
    }
    else {
      buffer << keywords[i];
    }
  }

  buffer << ">";
  SEARCH_LOG (buffer.str());
  Ipv4Address destAddress = ResolveNodeIpAddress(node);
  uint32_t transactionId = GetNextTransactionId ();
  if (node != GetNodeId()) {
    // std::cout << "search contact started!!! " << std::endl;
    Ptr<Packet> packet = Create<Packet> ();
    PennSearchMessage message = PennSearchMessage (PennSearchMessage::SEARCH_CONTACT, transactionId);
    message.SetSearchContact (keywords, originatorAddress);
    packet->AddHeader (message);
    m_socket->SendTo (packet, 0 , InetSocketAddress (destAddress, m_appPort));
  }
  else { 
    PennSearchMessage message2 = PennSearchMessage (PennSearchMessage::SEARCH_REQ, transactionId);
    std::set<std::string> emptySet;
    message2.SetSearchReq(emptySet, 0, keywords, originatorAddress);
    m_searchMessages.insert(std::make_pair(transactionId, message2));
    // std::cout << "herer3" << std::endl;
    m_chord->Lookup(keywords[0], PennChord::LookupType::SEARCH_REQ, transactionId); 
  }
}

void PennSearch::ProcessSearchContact(PennSearchMessage message) {
  // std::cout << ReverseLookup(m_local) << std::endl;
  // std::cout << "in process contact" << std::endl;
  uint32_t transactionId = message.GetTransactionId();
  std::vector<std::string> keywords = message.GetSearchContact().keywords;
  Ipv4Address originatorAddress = message.GetSearchContact().originatorAddress;
  std::set<std::string> emptySet;
  PennSearchMessage message2 = PennSearchMessage (PennSearchMessage::SEARCH_REQ, transactionId);
  message2.SetSearchReq(emptySet, 0, keywords, originatorAddress);
  m_searchMessages.insert(std::make_pair(transactionId, message2));
  m_chord->Lookup(keywords[0], PennChord::LookupType::SEARCH_REQ, transactionId);
}

// void PennSearch::SearchStart(Ipv4Address destAddress, std::string word) {

// }

void PennSearch::Search(Ipv4Address destAddress, uint32_t transactionId) {
  //make sure it is the same query
  PennSearchMessage message = m_searchMessages[transactionId];
  Ptr<Packet> packet = Create<Packet> ();
  packet->AddHeader (message);
  m_socket->SendTo (packet, 0 , InetSocketAddress (destAddress, m_appPort)); 
  
}

void PennSearch::ProcessSearchReq(PennSearchMessage message) {
  std::vector<std::string> keywords = message.GetSearchReq().keywords;
  uint32_t keyNumber = message.GetSearchReq().keyNumber;
  uint32_t totalNumber = keywords.size();
  Ipv4Address originatorAddress = message.GetSearchReq().originatorAddress;
  std::set<std::string> existingSet = message.GetSearchReq().obtainedResult;
  std::string word = keywords[keyNumber];
  std::set<std::string> searchResult = m_invertedList[word];
  std::set<std::string> intersectionSet;
  uint32_t transactionId = message.GetTransactionId();
  // std::cout << "in node: " << ReverseLookup(GetLocalAddress()) << std::endl;
  // std::cout << "search key is: " << word << std::endl;
  // std::cout << "keyNumber is: " << keyNumber << std::endl; 

  std::ostringstream buffer;
  buffer << "transactionId: " << transactionId << " InvertedListShip<" << word << ", {";
  uint32_t resultNum = searchResult.size();
  uint32_t count = 0;
  for (auto itLog = searchResult.begin(); itLog != searchResult.end(); itLog++) {
    if (count != resultNum - 1) {
      buffer << *itLog << ", ";
    }
    else {
      buffer << *itLog;
    }
    count++;
  }

  buffer << "}>";
  SEARCH_LOG (buffer.str());



  if (keyNumber != 0) {
    std::set_intersection(existingSet.begin(), existingSet.end(), searchResult.begin(), searchResult.end(), 
                        std::inserter(intersectionSet, intersectionSet.begin()));
  }
  else {
    intersectionSet = searchResult;
  }
  // std::cout << "in process searchreq: " << std::endl;
  
  if (keyNumber < totalNumber - 1) {
    PennSearchMessage messageUpdated = PennSearchMessage (PennSearchMessage::SEARCH_REQ, transactionId);
    keyNumber++;
    messageUpdated.SetSearchReq(intersectionSet, keyNumber, keywords, originatorAddress);
    //this is important
    std::map<uint32_t,  PennSearchMessage>::iterator iter = m_searchMessages.find(transactionId);
    if (iter == m_searchMessages.end()) {
      m_searchMessages.insert(std::make_pair(transactionId, messageUpdated));
    }
    else {
      m_searchMessages[transactionId] = messageUpdated;
    }
    
    // std::cout << "keyword in process search req " << keywords[keyNumber] << std::endl;
    m_chord->Lookup(keywords[keyNumber], PennChord::LookupType::SEARCH_REQ, transactionId);
  }
  else {
    //QueryRsp;
    Ptr<Packet> packet = Create<Packet> ();
    PennSearchMessage message2 = PennSearchMessage (PennSearchMessage::SEARCH_RSP, transactionId);
    message2.SetSearchRsp (intersectionSet);
    packet->AddHeader (message2);
    m_socket->SendTo (packet, 0 , InetSocketAddress (originatorAddress, m_appPort)); 
  }
}



uint32_t
PennSearch::GetNextTransactionId ()
{
  return m_currentTransactionId++;
}

// Handle Chord Callbacks

void
PennSearch::HandleChordPingFailure (Ipv4Address destAddress, std::string message)
{
  SEARCH_LOG ("Chord Ping Expired! Destination nodeId: " << ReverseLookup(destAddress) << " IP: " << destAddress << " Message: " << message);
}

void
PennSearch::HandleChordPingSuccess (Ipv4Address destAddress, std::string message)
{
  SEARCH_LOG ("Chord Ping Success! Destination nodeId: " << ReverseLookup(destAddress) << " IP: " << destAddress << " Message: " << message);
  // Send ping via search layer 
  SendPennSearchPing (destAddress, message);
}

void
PennSearch::HandleChordPingRecv (Ipv4Address destAddress, std::string message)
{
  SEARCH_LOG ("Chord Layer Received Ping! Source nodeId: " << ReverseLookup(destAddress) << " IP: " << destAddress << " Message: " << message);
}

void
PennSearch::HandleChordLookupSuccess (Ipv4Address destAddress, PennChord::LookupType type, std::uint32_t transId) 
{
//  std::cout << "casted type: " << (uint32_t) type << std::endl;
  if (type == PennChord::PUBLISH_REQ) {
    // std::cout << "send to process publish request" << std::endl;
    // std::cout << destAddress << "  node number is: " << ReverseLookup(destAddress) << std::endl;
    PublishPennSearch (destAddress, transId);
    }
  else if (type == PennChord::SEARCH_REQ) {
    // std::cout << "here 17" << std::endl;
    Search (destAddress, transId);
  }
 

}

// Override PennLog

void
PennSearch::SetTrafficVerbose (bool on)
{ 
  m_chord->SetTrafficVerbose (on);
  g_trafficVerbose = on;
}

void
PennSearch::SetErrorVerbose (bool on)
{ 
  m_chord->SetErrorVerbose (on);
  g_errorVerbose = on;
}

void
PennSearch::SetDebugVerbose (bool on)
{
  m_chord->SetDebugVerbose (on);
  g_debugVerbose = on;
}

void
PennSearch::SetStatusVerbose (bool on)
{
  m_chord->SetStatusVerbose (on);
  g_statusVerbose = on;
}

void
PennSearch::SetChordVerbose (bool on)
{
  m_chord->SetChordVerbose (on);
  g_chordVerbose = on;
}

void
PennSearch::SetSearchVerbose (bool on)
{
  m_chord->SetSearchVerbose (on);
  g_searchVerbose = on;
}
