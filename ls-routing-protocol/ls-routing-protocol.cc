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

#include "ns3/ls-routing-protocol.h"
#include "ns3/double.h"
#include "ns3/inet-socket-address.h"
#include "ns3/ipv4-header.h"
#include "ns3/ipv4-packet-info-tag.h"
#include "ns3/ipv4-route.h"
#include "ns3/log.h"
#include "ns3/random-variable-stream.h"
#include "ns3/simulator.h"
#include "ns3/socket-factory.h"
#include "ns3/test-result.h"
#include "ns3/udp-socket-factory.h"
#include "ns3/uinteger.h"
#include <ctime>
#include <unordered_set>
#include <deque>

using namespace ns3;

NS_LOG_COMPONENT_DEFINE("LSRoutingProtocol");
NS_OBJECT_ENSURE_REGISTERED(LSRoutingProtocol);

/********** Miscellaneous constants **********/

/// Maximum allowed sequence number
#define LS_MAX_SEQUENCE_NUMBER 0xFFFF
#define LS_PORT_NUMBER 698

TypeId
LSRoutingProtocol::GetTypeId(void)
{
  static TypeId tid = TypeId("LSRoutingProtocol")
                          .SetParent<PennRoutingProtocol>()
                          .AddConstructor<LSRoutingProtocol>()
                          .AddAttribute("LSPort", "Listening port for LS packets", UintegerValue(5000),
                                        MakeUintegerAccessor(&LSRoutingProtocol::m_lsPort), MakeUintegerChecker<uint16_t>())
                          .AddAttribute("PingTimeout", "Timeout value for PING_REQ in milliseconds", TimeValue(MilliSeconds(2000)),
                                        MakeTimeAccessor(&LSRoutingProtocol::m_pingTimeout), MakeTimeChecker())
                          .AddAttribute("HelloTimeout", "Timeout value for HELLO_REQ in milliseconds", TimeValue(MilliSeconds(80000)),
                                        MakeTimeAccessor(&LSRoutingProtocol::m_helloTimeout), MakeTimeChecker())
                          .AddAttribute("BroadcastHelloTimeout", "Timeout value for BroadcastHello in milliseconds", TimeValue(MilliSeconds(8000)),
                                        MakeTimeAccessor(&LSRoutingProtocol::m_broadcastHelloTimeout), MakeTimeChecker())
                          .AddAttribute("MaxTTL", "Maximum TTL value for LS packets", UintegerValue(16),
                                        MakeUintegerAccessor(&LSRoutingProtocol::m_maxTTL), MakeUintegerChecker<uint8_t>())
                          .AddAttribute("RoutingTableTimeout", "Timeout value for routing table in milliseconds", TimeValue(MilliSeconds(19000)),
                                        MakeTimeAccessor(&LSRoutingProtocol::m_routingTableTimeout), MakeTimeChecker())
                          .AddAttribute("RroadcastAdvTimeout", "Timeout value for BroadAdv in milliseconds", TimeValue(MilliSeconds(5000)),
                                        MakeTimeAccessor(&LSRoutingProtocol::m_broadcastAdvTimeout), MakeTimeChecker());
  return tid;
}

LSRoutingProtocol::LSRoutingProtocol()
    : m_auditPingsTimer(Timer::CANCEL_ON_DESTROY), m_auditHelloTimer(Timer::CANCEL_ON_DESTROY), m_broadcastHelloTimer(Timer::CANCEL_ON_DESTROY),
    m_broadcastAdvTimer(Timer::CANCEL_ON_DESTROY), m_routingTableTimer(Timer::CANCEL_ON_DESTROY)
{

  m_currentSequenceNumber = 0;
  // Setup static routing
  m_staticRouting = Create<Ipv4StaticRouting>();
}

LSRoutingProtocol::~LSRoutingProtocol() {}

void LSRoutingProtocol::DoDispose()
{
  if (m_recvSocket)
  {
    m_recvSocket->Close();
    m_recvSocket = 0;
  }

  // Close sockets
  for (std::map<Ptr<Socket>, Ipv4InterfaceAddress>::iterator iter = m_socketAddresses.begin();
       iter != m_socketAddresses.end(); iter++)
  {
    iter->first->Close();
  }
  m_socketAddresses.clear();

  // Clear static routing
  m_staticRouting = 0;

  // Cancel timers
  m_auditPingsTimer.Cancel();
  m_auditHelloTimer.Cancel();
  m_broadcastHelloTimer.Cancel();
  m_routingTableTimer.Cancel();
  m_broadcastAdvTimer.Cancel();
  m_pingTracker.clear();

  PennRoutingProtocol::DoDispose();
}

void LSRoutingProtocol::SetMainInterface(uint32_t mainInterface)
{
  m_mainAddress = m_ipv4->GetAddress(mainInterface, 0).GetLocal();
}

void LSRoutingProtocol::SetNodeAddressMap(std::map<uint32_t, Ipv4Address> nodeAddressMap)
{
  m_nodeAddressMap = nodeAddressMap;
}

void LSRoutingProtocol::SetAddressNodeMap(std::map<Ipv4Address, uint32_t> addressNodeMap)
{
  m_addressNodeMap = addressNodeMap;
}

Ipv4Address
LSRoutingProtocol::ResolveNodeIpAddress(uint32_t nodeNumber)
{
  std::map<uint32_t, Ipv4Address>::iterator iter = m_nodeAddressMap.find(nodeNumber);
  if (iter != m_nodeAddressMap.end())
  {
    return iter->second;
  }
  return Ipv4Address::GetAny();
}

std::string
LSRoutingProtocol::ReverseLookup(Ipv4Address ipAddress)
{
  std::map<Ipv4Address, uint32_t>::iterator iter = m_addressNodeMap.find(ipAddress);
  if (iter != m_addressNodeMap.end())
  {
    std::ostringstream sin;
    uint32_t nodeNumber = iter->second;
    sin << nodeNumber;
    return sin.str();
  }
  return "Unknown";
}

void LSRoutingProtocol::DoInitialize()
{

  if (m_mainAddress == Ipv4Address())
  {
    Ipv4Address loopback("127.0.0.1");
    for (uint32_t i = 0; i < m_ipv4->GetNInterfaces(); i++)
    {
      // Use primary address, if multiple
      Ipv4Address addr = m_ipv4->GetAddress(i, 0).GetLocal();
      if (addr != loopback)
      {
        m_mainAddress = addr;
        break;
      }
    }

    NS_ASSERT(m_mainAddress != Ipv4Address());
  }

  NS_LOG_DEBUG("Starting LS on node " << m_mainAddress);

  bool canRunLS = false;
  // Create sockets
  for (uint32_t i = 0; i < m_ipv4->GetNInterfaces(); i++)
  {
    Ipv4Address ipAddress = m_ipv4->GetAddress(i, 0).GetLocal();
    if (ipAddress == Ipv4Address::GetLoopback())
      continue;

    // Create a socket to listen on all the interfaces
    if (m_recvSocket == 0)
    {
      m_recvSocket = Socket::CreateSocket(GetObject<Node>(), UdpSocketFactory::GetTypeId());
      m_recvSocket->SetAllowBroadcast(true);
      InetSocketAddress inetAddr(Ipv4Address::GetAny(), LS_PORT_NUMBER);
      m_recvSocket->SetRecvCallback(MakeCallback(&LSRoutingProtocol::RecvLSMessage, this));
      if (m_recvSocket->Bind(inetAddr))
      {
        NS_FATAL_ERROR("Failed to bind() LS socket");
      }
      m_recvSocket->SetRecvPktInfo(true);
      m_recvSocket->ShutdownSend();
    }

    // Create socket on this interface
    Ptr<Socket> socket = Socket::CreateSocket(GetObject<Node>(), UdpSocketFactory::GetTypeId());
    socket->SetAllowBroadcast(true);
    InetSocketAddress inetAddr(m_ipv4->GetAddress(i, 0).GetLocal(), m_lsPort);
    socket->SetRecvCallback(MakeCallback(&LSRoutingProtocol::RecvLSMessage, this));
    if (socket->Bind(inetAddr))
    {
      NS_FATAL_ERROR("LSRoutingProtocol::DoInitialize::Failed to bind socket!");
    }
    socket->BindToNetDevice(m_ipv4->GetNetDevice(i));
    m_socketAddresses[socket] = m_ipv4->GetAddress(i, 0);
    canRunLS = true;
  }

  if (canRunLS)
  { 
    BroadcastHello();
    AuditPings();
    AuditNeighbors();
    LSAdvertisement();
    AuditRoutingTable();
    NS_LOG_DEBUG("Starting LS on node " << m_mainAddress);
  }
}

void LSRoutingProtocol::PrintRoutingTable(Ptr<OutputStreamWrapper> stream, Time::Unit unit) const
{
  // You can ignore this function
}

Ptr<Ipv4Route>
LSRoutingProtocol::RouteOutput(Ptr<Packet> packet, const Ipv4Header &header, Ptr<NetDevice> outInterface,
                               Socket::SocketErrno &sockerr)
{
  Ptr<Ipv4Route> ipv4Route = m_staticRouting->RouteOutput(packet, header, outInterface, sockerr);
  if (ipv4Route)
  {
    DEBUG_LOG("Found route to: " << ipv4Route->GetDestination() << " via next-hop: " << ipv4Route->GetGateway()
                                 << " with source: " << ipv4Route->GetSource() << " and output device "
                                 << ipv4Route->GetOutputDevice());
  }
  else
  {
    DEBUG_LOG("No Route to destination: " << header.GetDestination());
  }
  return ipv4Route;
}

bool LSRoutingProtocol::RouteInput(Ptr<const Packet> packet, const Ipv4Header &header, Ptr<const NetDevice> inputDev,
                                   UnicastForwardCallback ucb, MulticastForwardCallback mcb, LocalDeliverCallback lcb,
                                   ErrorCallback ecb)
{
  Ipv4Address destinationAddress = header.GetDestination();
  Ipv4Address sourceAddress = header.GetSource();

  // Drop if packet was originated by this node
  if (IsOwnAddress(sourceAddress) == true)
  {
    return true;
  }

  // Check for local delivery
  uint32_t interfaceNum = m_ipv4->GetInterfaceForDevice(inputDev);
  if (m_ipv4->IsDestinationAddress(destinationAddress, interfaceNum))
  {
    if (!lcb.IsNull())
    {
      lcb(packet, header, interfaceNum);
      return true;
    }
    else
    {
      return false;
    }
  }

  // Check static routing table
  if (m_staticRouting->RouteInput(packet, header, inputDev, ucb, mcb, lcb, ecb))
  {
    return true;
  }

  DEBUG_LOG("Cannot forward packet. No Route to destination: " << header.GetDestination());
  return false;
}

void LSRoutingProtocol::BroadcastPacket(Ptr<Packet> packet)
{
  for (std::map<Ptr<Socket>, Ipv4InterfaceAddress>::const_iterator i = m_socketAddresses.begin();
       i != m_socketAddresses.end(); i++)
  {
    Ptr<Packet> pkt = packet->Copy();
    Ipv4Address broadcastAddr = i->second.GetLocal().GetSubnetDirectedBroadcast(i->second.GetMask());
    i->first->SendTo(pkt, 0, InetSocketAddress(broadcastAddr, LS_PORT_NUMBER));
  }
}

void LSRoutingProtocol::ProcessCommand(std::vector<std::string> tokens)
{
  // std::cout << "hello how are you?" << std::endl;
  std::vector<std::string>::iterator iterator = tokens.begin();
  std::string command = *iterator;
  if (command == "PING")
  {
    if (tokens.size() < 3)
    {
      ERROR_LOG("Insufficient PING params...");
      return;
    }
    iterator++;
    std::istringstream sin(*iterator);
    uint32_t nodeNumber;
    sin >> nodeNumber;
    iterator++;
    std::string pingMessage = *iterator;
    Ipv4Address destAddress = ResolveNodeIpAddress(nodeNumber);
    // getany returns the 0.0.0.0
    if (destAddress != Ipv4Address::GetAny())
    {
      uint32_t sequenceNumber = GetNextSequenceNumber();
      TRAFFIC_LOG("Sending PING_REQ to Node: " << nodeNumber << " IP: " << destAddress << " Message: "
                                               << pingMessage << " SequenceNumber: " << sequenceNumber);
      Ptr<PingRequest> pingRequest = Create<PingRequest>(sequenceNumber, Simulator::Now(), destAddress, pingMessage);
      // Add to ping-tracker
      m_pingTracker.insert(std::make_pair(sequenceNumber, pingRequest));
      Ptr<Packet> packet = Create<Packet>();
      LSMessage lsMessage = LSMessage(LSMessage::PING_REQ, sequenceNumber, m_maxTTL, m_mainAddress);
      lsMessage.SetPingReq(destAddress, pingMessage);
      packet->AddHeader(lsMessage);
      BroadcastPacket(packet);
    }
  }
  else if (command == "DUMP")
  { 
    if (tokens.size() < 2)
    {
      ERROR_LOG("Insufficient Parameters!");
      return;
    }
    iterator++;
    std::string table = *iterator;
    if (table == "ROUTES" || table == "ROUTING")
    {
      DumpRoutingTable();
    }
    else if (table == "NEIGHBORS" || table == "neighborS")
    {
      DumpNeighbors();
    }
    else if (table == "LSA")
    {
      DumpLSA();
    }
  }
}

void LSRoutingProtocol::DumpLSA()
{
  STATUS_LOG(std::endl
             << "**************** LSA DUMP ********************" << std::endl
             << "Node\t\tNeighbor(s)");
  PRINT_LOG("");
}

void LSRoutingProtocol::DumpNeighbors()
{ 
 
  STATUS_LOG(std::endl
             << "**************** Neighbor List ********************" << std::endl
             << "NeighborNumber\t\tNeighborAddr\t\tInterfaceAddr");
             
  
  PRINT_LOG("");
  // std::cout << "here is : dump neighbors" << "the table size is: " << m_neighborTable.size() <<std::endl;
  std::ostringstream buffer;
  std::map<uint32_t, NeighborTableEntry>::iterator iter;
  for (iter = m_neighborTable.begin(); iter != m_neighborTable.end(); iter++) {
    checkNeighborTableEntry(iter->first, iter->second.neighborAddr, iter->second.interfaceAddr);
    buffer << iter->first << "\t\t\t" << iter->second.neighborAddr << "\t\t" << iter->second.interfaceAddr << std::endl;
  }
  // std::string neighborNum, Ipv4Address neighborAddr, Ipv4Address ifAddr
  PRINT_LOG(buffer.str());

  /* NOTE: For purpose of autograding, you should invoke the following function for each
  neighbor table entry. The output format is indicated by parameter name and type.
  */
   
}

void LSRoutingProtocol::DumpRoutingTable()
{
    
  STATUS_LOG(std::endl
             << "**************** Route Table ********************" << std::endl
             << "DestNumber\t\tDestAddr\t\tNextHopNumber\t\tNextHopAddr\t\tInterfaceAddr\t\tCost");

  std::ostringstream buffer;
  std::map<uint32_t, RoutingTableEntry>::iterator iter;
  for (iter = m_routingTable.begin(); iter != m_routingTable.end(); iter++) {
    if (iter->second.cost <= 16) {
      checkRouteTableEntry(iter->first, iter->second.destAddr, iter->second.nextHopNum, iter->second.nextHopAddr, iter->second.interfaceAddr, iter->second.cost);
      buffer << iter->first << "\t\t\t" << iter->second.destAddr << "\t\t" << iter->second.nextHopNum << "\t\t\t" << 
      iter->second.nextHopAddr << "\t\t" << iter->second.interfaceAddr << "\t\t" << iter->second.cost << std::endl;
    }
    
  }
  PRINT_LOG(buffer.str());

  /* NOTE: For purpose of autograding, you should invoke the following function for each
  routing table entry. The output format is indicated by parameter name and type.
  */
  //  checkNeighborTableEntry();
}
void LSRoutingProtocol::RecvLSMessage(Ptr<Socket> socket)
{
  Address sourceAddr;
  Ptr<Packet> packet = socket->RecvFrom(sourceAddr);
  LSMessage lsMessage;
  Ipv4PacketInfoTag interfaceInfo;
  if (!packet->RemovePacketTag(interfaceInfo))
  {
    NS_ABORT_MSG("No incoming interface on OLSR message, aborting.");
  }
  //"if" is interface
  uint32_t incomingIf = interfaceInfo.GetRecvIf();
  // std::cout << "incomingIf is: " << incomingIf << std::endl;
  if (!packet->RemoveHeader(lsMessage))
  {
    NS_ABORT_MSG("No incoming interface on LS message, aborting.");
  }

  Ipv4Address interface;
  // std::cout << "interface original is: " << interface << std::endl;
  uint32_t idx = 1;
  for (std::map<Ptr<Socket>, Ipv4InterfaceAddress>::iterator iter = m_socketAddresses.begin();
       iter != m_socketAddresses.end(); iter++)
  {
    if (idx == incomingIf)
    {
      interface = iter->second.GetLocal(); // find the incoming interface
      // std::cout << "interface address is: " << iter->second << std::endl;
      // std::cout << "interface now is: " << interface << std::endl;;
      break;
    }
    idx++;
  }

  switch (lsMessage.GetMessageType())
  {
  case LSMessage::PING_REQ:
    ProcessPingReq(lsMessage);
    break;
  case LSMessage::PING_RSP:
    ProcessPingRsp(lsMessage);
    break;
  case LSMessage::HELLO_REQ:
    ProcessHelloReq(lsMessage);
    break;
  case LSMessage::HELLO_RSP:
    ProcessHelloRsp(lsMessage, interface);
    break;
  case LSMessage::ADV: {
    Ipv4Address ipaddr = lsMessage.GetOriginatorAddress();
    std::map<Ipv4Address, uint32_t>::iterator iter_LSP = m_validLSP.find(ipaddr);
    if (iter_LSP == m_validLSP.end()) {
      m_validLSP.insert(std::make_pair(ipaddr, lsMessage.GetSequenceNumber()));
      ProcessLSP(lsMessage, interface);
    }
    else if (iter_LSP->second != lsMessage.GetSequenceNumber()) {
      m_validLSP[ipaddr] = lsMessage.GetSequenceNumber();
      ProcessLSP(lsMessage, interface);
    }
  }
    break;
  default:
    ERROR_LOG("Unknown Message Type!");
    break;
  }
}

void LSRoutingProtocol::ProcessPingReq(LSMessage lsMessage)
{
  // Check destination address
  if (IsOwnAddress(lsMessage.GetPingReq().destinationAddress))
  {
    // Use reverse lookup for ease of debug
    std::string fromNode = ReverseLookup(lsMessage.GetOriginatorAddress());
    TRAFFIC_LOG("Received PING_REQ, From Node: " << fromNode
                                                 << ", Message: " << lsMessage.GetPingReq().pingMessage);
    // Send Ping Response
    LSMessage lsResp = LSMessage(LSMessage::PING_RSP, lsMessage.GetSequenceNumber(), m_maxTTL, m_mainAddress);
    lsResp.SetPingRsp(lsMessage.GetOriginatorAddress(), lsMessage.GetPingReq().pingMessage);
    Ptr<Packet> packet = Create<Packet>();
    packet->AddHeader(lsResp);
    BroadcastPacket(packet);
  }
}


void LSRoutingProtocol::ProcessPingRsp(LSMessage lsMessage)
{
  // Check destination address
  if (IsOwnAddress(lsMessage.GetPingRsp().destinationAddress))
  {
    // Remove from pingTracker
    std::map<uint32_t, Ptr<PingRequest>>::iterator iter;
    iter = m_pingTracker.find(lsMessage.GetSequenceNumber());
    if (iter != m_pingTracker.end())
    {
      std::string fromNode = ReverseLookup(lsMessage.GetOriginatorAddress());
      TRAFFIC_LOG("Received PING_RSP, From Node: " << fromNode
                                                   << ", Message: " << lsMessage.GetPingRsp().pingMessage);
      m_pingTracker.erase(iter);
    }
    else
    {
      DEBUG_LOG("Received invalid PING_RSP!");
    }
  }
}

void LSRoutingProtocol::ProcessHelloReq(LSMessage lsMessage)
{
  // Check destination address
  
  
  // Use reverse lookup for ease of debug
  std::string fromNode = ReverseLookup(lsMessage.GetOriginatorAddress());
  TRAFFIC_LOG("Received HELLO_REQ, From Node: " << fromNode
                                                 << ", Message: " << lsMessage.GetHelloReq().helloMessage);
  // Send Hello Response
  uint32_t TTL = 1;
  LSMessage lsResp = LSMessage(LSMessage::HELLO_RSP, lsMessage.GetSequenceNumber(), TTL, m_mainAddress);
  lsResp.SetHelloRsp(lsMessage.GetOriginatorAddress(), "hello reply");
  Ptr<Packet> packet = Create<Packet>();
  packet->AddHeader(lsResp);
  BroadcastPacket(packet);
  
}

void LSRoutingProtocol::ProcessHelloRsp(LSMessage lsMessage, Ipv4Address interface)
{
  // Check destination address
  if (IsOwnAddress(lsMessage.GetHelloRsp().destinationAddress))
  {
    std::string fromNode = ReverseLookup(lsMessage.GetOriginatorAddress());
    TRAFFIC_LOG("Received HELLO_Rsp, From Node: " << fromNode
                                                  << ", Message: " << lsMessage.GetHelloRsp().helloMessage);
  
    uint16_t nodeNumber = 0;
    Ipv4Address ipAddress = lsMessage.GetOriginatorAddress();
      
    std::map<Ipv4Address, uint32_t>::iterator iterNode = m_addressNodeMap.find(ipAddress);
    if (iterNode != m_addressNodeMap.end())
    {
      nodeNumber = iterNode->second;
    }
          
    NeighborTableEntry entry;
    entry.neighborAddr = ipAddress;
    entry.interfaceAddr = interface;
    entry.m_timestamp = Simulator::Now();
      
    std::map<uint32_t, NeighborTableEntry>::iterator iterNeighbor = m_neighborTable.find(nodeNumber);
    if (iterNeighbor == m_neighborTable.end()) {
      m_neighborTable.insert(std::make_pair(nodeNumber, entry));
      // std::cout << "m_neighborTable size: " << m_neighborTable.size()<< std::endl;
    }
    else {
      m_neighborTable[nodeNumber] = entry;
    }
  }
  
}

void LSRoutingProtocol::InitializeNeighbors() {
}

void LSRoutingProtocol::Flood(Ptr<Packet> packet, Ipv4Address interface)
{
  // std::cout << "+++++++++++++++++++" << std::endl;
  // std::cout << "Run Flood..." << std::endl;
  for (std::map<Ptr<Socket>, Ipv4InterfaceAddress>::const_iterator iter = m_socketAddresses.begin();
       iter != m_socketAddresses.end(); iter++)
  {
    // std::cout << "socket interface: " << iter->second.GetLocal() << "\t receving interface: " << interface << ", and equal? " << (iter->second.GetLocal() == interface) << std::endl;
    if (iter->second.GetLocal() != interface)
    {
      Ptr<Packet> pkt = packet->Copy();
      Ipv4Address broadcastAddr = iter->second.GetLocal().GetSubnetDirectedBroadcast(iter->second.GetMask());
      iter->first->SendTo(pkt, 0, InetSocketAddress(broadcastAddr, LS_PORT_NUMBER));
      // std::cout << "sending to : " << broadcastAddr << " from " << m_mainAddress << std::endl;
    }
  }
}

void LSRoutingProtocol::ComputeRoutingTable()
{
  // Input: m_validLSP
  // Output: list of routing table entry should contain
  // 〈destination node number, destination IP address, next hop node number, next hop IP address, interface IP address, cost〉
  std::deque<uint32_t> queue;
  uint32_t selfNodeNum = m_addressNodeMap[m_mainAddress];
  std::map<uint32_t, uint32_t> cameFrom;
  // for (std::unordered_set<uint16_t> it = m_neighbors.begin(); it != m_neighbors.end(); it++) {
  //   cameFrom.insert(std::make_pair(*it, )
  // }
  queue.push_back(selfNodeNum);
  std::unordered_set<uint32_t> visited;
  uint32_t nextLevelSize = 1;
  uint32_t level = 0;
  uint32_t levelSize = 1;

  while(queue.size() > 0) {
    std::unordered_set<uint32_t>::iterator iter;
    
    nextLevelSize = 0;
    
    for (uint32_t i = 0; i < levelSize; i++) {
      uint32_t curNode = queue[0];
      std::unordered_set <uint32_t> neighbors = m_graph[curNode];
      queue.pop_front();
      for (std::unordered_set <uint32_t>::iterator iter = neighbors.begin(); iter != neighbors.end(); iter++) {
      if (visited.find(*iter) == visited.end()) {
        queue.push_back(*iter);
        visited.insert(*iter);
        nextLevelSize++;
        if (level > 1) {
          cameFrom.insert(std::make_pair(*iter, cameFrom[curNode]));
          RoutingTableEntry entry;
          entry.destAddr = m_nodeAddressMap[curNode];
          entry.nextHopNum = cameFrom[curNode];
          entry.nextHopAddr = m_nodeAddressMap[cameFrom[curNode]];
          entry.interfaceAddr = m_interfaces[cameFrom[curNode]];
          entry.cost = level;
          entry.timestamp = Simulator::Now();
          m_routingTable.insert(std::make_pair(i, entry));
        }
        else if (level == 1) {
          cameFrom.insert(std::make_pair(*iter, curNode));
          RoutingTableEntry entry;
          entry.destAddr = m_nodeAddressMap[curNode];
          entry.nextHopNum = curNode;
          entry.nextHopAddr = m_nodeAddressMap[curNode];
          entry.interfaceAddr = m_interfaces[curNode];
          entry.cost = level;
          entry.timestamp = Simulator::Now();
          m_routingTable.insert(std::make_pair(i, entry));
          }
      }
      levelSize = nextLevelSize;
      level++;
    }
      //need to pop the entry
    }
  }
}


void LSRoutingProtocol::LSAdvertisement() {
  uint32_t m_curNodeNum = m_addressNodeMap[m_mainAddress];
  for (std::map<uint32_t, Ipv4Address>::iterator iter =  m_nodeAddressMap.begin(); iter!= m_nodeAddressMap.end(); iter++) {
    std::map<uint32_t, NeighborTableEntry>::iterator iterNeighbor = m_neighborTable.find(iter->first);
    if (iterNeighbor != m_neighborTable.end()) {
      m_neighbors.insert(iter->first);
    }
    else if (iterNeighbor == m_neighborTable.end() && m_neighbors.find(iter->first) != m_neighbors.end()) {
      InitializeNeighbors();
      m_routingTable.clear();
    }
  }

  std::ostringstream out;
  for (uint32_t i : m_neighbors) {
    char c = i;
    out << c;
  }
  std::string neighbor_string(out.str());
  
  uint32_t sequenceNumber = GetNextSequenceNumber();
  Ptr<Packet> packet = Create<Packet>();
  uint32_t TTL = 16;
  LSMessage lsMessage = LSMessage(LSMessage::ADV, sequenceNumber, TTL, m_mainAddress);
  lsMessage.SetAdv(m_curNodeNum, neighbor_string, 1, 0);
  packet->AddHeader(lsMessage);
  BroadcastPacket(packet);
  m_broadcastAdvTimer.Schedule(m_broadcastAdvTimeout);

}


void LSRoutingProtocol::ProcessLSP(LSMessage lsMessage, Ipv4Address interface)
{
  //  std::cout << "current node: " << ReverseLookup(m_mainAddress) << std::endl;
  // std::cout << " In own dv the distance to node 0: " << m_distances[0];
  // std::cout << "     received packet from node: " << m_addressNodeMap[dvMessage.GetOriginatorAddress()] << std::endl;

  std::string neighbor_string = lsMessage.GetAdv().neighbors;
  std::unordered_set<uint32_t> neighbors;
  std::uint32_t nodeNum = lsMessage.GetAdv().nodeNum;
  std::uint32_t addedNeighbor = lsMessage.GetAdv().ifAdded;
  std::uint32_t removedNeighbor = lsMessage.GetAdv().ifRemoved;

  for (uint32_t i = 0; i < neighbor_string.length(); i++) {
    neighbors.insert(uint32_t(neighbor_string[i]));
  }

  // neighbors.insert(uint16_t(distance_string[i]));

  std::map<uint32_t, std::unordered_set<uint32_t>>::iterator iter = m_graph.find(nodeNum);
  if (iter == m_graph.end()) {
    m_graph.insert(std::make_pair(nodeNum, neighbors));
  }
  else {
    if (addedNeighbor == 1) {
      for (std::unordered_set<uint32_t>::iterator iterNeighbor = neighbors.begin(); iterNeighbor != neighbors.end(); iterNeighbor++) {
        if (m_graph[nodeNum].find(*iterNeighbor) == m_graph[nodeNum].end()) {
        m_graph[nodeNum].insert(*iterNeighbor);
        }
      }
    }
    else if (removedNeighbor == 1) {
      for (std::unordered_set<uint32_t>::iterator iterNeighbor2 = m_graph[nodeNum].begin(); iterNeighbor2 != m_graph[nodeNum].end(); iterNeighbor2++) {
        if (neighbors.find(*iterNeighbor2) == neighbors.end()){
          m_graph[nodeNum].erase(*iterNeighbor2);
        }
      }
    }

  }

  ComputeRoutingTable();  
  Ptr<Packet> packet = Create<Packet>();
  packet->AddHeader(lsMessage);
  Flood(packet, interface);
}





bool LSRoutingProtocol::IsOwnAddress(Ipv4Address originatorAddress)
{
  // Check all interfaces
  for (std::map<Ptr<Socket>, Ipv4InterfaceAddress>::const_iterator i = m_socketAddresses.begin();
       i != m_socketAddresses.end(); i++)
  {
    Ipv4InterfaceAddress interfaceAddr = i->second;
    if (originatorAddress == interfaceAddr.GetLocal())
    {
      return true;
    }
  }
  return false;
}

void LSRoutingProtocol::AuditPings()
{
  std::map<uint32_t, Ptr<PingRequest>>::iterator iter;
  for (iter = m_pingTracker.begin(); iter != m_pingTracker.end();)
  {
    
    Ptr<PingRequest> pingRequest = iter->second;

    if (pingRequest->GetTimestamp().GetMilliSeconds() + m_pingTimeout.GetMilliSeconds() <= Simulator::Now().GetMilliSeconds())
    {
      DEBUG_LOG("Ping expired. Message: " << pingRequest->GetPingMessage()
                                          << " Timestamp: " << pingRequest->GetTimestamp().GetMilliSeconds()
                                          << " CurrentTime: " << Simulator::Now().GetMilliSeconds());
      // Remove stale entries
      m_pingTracker.erase(iter++);
    }
    else
    {
      ++iter;
    }
  }
  // Rechedule timer
  m_auditPingsTimer.Schedule(m_pingTimeout);
}

void LSRoutingProtocol::BroadcastHello()
{
    std::string helloMessage = "hello";
    ////// get any  returns the 0.0.0.0
    
    uint32_t sequenceNumber = GetNextSequenceNumber();
    HelloRequest helloRequest;
    helloRequest.m_timestamp = Simulator::Now();
    helloRequest.m_sequenceNumber = sequenceNumber;
    helloRequest.m_helloMessage = "Hello!";

    Ptr<Packet> packet = Create<Packet>();
    uint32_t TTL = 1;
    LSMessage lsMessage = LSMessage(LSMessage::HELLO_REQ, sequenceNumber, TTL, m_mainAddress);
    lsMessage.SetHelloReq(helloMessage);
    packet->AddHeader(lsMessage);
    // std::cout << "herereereeeeeeeeeeeeeeeeeeeee";
    BroadcastPacket(packet);
    m_broadcastHelloTimer.Schedule(m_broadcastHelloTimeout);

}



void LSRoutingProtocol::AuditNeighbors()
{
  // std::map<uint32_t, Ptr<PingRequest>>::iterator iter;
  // std::cout << "how many times" << std::endl;
  // std::cout << "now " << Simulator::Now().GetMilliSeconds() << std::endl;

  
  std::map<uint32_t, NeighborTableEntry>::iterator iter;
  for (iter = m_neighborTable.begin(); iter != m_neighborTable.end();)
  {
    NeighborTableEntry neighborEntry = iter->second;
    // std::cout << "Timestamp: " << neighborEntry.m_timestamp.GetMilliSeconds() << std::endl;
    // std::cout << "m_helloTimeout: " << m_helloTimeout.GetMilliSeconds() << std::endl;
    // std::cout << "now " << Simulator::Now().GetMilliSeconds() << std::endl;
    
    if (neighborEntry.m_timestamp.GetMilliSeconds() + m_helloTimeout.GetMilliSeconds() <= Simulator::Now().GetMilliSeconds())
    {
      // DEBUG_LOG("Ping expired. Message: " << pingRequest->GetPingMessage()
      //                                     << " Timestamp: " << pingRequest->GetTimestamp().GetMilliSeconds()
      //                                     << " CurrentTime: " << Simulator::Now().GetMilliSeconds());
      // Remove stale entries

      m_neighborTable.erase(iter++);
      // std::cout << "removed neighbor entry here" << std::endl;
    }
    else
    {
      ++iter;
    }
  }
  // Rechedule timer
  m_auditHelloTimer.Schedule(m_helloTimeout);
}

void LSRoutingProtocol::AuditRoutingTable()
{ 
  std::map<uint32_t, RoutingTableEntry>::iterator iter;
  for (iter = m_routingTable.begin(); iter != m_routingTable.end();)
  {
    RoutingTableEntry routingEntry = iter->second;
    if (routingEntry.timestamp.GetMilliSeconds() + m_routingTableTimeout.GetMilliSeconds() <= Simulator::Now().GetMilliSeconds())
    {
      m_routingTable.erase(iter++);
      // std::cout << "removed neighbor entry here" << std::endl;
    }
    else
    {
      ++iter;
    }
  }
  // Rechedule timer
  m_routingTableTimer.Schedule(m_routingTableTimeout);
}



uint32_t
LSRoutingProtocol::GetNextSequenceNumber()
{
  m_currentSequenceNumber = (m_currentSequenceNumber + 1) % (LS_MAX_SEQUENCE_NUMBER + 1);
  return m_currentSequenceNumber;
}

void LSRoutingProtocol::NotifyInterfaceUp(uint32_t i)
{
  m_staticRouting->NotifyInterfaceUp(i);
}
void LSRoutingProtocol::NotifyInterfaceDown(uint32_t i)
{
  m_staticRouting->NotifyInterfaceDown(i);
}
void LSRoutingProtocol::NotifyAddAddress(uint32_t interface, Ipv4InterfaceAddress address)
{
  m_staticRouting->NotifyAddAddress(interface, address);
}
void LSRoutingProtocol::NotifyRemoveAddress(uint32_t interface, Ipv4InterfaceAddress address)
{
  m_staticRouting->NotifyRemoveAddress(interface, address);
}

void LSRoutingProtocol::SetIpv4(Ptr<Ipv4> ipv4)
{
  NS_ASSERT(ipv4 != 0);
  NS_ASSERT(m_ipv4 == 0);
  NS_LOG_DEBUG("Created ls::RoutingProtocol");
  // Configure timers
  m_auditPingsTimer.SetFunction(&LSRoutingProtocol::AuditPings, this);
  m_auditHelloTimer.SetFunction(&LSRoutingProtocol::AuditNeighbors, this);
  m_broadcastHelloTimer.SetFunction(&LSRoutingProtocol::BroadcastHello, this);
  m_routingTableTimer.SetFunction(&LSRoutingProtocol::AuditRoutingTable, this);
  m_broadcastAdvTimer.SetFunction(&LSRoutingProtocol::LSAdvertisement, this);


  m_ipv4 = ipv4;
  m_staticRouting->SetIpv4(m_ipv4);
}