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

#include "ns3/dv-routing-protocol.h"
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

#include <vector>
#include <ctime>
#include <unordered_set>

using namespace ns3;

NS_LOG_COMPONENT_DEFINE("DVRoutingProtocol");
NS_OBJECT_ENSURE_REGISTERED(DVRoutingProtocol);

#define DV_MAX_SEQUENCE_NUMBER 0xFFFF
#define DV_PORT_NUMBER 698

TypeId
DVRoutingProtocol::GetTypeId(void)
{
  static TypeId tid = TypeId("DVRoutingProtocol")
                          .SetParent<PennRoutingProtocol>()
                          .AddConstructor<DVRoutingProtocol>()
                          .AddAttribute("DVPort",
                                        "Listening port for DV packets",
                                        UintegerValue(5000),
                                        MakeUintegerAccessor(&DVRoutingProtocol::m_dvPort),
                                        MakeUintegerChecker<uint16_t>())
                          .AddAttribute("PingTimeout",
                                        "Timeout value for PING_REQ in milliseconds",
                                        TimeValue(MilliSeconds(2000)),
                                        MakeTimeAccessor(&DVRoutingProtocol::m_pingTimeout),
                                        MakeTimeChecker())
                          .AddAttribute("HelloTimeout",
                                        "Timeout value for HELLO_REQ in milliseconds",
                                        TimeValue(MilliSeconds(9000)),
                                        MakeTimeAccessor(&DVRoutingProtocol::m_helloTimeout),
                                        MakeTimeChecker())
                          .AddAttribute("BroadcastHelloTimeout",
                                        "Timeout value for BroadcastHello in milliseconds",
                                        TimeValue(MilliSeconds(7000)),
                                        MakeTimeAccessor(&DVRoutingProtocol::m_broadcastHelloTimeout),
                                        MakeTimeChecker())
                          
                          .AddAttribute("MaxTTL",
                                        "Maximum TTL value for DV packets",
                                        UintegerValue(16),
                                        MakeUintegerAccessor(&DVRoutingProtocol::m_maxTTL),
                                        MakeUintegerChecker<uint8_t>())
                          .AddAttribute("BroadcastPathAdvTimeout",
                                        "Timeout value for BroadAdv in milliseconds",
                                        TimeValue(MilliSeconds(5000)),
                                        MakeTimeAccessor(&DVRoutingProtocol::m_broadcastPathAdvTimeout),
                                        MakeTimeChecker())
                          .AddAttribute("RoutingPathTableTimeout",
                                        "Timeout value for HELLO_REQ in milliseconds",
                                        TimeValue(MilliSeconds(19000)),
                                        MakeTimeAccessor(&DVRoutingProtocol::m_routingPathTableTimeout),
                                        MakeTimeChecker());
  return tid;
}

DVRoutingProtocol::DVRoutingProtocol()
    : m_auditPingsTimer(Timer::CANCEL_ON_DESTROY), m_auditHelloTimer(Timer::CANCEL_ON_DESTROY), m_broadcastHelloTimer(Timer::CANCEL_ON_DESTROY), 
    m_broadcastPathAdvTimer(Timer::CANCEL_ON_DESTROY), m_routingPathTableTimer(Timer::CANCEL_ON_DESTROY)
{

  m_currentSequenceNumber = 0;
  // Setup static routing
  m_staticRouting = Create<Ipv4StaticRouting>();
}

DVRoutingProtocol::~DVRoutingProtocol()
{
}

void DVRoutingProtocol::DoDispose()
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
  m_broadcastPathAdvTimer.Cancel();
  m_routingPathTableTimer.Cancel();
  m_pingTracker.clear();

  PennRoutingProtocol::DoDispose();
}

void DVRoutingProtocol::SetMainInterface(uint32_t mainInterface)
{
  m_mainAddress = m_ipv4->GetAddress(mainInterface, 0).GetLocal();
}

void DVRoutingProtocol::SetNodeAddressMap(std::map<uint32_t, Ipv4Address> nodeAddressMap)
{
  m_nodeAddressMap = nodeAddressMap;
}

void DVRoutingProtocol::SetAddressNodeMap(std::map<Ipv4Address, uint32_t> addressNodeMap)
{
  m_addressNodeMap = addressNodeMap;
}

Ipv4Address
DVRoutingProtocol::ResolveNodeIpAddress(uint32_t nodeNumber)
{
  std::map<uint32_t, Ipv4Address>::iterator iter = m_nodeAddressMap.find(nodeNumber);
  if (iter != m_nodeAddressMap.end())
  {
    return iter->second;
  }
  return Ipv4Address::GetAny();
}

std::string
DVRoutingProtocol::ReverseLookup(Ipv4Address ipAddress)
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

void DVRoutingProtocol::DoInitialize()
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

  NS_LOG_DEBUG("Starting DV on node " << m_mainAddress);

  bool canRunDV = false;
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
      InetSocketAddress inetAddr(Ipv4Address::GetAny(), DV_PORT_NUMBER);
      m_recvSocket->SetRecvCallback(MakeCallback(&DVRoutingProtocol::RecvDVMessage, this));
      if (m_recvSocket->Bind(inetAddr))
      {
        NS_FATAL_ERROR("Failed to bind() DV socket");
      }
      m_recvSocket->SetRecvPktInfo(true);
      m_recvSocket->ShutdownSend();
    }

    // Create socket on this interface
    Ptr<Socket> socket = Socket::CreateSocket(GetObject<Node>(), UdpSocketFactory::GetTypeId());
    socket->SetAllowBroadcast(true);
    InetSocketAddress inetAddr(m_ipv4->GetAddress(i, 0).GetLocal(), m_dvPort);
    socket->SetRecvCallback(MakeCallback(&DVRoutingProtocol::RecvDVMessage, this));
    if (socket->Bind(inetAddr))
    {
      NS_FATAL_ERROR("DVRoutingProtocol::DoInitialize::Failed to bind socket!");
    }
    socket->BindToNetDevice(m_ipv4->GetNetDevice(i));
    m_socketAddresses[socket] = m_ipv4->GetAddress(i, 0);
    canRunDV = true;
  }

  if (canRunDV)
  { 
    // InitializeDV();
    InitializePathDV();
    BroadcastHello();
    AuditPings();
    AuditNeighbors();
    // DVAdvertisement();
    PathAdvertisement();
    // AuditRoutingTable();
    AuditRoutingPathTable();
    NS_LOG_DEBUG("Starting DV on node " << m_mainAddress);
  }
}

void DVRoutingProtocol::PrintRoutingTable(Ptr<OutputStreamWrapper> stream, Time::Unit unit) const
{
  // You can ignore this function
}

Ptr<Ipv4Route>
DVRoutingProtocol::RouteOutput(Ptr<Packet> packet, const Ipv4Header &header, Ptr<NetDevice> outInterface, Socket::SocketErrno &sockerr)
{
  Ptr<Ipv4Route> ipv4Route = m_staticRouting->RouteOutput(packet, header, outInterface, sockerr);
  if (ipv4Route)
  {
    DEBUG_LOG("Found route to: " << ipv4Route->GetDestination() << " via next-hop: " << ipv4Route->GetGateway() << " with source: " << ipv4Route->GetSource() << " and output device " << ipv4Route->GetOutputDevice());
  }
  else
  {
    DEBUG_LOG("No Route to destination: " << header.GetDestination());
  }
  return ipv4Route;
}

bool DVRoutingProtocol::RouteInput(Ptr<const Packet> packet,
                                   const Ipv4Header &header, Ptr<const NetDevice> inputDev,
                                   UnicastForwardCallback ucb, MulticastForwardCallback mcb,
                                   LocalDeliverCallback lcb, ErrorCallback ecb)
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

void DVRoutingProtocol::BroadcastPacket(Ptr<Packet> packet)
{
  for (std::map<Ptr<Socket>, Ipv4InterfaceAddress>::const_iterator i =
           m_socketAddresses.begin();
       i != m_socketAddresses.end(); i++)
  {
    Ptr<Packet> pkt = packet->Copy();
    Ipv4Address broadcastAddr = i->second.GetLocal().GetSubnetDirectedBroadcast(i->second.GetMask());
    i->first->SendTo(pkt, 0, InetSocketAddress(broadcastAddr, DV_PORT_NUMBER));
  }
}

void DVRoutingProtocol::ProcessCommand(std::vector<std::string> tokens)
{
  std::cout << "hererererererererereprocess command" << std::endl;
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
    if (destAddress != Ipv4Address::GetAny())
    {
      uint32_t sequenceNumber = GetNextSequenceNumber();
      TRAFFIC_LOG("Sending PING_REQ to Node: " << nodeNumber << " IP: " << destAddress << " Message: " << pingMessage << " SequenceNumber: " << sequenceNumber);
      Ptr<PingRequest> pingRequest = Create<PingRequest>(sequenceNumber, Simulator::Now(), destAddress, pingMessage);
      // Add to ping-tracker
      m_pingTracker.insert(std::make_pair(sequenceNumber, pingRequest));
      Ptr<Packet> packet = Create<Packet>();
      DVMessage dvMessage = DVMessage(DVMessage::PING_REQ, sequenceNumber, m_maxTTL, m_mainAddress);
      dvMessage.SetPingReq(destAddress, pingMessage);
      packet->AddHeader(dvMessage);
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
    else if (table == "NEIGHBORS" || table == "NEIGHBOURS")
    {
      DumpNeighbors();
    }
  }
}

void DVRoutingProtocol::DumpNeighbors()
{
  STATUS_LOG(std::endl
             << "**************** Neighbor List ********************" << std::endl
             << "NeighborNumber\t\tNeighborAddr\t\tInterfaceAddr");
  PRINT_LOG("");
  std::ostringstream buffer;
  std::map<uint32_t, NeighborTableEntry>::iterator iter;
  for (iter = m_neighborTable.begin(); iter != m_neighborTable.end(); iter++) {
    checkNeighborTableEntry(iter->first, iter->second.neighborAddr, iter->second.interfaceAddr);
    buffer << iter->first << "\t\t\t" << iter->second.neighborAddr << "\t\t" << iter->second.interfaceAddr << std::endl;
  }
  PRINT_LOG(buffer.str());

  /* NOTE: For purpose of autograding, you should invoke the following function for each
  neighbor table entry. The output format is indicated by parameter name and type.
  */
  //  checkNeighborTableEntry();
}

void DVRoutingProtocol::DumpRoutingTable()
{
  STATUS_LOG(std::endl
             << "**************** Route Table ********************" << std::endl
             << "DestNumber\t\tDestAddr\t\tNextHopNumber\t\tNextHopAddr\t\tInterfaceAddr\t\tPath");

  PRINT_LOG("");
  // std::cout << "routing table size: " << m_routingTable.size() << std::endl;
  std::ostringstream buffer;
  std::ostringstream out;
  std::map<uint32_t, RoutingTablePathEntry>::iterator iter;
  for (iter = m_routingPathTable.begin(); iter != m_routingPathTable.end(); iter++) {
    out.str("");
    out.clear();
    for (auto iterNode = iter->second.path.rbegin(); iterNode!= iter->second.path.rend(); iterNode++) {
      out << unsigned(*iterNode) << ",";
    }
    std::string path_string(out.str());
    // checkRouteTableEntry(iter->first, iter->second.destAddr, iter->second.nextHopNum, iter->second.nextHopAddr, iter->second.interfaceAddr, iter->second.cost);
    buffer << iter->first << "\t\t\t" << iter->second.destAddr << "\t\t" << iter->second.nextHopNum << "\t\t\t" << 
    iter->second.nextHopAddr << "\t\t" << iter->second.interfaceAddr << "\t\t" << path_string << std::endl;
  }
  
  // std::cout << "path to node 15 is: " << std:: endl;
  //   for (uint8_t i = 0; i < m_paths[15].size(); i++) {
  //   std::cout << unsigned(m_paths[15][i]) << "," ;
    
  // }
  // std::cout << std::endl;
  
  
  // for (uint32_t i = 0; i < m_distances.size(); i++) {
  //   std::cout << m_distances[i] << " ";
  // }  
  // std::cout << std::endl;
  PRINT_LOG(buffer.str());

  /* NOTE: For purpose of autograding, you should invoke the following function for each
  routing table entry. The output format is indicated by parameter name and type.
  */
  //  checkRouteTableEntry();
}

void DVRoutingProtocol::RecvDVMessage(Ptr<Socket> socket)
{
  Address sourceAddr;
  Ptr<Packet> packet = socket->RecvFrom(sourceAddr);
  DVMessage dvMessage;
  Ipv4PacketInfoTag interfaceInfo;
  if (!packet->RemovePacketTag(interfaceInfo))
  {
    NS_ABORT_MSG("No incoming interface on OLSR message, aborting.");
  }
  uint32_t incomingIf = interfaceInfo.GetRecvIf();

  if (!packet->RemoveHeader(dvMessage))
  {
    NS_ABORT_MSG("No incoming interface on DV message, aborting.");
  }

  Ipv4Address interface;
  uint32_t idx = 1;
  for (std::map<Ptr<Socket>, Ipv4InterfaceAddress>::iterator iter = m_socketAddresses.begin();
       iter != m_socketAddresses.end(); iter++)
  {
    if (idx == incomingIf)
    {
      interface = iter->second.GetLocal(); // find the incoming interface
      break;
    }
    idx++;
  }

  switch (dvMessage.GetMessageType())
  {
  case DVMessage::PING_REQ:
    ProcessPingReq(dvMessage);
    break;
  case DVMessage::PING_RSP:
    ProcessPingRsp(dvMessage);
    break;
  case DVMessage::HELLO_REQ:
    ProcessHelloReq(dvMessage);
    break;
  case DVMessage::HELLO_RSP:
    ProcessHelloRsp(dvMessage, interface);
    break;
  // case DVMessage::ADV: {
  //   Ipv4Address ipaddr = dvMessage.GetOriginatorAddress();
  //   std::map<Ipv4Address, uint32_t>::iterator iter_DVP = m_validDVP.find(ipaddr);
  //   if (iter_DVP == m_validDVP.end()) {
  //     m_validDVP.insert(std::make_pair(ipaddr, dvMessage.GetSequenceNumber()));
  //     ProcessDV(dvMessage, interface);
  //   }
  //   else if (iter_DVP->second != dvMessage.GetSequenceNumber()) {
  //     m_validDVP[ipaddr] = dvMessage.GetSequenceNumber();
  //     ProcessDV(dvMessage, interface);
  //   }
  //   break;
  //   }
  case DVMessage::PATHVEC: {
    Ipv4Address ipaddr = dvMessage.GetOriginatorAddress();
    std::map<Ipv4Address, uint32_t>::iterator iter_DVP = m_validPathDVP.find(ipaddr);
    if (iter_DVP == m_validPathDVP.end()) {
      m_validPathDVP.insert(std::make_pair(ipaddr, dvMessage.GetSequenceNumber()));
      ProcessPathAdv(dvMessage, interface);
    }
    else if (iter_DVP->second != dvMessage.GetSequenceNumber()) {
      m_validPathDVP[ipaddr] = dvMessage.GetSequenceNumber();
      ProcessPathAdv(dvMessage, interface);
    }
    break;
    }
  default:
    ERROR_LOG("Unknown Message Type!");
    break;
  }
}

void DVRoutingProtocol::ProcessPingReq(DVMessage dvMessage)
{
  // Check destination address
  if (IsOwnAddress(dvMessage.GetPingReq().destinationAddress))
  {
    // Use reverse lookup for ease of debug
    std::string fromNode = ReverseLookup(dvMessage.GetOriginatorAddress());
    TRAFFIC_LOG("Received PING_REQ, From Node: " << fromNode << ", Message: " << dvMessage.GetPingReq().pingMessage);
    // Send Ping Response
    DVMessage dvResp = DVMessage(DVMessage::PING_RSP, dvMessage.GetSequenceNumber(), m_maxTTL, m_mainAddress);
    dvResp.SetPingRsp(dvMessage.GetOriginatorAddress(), dvMessage.GetPingReq().pingMessage);
    Ptr<Packet> packet = Create<Packet>();
    packet->AddHeader(dvResp);
    BroadcastPacket(packet);
  }
  else {
    
  }
}

void DVRoutingProtocol::ProcessPingRsp(DVMessage dvMessage)
{
  // Check destination address
  if (IsOwnAddress(dvMessage.GetPingRsp().destinationAddress))
  {
    // Remove from pingTracker
    std::map<uint32_t, Ptr<PingRequest>>::iterator iter;
    iter = m_pingTracker.find(dvMessage.GetSequenceNumber());
    if (iter != m_pingTracker.end())
    {
      std::string fromNode = ReverseLookup(dvMessage.GetOriginatorAddress());
      TRAFFIC_LOG("Received PING_RSP, From Node: " << fromNode << ", Message: " << dvMessage.GetPingRsp().pingMessage);
      // DVAdvertisement();
      m_pingTracker.erase(iter);
    }
    else
    {
      DEBUG_LOG("Received invalid PING_RSP!");
    }
  }
}

void DVRoutingProtocol::ProcessHelloReq(DVMessage dvMessage)
{
  // Check destination address
  
  
  // Use reverse lookup for ease of debug
  std::string fromNode = ReverseLookup(dvMessage.GetOriginatorAddress());
  TRAFFIC_LOG("Received HELLO_REQ, From Node: " << fromNode
                                                 << ", Message: " << dvMessage.GetHelloReq().helloMessage);
  // Send Hello Response
  uint32_t TTL = 1;
  DVMessage dvResp = DVMessage(DVMessage::HELLO_RSP, dvMessage.GetSequenceNumber(), TTL, m_mainAddress);
  dvResp.SetHelloRsp(dvMessage.GetOriginatorAddress(), "hello reply");
  Ptr<Packet> packet = Create<Packet>();
  packet->AddHeader(dvResp);
  BroadcastPacket(packet);
  
}

void DVRoutingProtocol::ProcessHelloRsp(DVMessage dvMessage, Ipv4Address interface)
{
  // Check destination address
  if (IsOwnAddress(dvMessage.GetHelloRsp().destinationAddress))
  {
    std::string fromNode = ReverseLookup(dvMessage.GetOriginatorAddress());
    TRAFFIC_LOG("Received HELLO_Rsp, From Node: " << fromNode
                                                  << ", Message: " << dvMessage.GetHelloRsp().helloMessage);
  
    uint32_t nodeNumber = 0;
    Ipv4Address ipAddress = dvMessage.GetOriginatorAddress();
      
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
  // std::cout << "node " << ReverseLookup(m_mainAddress) << " neighbor size is in hellorsp:  " << m_neighborTable.size() << std::endl;
  }
  
  
}

// void DVRoutingProtocol::InitializeDV() {
//   m_distances.clear();
//   for (uint32_t i = 0; i < m_nodeAddressMap.size(); i++) {
//     m_distances.push_back(20);
//   }
// }


// void DVRoutingProtocol::DVAdvertisement() {
//   for (std::map<uint32_t, Ipv4Address>::iterator iter =  m_nodeAddressMap.begin(); iter!= m_nodeAddressMap.end(); iter++) {
//     std::map<uint32_t, NeighborTableEntry>::iterator iterNeighbor = m_neighborTable.find(iter->first);
//     if (iterNeighbor != m_neighborTable.end()) {
//       m_distances[iter->first] = 1;
//     }
//     else if (iterNeighbor == m_neighborTable.end() && m_distances[iter->first] == 1) {
//       InitializeDV();
//       m_routingTable.clear();
//     }
//     else if (m_mainAddress == iter->second) {
//       m_distances[iter->first] = 0;
//     }
//   }
  
//   std::ostringstream out;
//   for (uint32_t i : m_distances) {
//     char c = i;
//     out << c;
//   }
//   std::string distance_string(out.str());
  
//   uint32_t sequenceNumber = GetNextSequenceNumber();
//   Ptr<Packet> packet = Create<Packet>();
//   uint32_t TTL = 1;
//   DVMessage dvMessage = DVMessage(DVMessage::ADV, sequenceNumber, TTL, m_mainAddress);
//   dvMessage.SetAdv(distance_string);
//   packet->AddHeader(dvMessage);
//   BroadcastPacket(packet);
//   m_broadcastAdvTimer.Schedule(m_broadcastAdvTimeout);

// }


// void DVRoutingProtocol::ProcessDV(DVMessage dvMessage, Ipv4Address interface)
// {
//   //  std::cout << "current node: " << ReverseLookup(m_mainAddress) << std::endl;
//   // std::cout << " In own dv the distance to node 0: " << m_distances[0];
//   // std::cout << "     received packet from node: " << m_addressNodeMap[dvMessage.GetOriginatorAddress()] << std::endl;

//   std::string distance_string = dvMessage.GetAdv().distances;
//   std::vector<uint32_t> distances;
//   for (uint32_t i = 0; i < distance_string.length(); i++) {
//     distances.push_back(uint32_t(distance_string[i]));
//   }
//   for (uint32_t i = 0; i < distances.size(); i++) {
//     //i is the destination node number
//     uint32_t neighborNodeNum = m_addressNodeMap[dvMessage.GetOriginatorAddress()];
//     std::map<uint32_t, RoutingTableEntry>::iterator iterRouting = m_routingTable.find(i);
//     if (iterRouting == m_routingTable.end()) {
//       uint32_t newDistance = 1 + distances[i];
//       if (m_nodeAddressMap[i] != m_mainAddress && newDistance < 20) {
//               // std::cout << "added new distance: "  << newDistance << std::endl;
//         RoutingTableEntry entry;
//         entry.destAddr = m_nodeAddressMap[i];
//         entry.nextHopNum = neighborNodeNum;
//         entry.nextHopAddr = dvMessage.GetOriginatorAddress();
//         entry.interfaceAddr = interface;
//         entry.cost = newDistance;
//         entry.timestamp = Simulator::Now();
//         m_routingTable.insert(std::make_pair(i, entry));
//         m_distances[i] = newDistance;
//       }
//     }
//     else {
//       uint32_t newDistance = 1 + distances[i];
//       if (m_distances[i] > newDistance) {
//         // std::cout << " old distance in m_distances: " << m_distances[i] << std::endl;
//         // std::cout << " replaced by new distance: " << newDistance << std::endl;
//         m_distances[i] = newDistance;
//         RoutingTableEntry entry;
//         entry.destAddr = m_nodeAddressMap[i];
//         entry.nextHopNum = neighborNodeNum;
//         entry.nextHopAddr = dvMessage.GetOriginatorAddress();
//         entry.interfaceAddr = interface;
//         entry.cost = newDistance;
//         entry.timestamp = Simulator::Now();
//         m_routingTable[i] = entry;
//       }
//       else if (newDistance > m_distances[i] && m_routingTable[i].interfaceAddr == interface) {
//         std::map<uint32_t, RoutingTableEntry>::iterator iter = m_routingTable.find(i);
//         m_routingTable.erase(iter);
//         m_distances[i] = 20;
//       }
//       else if (m_distances[i] == newDistance && m_routingTable[i].interfaceAddr != interface ) {
//         // std::cout << " herere3 ";
//         // m_routingTable[i].timestamp = Simulator::Now();
//         m_distances[i] = newDistance;
//         RoutingTableEntry entry;
//         entry.destAddr = m_nodeAddressMap[i];
//         entry.nextHopNum = neighborNodeNum;
//         entry.nextHopAddr = dvMessage.GetOriginatorAddress();
//         entry.interfaceAddr = interface;
//         entry.cost = newDistance;
//         entry.timestamp = Simulator::Now();
//         m_routingTable[i] = entry;
//       }
//       else if (m_distances[i] == newDistance && m_routingTable[i].interfaceAddr == interface ){
//         m_routingTable[i].timestamp = Simulator::Now();
//       }
//     }
//   }

//   std::ostringstream out;
//   for (uint32_t i : m_distances) {
//     char c = i;
//     out << c;
//   }
//   std::string distance_string_new(out.str());
  
//   uint32_t TTL = 1;
//   DVMessage dvResp = DVMessage(DVMessage::ADV, dvMessage.GetSequenceNumber(), TTL, m_mainAddress);
//   dvResp.SetAdv(distance_string_new);
//   Ptr<Packet> packet = Create<Packet>();
//   packet->AddHeader(dvResp);
//   BroadcastPacket(packet);
// }

void DVRoutingProtocol::InitializePathDV() {
  uint32_t mainNodeNum = m_addressNodeMap[m_mainAddress];
  m_paths.clear();
  for (uint32_t i = 0; i < m_nodeAddressMap.size(); i++) {
    std::vector<uint8_t> path;
    if (mainNodeNum == i) {
      char num = mainNodeNum;
      m_mainNodeNum = uint8_t (num);
      path.push_back(m_mainNodeNum);
    }
    m_paths.push_back(path);
  }
}

void DVRoutingProtocol::PathAdvertisement() {
    
  for (std::map<uint32_t, Ipv4Address>::iterator iter =  m_nodeAddressMap.begin(); iter!= m_nodeAddressMap.end(); iter++) {
    std::map<uint32_t, NeighborTableEntry>::iterator iterNeighbor = m_neighborTable.find(iter->first);
    if (iterNeighbor != m_neighborTable.end()) {
      char node = iter->first;
      uint8_t nodeNum = uint8_t(node);
      m_paths[nodeNum].clear();
      m_paths[nodeNum].push_back(nodeNum);
      m_paths[nodeNum].push_back(m_mainNodeNum);
    }
    else if (iterNeighbor == m_neighborTable.end() && m_paths[iter->first].size() == 2) {
      // m_paths[iter->first].clear();
      InitializePathDV();
      m_routingPathTable.clear();
    }
  }
  uint32_t totalPathSize = 0;
  for (uint8_t j = 0; j < m_paths.size(); j++) {
    totalPathSize = totalPathSize + m_paths[j].size();
  }
  
  uint32_t sequenceNumber = GetNextSequenceNumber();
  Ptr<Packet> packet = Create<Packet>();
  uint32_t TTL = 1;
  DVMessage dvMessage = DVMessage(DVMessage::PATHVEC, sequenceNumber, TTL, m_mainAddress);
  dvMessage.SetPathVec(m_paths, totalPathSize);
  packet->AddHeader(dvMessage);
  BroadcastPacket(packet);
  m_broadcastPathAdvTimer.Schedule(m_broadcastPathAdvTimeout);
}

void DVRoutingProtocol::ProcessPathAdv(DVMessage dvMessage, Ipv4Address interface)
{
   std::vector<std::vector<uint8_t>> pathvec = dvMessage.GetPathVec().paths;
  std::vector<std::unordered_set<uint8_t>> pathset = dvMessage.GetPathVec().pathsets;
  uint32_t neighborNodeNum = m_addressNodeMap[dvMessage.GetOriginatorAddress()];
  uint32_t totalPathSize = 0;
  for (uint8_t i = 0; i < pathvec.size(); i++) {
    //i is the destination node number
    std::vector<uint8_t> newPath = pathvec[i];
    std::unordered_set<uint8_t> newSet = pathset[i];
    if (newSet.find(m_mainNodeNum) == newSet.end() && newPath.size() > 0) {
      std::map<uint32_t, RoutingTablePathEntry>::iterator iterRouting = m_routingPathTable.find(i);
      if (iterRouting == m_routingPathTable.end()) {
        newPath.push_back(m_mainNodeNum);
        RoutingTablePathEntry entry;
        entry.destAddr = m_nodeAddressMap[i];
        entry.nextHopNum = neighborNodeNum;
        entry.nextHopAddr = dvMessage.GetOriginatorAddress();
        entry.interfaceAddr = interface;
        entry.path = newPath;
        entry.timestamp = Simulator::Now();
        m_routingPathTable.insert(std::make_pair(i, entry));
        m_paths[i] = newPath;
      }
      else {
        newPath.push_back(m_mainNodeNum);
        if (m_paths[i].size() > newPath.size()) {
          m_paths[i] = newPath;
          RoutingTablePathEntry entry;
          entry.destAddr = m_nodeAddressMap[i];
          entry.nextHopNum = neighborNodeNum;
          entry.nextHopAddr = dvMessage.GetOriginatorAddress();
          entry.interfaceAddr = interface;
          entry.path = newPath;
          entry.timestamp = Simulator::Now();
          m_routingPathTable[i] = entry;
        }
        else if (m_paths[i].size() == newPath.size() && m_routingPathTable[i].interfaceAddr == interface ){
          m_routingPathTable[i].timestamp = Simulator::Now();
        }
      }
    }
    else if(m_paths[i].size() > 1 && m_routingPathTable[i].interfaceAddr == interface) {
      std::map<uint32_t, RoutingTablePathEntry>::iterator iter = m_routingPathTable.find(i);
      
      // std::cout << "detected at node " << unsigned(m_mainNodeNum) ;
      // std::cout << "sent from neighbor: " << unsigned(m_routingPathTable[i].nextHopNum) << std::endl;
      m_routingPathTable.erase(iter);
      m_paths[i].clear();
      // std::cout << "path size: " << m_paths[i].size() << "done" << std::endl;
    }
    
    
  }
  for (uint8_t j = 0; j < m_paths.size(); j++) {
    totalPathSize = totalPathSize + m_paths[j].size();
  }

  uint32_t TTL = 1;
  DVMessage dvResp = DVMessage(DVMessage::PATHVEC, dvMessage.GetSequenceNumber(), TTL, m_mainAddress);
  dvResp.SetPathVec(m_paths, totalPathSize);
  Ptr<Packet> packet = Create<Packet>();
  packet->AddHeader(dvResp);
  BroadcastPacket(packet);
}



bool DVRoutingProtocol::IsOwnAddress(Ipv4Address originatorAddress)
{
  // Check all interfaces
  for (std::map<Ptr<Socket>, Ipv4InterfaceAddress>::const_iterator i = m_socketAddresses.begin(); i != m_socketAddresses.end(); i++)
  {
    Ipv4InterfaceAddress interfaceAddr = i->second;
    if (originatorAddress == interfaceAddr.GetLocal())
    {
      return true;
    }
  }
  return false;
}

void DVRoutingProtocol::AuditPings()
{
  std::map<uint32_t, Ptr<PingRequest>>::iterator iter;
  for (iter = m_pingTracker.begin(); iter != m_pingTracker.end();)
  {
    Ptr<PingRequest> pingRequest = iter->second;
    if (pingRequest->GetTimestamp().GetMilliSeconds() + m_pingTimeout.GetMilliSeconds() <= Simulator::Now().GetMilliSeconds())
    {
      DEBUG_LOG("Ping expired. Message: " << pingRequest->GetPingMessage() << " Timestamp: " << pingRequest->GetTimestamp().GetMilliSeconds() << " CurrentTime: " << Simulator::Now().GetMilliSeconds());
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

void DVRoutingProtocol::BroadcastHello()
{
  // std::cout  << "broadcasthelllo invoked here at: " << Simulator::Now().GetSeconds() << std::endl;
  std::string helloMessage = "hello";
  ////// get any  returns the 0.0.0.0
    
  uint32_t sequenceNumber = GetNextSequenceNumber();


  Ptr<Packet> packet = Create<Packet>();
  uint32_t TTL = 1;
  DVMessage dvMessage = DVMessage(DVMessage::HELLO_REQ, sequenceNumber, TTL, m_mainAddress);
  dvMessage.SetHelloReq(helloMessage);
  packet->AddHeader(dvMessage);
  // std::cout << "in broascast hello time now is :" << Simulator::Now().GetSeconds() << std::endl;
  BroadcastPacket(packet);
  m_broadcastHelloTimer.Schedule(m_broadcastHelloTimeout);

}



void DVRoutingProtocol::AuditNeighbors()
{ 
  std::map<uint32_t, NeighborTableEntry>::iterator iter;
  for (iter = m_neighborTable.begin(); iter != m_neighborTable.end();)
  {
    NeighborTableEntry neighborEntry = iter->second;
    if (neighborEntry.m_timestamp.GetMilliSeconds() + m_helloTimeout.GetMilliSeconds() <= Simulator::Now().GetMilliSeconds())
    {
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

// void DVRoutingProtocol::AuditRoutingTable()
// { 
//   std::map<uint32_t, RoutingTableEntry>::iterator iter;
//   for (iter = m_routingTable.begin(); iter != m_routingTable.end();)
//   {
//     RoutingTableEntry routingEntry = iter->second;
//     if (routingEntry.timestamp.GetMilliSeconds() + m_routingTableTimeout.GetMilliSeconds() <= Simulator::Now().GetMilliSeconds())
//     {
//       m_routingTable.erase(iter++);
//       // std::cout << "removed neighbor entry here" << std::endl;
//     }
//     else
//     {
//       ++iter;
//     }
//   }
//   // Rechedule timer
//   m_routingTableTimer.Schedule(m_routingTableTimeout);
// }


void DVRoutingProtocol::AuditRoutingPathTable()
{ 
  std::map<uint32_t, RoutingTablePathEntry>::iterator iter;
  for (iter = m_routingPathTable.begin(); iter != m_routingPathTable.end();)
  {
    RoutingTablePathEntry routingEntry = iter->second;
    if (routingEntry.timestamp.GetMilliSeconds() + m_routingPathTableTimeout.GetMilliSeconds() <= Simulator::Now().GetMilliSeconds())
    {
      m_paths[iter->first].clear();
      m_routingPathTable.erase(iter++);
      // std::cout << "removed neighbor entry here" << std::endl;
    }
    else
    {
      ++iter;
    }
  }
  
  // Rechedule timer
  m_routingPathTableTimer.Schedule(m_routingPathTableTimeout);
}




uint32_t
DVRoutingProtocol::GetNextSequenceNumber()
{
  m_currentSequenceNumber = (m_currentSequenceNumber + 1) % (DV_MAX_SEQUENCE_NUMBER + 1);
  return m_currentSequenceNumber;
}

void DVRoutingProtocol::NotifyInterfaceUp(uint32_t i)
{
  m_staticRouting->NotifyInterfaceUp(i);
}
void DVRoutingProtocol::NotifyInterfaceDown(uint32_t i)
{
  m_staticRouting->NotifyInterfaceDown(i);
}
void DVRoutingProtocol::NotifyAddAddress(uint32_t interface, Ipv4InterfaceAddress address)
{
  m_staticRouting->NotifyAddAddress(interface, address);
}
void DVRoutingProtocol::NotifyRemoveAddress(uint32_t interface, Ipv4InterfaceAddress address)
{
  m_staticRouting->NotifyRemoveAddress(interface, address);
}

void DVRoutingProtocol::SetIpv4(Ptr<Ipv4> ipv4)
{
  NS_ASSERT(ipv4 != 0);
  NS_ASSERT(m_ipv4 == 0);
  NS_LOG_DEBUG("Created dv::RoutingProtocol");
  // Configure timers
  m_auditPingsTimer.SetFunction(&DVRoutingProtocol::AuditPings, this);
  m_auditHelloTimer.SetFunction(&DVRoutingProtocol::AuditNeighbors, this);
  m_broadcastHelloTimer.SetFunction(&DVRoutingProtocol::BroadcastHello, this);
  m_broadcastPathAdvTimer.SetFunction(&DVRoutingProtocol::PathAdvertisement, this);
  m_routingPathTableTimer.SetFunction(&DVRoutingProtocol::AuditRoutingPathTable, this);
  // m_broadcastAdvTimer.SetFunction(&DVRoutingProtocol::DVAdvertisement, this);
  

  m_ipv4 = ipv4;
  m_staticRouting->SetIpv4(m_ipv4);
}