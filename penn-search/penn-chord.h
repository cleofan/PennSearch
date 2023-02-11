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

#ifndef PENN_CHORD_H
#define PENN_CHORD_H

#include "ns3/penn-application.h"
#include "ns3/penn-chord-message.h"
#include "ns3/ping-request.h"
#include <openssl/sha.h>

#include "ns3/ipv4-address.h"
#include <map>
#include <set>
#include <vector>
#include <string>
#include "ns3/socket.h"
#include "ns3/nstime.h"
#include "ns3/timer.h"
#include "ns3/uinteger.h"
#include "ns3/boolean.h"
#include "ns3/penn-key-helper.h"

using namespace ns3;

class PennChord : public PennApplication
{
  public:

    static TypeId GetTypeId (void);
    PennChord ();
    virtual ~PennChord ();

    enum LookupType
    {
      PUBLISH_REQ = 1,
      SEARCH_REQ = 2,
      // Define extra message types when needed
    };
    void SendPing (Ipv4Address destAddress, std::string pingMessage);
    void RecvMessage (Ptr<Socket> socket);
    void ProcessPingReq (PennChordMessage message, Ipv4Address sourceAddress, uint16_t sourcePort);
    void ProcessPingRsp (PennChordMessage message, Ipv4Address sourceAddress, uint16_t sourcePort);
    void ProcessJoinReq (PennChordMessage message);
    void ProcessJoinRsp (PennChordMessage message);
    void ProcessStabilize (PennChordMessage message, Ipv4Address sourceAddress, uint16_t sourcePort);
    void ProcessStabilizeRsp (PennChordMessage message);
    void ProcessNotify(PennChordMessage message);
    void ProcessRingState (PennChordMessage message);
    void ProcessLeaveNoticeSucc (PennChordMessage message);
    void ProcessLeaveNoticePred (PennChordMessage message);
    void CreateChord ();
    void JoinChord (std::string target);
    void FindNodeSuccessor(std::string target);
    void HandleLeave ();
    void SendRingState(Ipv4Address originatorAddress);
    void Stabilize();

    void ForwardJoinReq (PennChordMessage message);
    void RspJoinReq (Ipv4Address newAddress, PennChordMessage message);
    void Contact (Ipv4Address destAddress, std::vector<std::string> keywords);
    void ProcessSearchContact (PennChordMessage message, Ipv4Address sourceAddress, uint16_t sourcePort);




    void AuditPings ();
    uint32_t GetNextTransactionId ();
    void StopChord ();

    // Callback with Application Layer (add more when required)
    void SetPingSuccessCallback (Callback <void, Ipv4Address, std::string> pingSuccessFn);
    void SetPingFailureCallback (Callback <void, Ipv4Address, std::string> pingFailureFn);
    void SetPingRecvCallback (Callback <void, Ipv4Address, std::string> pingRecvFn);
    void SetLookupSuccessCallback(Callback <void, Ipv4Address, LookupType, uint32_t> lookupSuccessFn);

    // From PennApplication
    virtual void ProcessCommand (std::vector<std::string> tokens);

    void Lookup(std::string key, LookupType type, uint32_t transId);
    void ProcessLookupRsp(PennChordMessage message, Ipv4Address sourceAddress, uint16_t sourcePort);
    void FixFingers();
    void ProcessFixFingerRsp(PennChordMessage message);
    void ProcessFixFinger(PennChordMessage message);
    void FindSuccessor(uint32_t idVal, PennChordMessage message);
    Ipv4Address ClosestPrecedingNode(uint32_t idVal);
    bool InRange(uint32_t id, uint32_t n, uint32_t successor);
    void ProcessLookup(PennChordMessage message);
    void InitializeFingerTable();

    
  protected:
    virtual void DoDispose ();
    
  private:
    virtual void StartApplication (void);
    virtual void StopApplication (void);


    uint32_t m_currentTransactionId;
    Ptr<Socket> m_socket;
    Time m_pingTimeout;
    Time m_stabilizeTimeout;
    Time m_fixFingerTimeout;
    uint16_t m_appPort;

    Ipv4Address m_successorAddress;
    Ipv4Address m_predecessorAddress;
    // Timers
    Timer m_auditPingsTimer;
    Timer m_stabilizeTimer;
    Timer m_fixFingerTimer;
    
    // Ping tracker
    std::map<uint32_t, Ptr<PingRequest> > m_pingTracker;

    // Callbacks
    Callback <void, Ipv4Address, std::string> m_pingSuccessFn;
    Callback <void, Ipv4Address, std::string> m_pingFailureFn;
    Callback <void, Ipv4Address, std::string> m_pingRecvFn;
    Callback <void, Ipv4Address, LookupType, uint32_t> m_lookupSuccessFn;

    //finger table
    std::vector<Ipv4Address> m_fingerTable;

    //finger table index
    uint32_t m_next;

    //node ipaddress
    Ipv4Address m_address;

    //node hash value
    uint32_t m_value;

    //cur node ID
    std::string m_node;


    
};

#endif


