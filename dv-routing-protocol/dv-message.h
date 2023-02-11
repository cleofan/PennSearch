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

#ifndef DV_MESSAGE_H
#define DV_MESSAGE_H

#include "ns3/header.h"
#include "ns3/ipv4-address.h"
#include "ns3/packet.h"
#include "ns3/object.h"

#include <map>
#include <vector>
#include <unordered_set>

using namespace ns3;

#define IPV4_ADDRESS_SIZE 4

class DVMessage : public Header
{
  public:
    DVMessage ();
    virtual ~DVMessage ();


    enum MessageType
      {
        PING_REQ = 1,
        PING_RSP = 2,
        HELLO_REQ = 3,
        HELLO_RSP = 4,
        ADV = 5,
        PATHVEC = 6,
        // Define extra message types when needed       
      };

    DVMessage (DVMessage::MessageType messageType, uint32_t sequenceNumber, uint8_t ttl, Ipv4Address originatorAddress);

    /**
    *  \brief Sets message type
    *  \param messageType message type
    */
    void SetMessageType (MessageType messageType);

    /**
     *  \returns message type
     */
    MessageType GetMessageType () const;

    /**
     *  \brief Sets Sequence Number
     *  \param sequenceNumber Sequence Number of the request
     */
    void SetSequenceNumber (uint32_t sequenceNumber);

    /**
     *  \returns Sequence Number
     */
    uint32_t GetSequenceNumber () const;

    /**
     *  \brief Sets Originator IP Address
     *  \param originatorAddress Originator IPV4 address
     */
    void SetOriginatorAddress (Ipv4Address originatorAddress);

    /** 
     *  \returns Originator IPV4 address
     */
    Ipv4Address GetOriginatorAddress () const;

    /**
     *  \brief Sets Time To Live of the message 
     *  \param ttl TTL of the message
     */
    void SetTTL (uint8_t ttl);

    /** 
     *  \returns TTL of the message
     */
    uint8_t GetTTL () const;

  private:
    /**
     *  \cond
     */
    MessageType m_messageType;
    uint32_t m_sequenceNumber;
    Ipv4Address m_originatorAddress;
    uint8_t m_ttl;
    /**
     *  \endcond
     */
  public:
    static TypeId GetTypeId (void);
    virtual TypeId GetInstanceTypeId (void) const;
    void Print (std::ostream &os) const;
    uint32_t GetSerializedSize (void) const;
    void Serialize (Buffer::Iterator start) const;
    uint32_t Deserialize (Buffer::Iterator start);

    
    struct PingReq
      {
        void Print (std::ostream &os) const;
        uint32_t GetSerializedSize (void) const;
        void Serialize (Buffer::Iterator &start) const;
        uint32_t Deserialize (Buffer::Iterator &start);
        // Payload
        Ipv4Address destinationAddress;
        std::string pingMessage;
      };

    struct PingRsp
      {
        void Print (std::ostream &os) const;
        uint32_t GetSerializedSize (void) const;
        void Serialize (Buffer::Iterator &start) const;
        uint32_t Deserialize (Buffer::Iterator &start);
        // Payload
        Ipv4Address destinationAddress;
        std::string pingMessage;
      };

      
    struct HelloReq
      {
      void Print(std::ostream& os) const;
      uint32_t GetSerializedSize(void) const;
      void Serialize(Buffer::Iterator& start) const;
      uint32_t Deserialize(Buffer::Iterator& start);
      // Payload
      // Ipv4Address destinationAddress;
      std::string helloMessage;
      };

    struct HelloRsp
      {
      void Print(std::ostream& os) const;
      uint32_t GetSerializedSize(void) const;
      void Serialize(Buffer::Iterator& start) const;
      uint32_t Deserialize(Buffer::Iterator& start);
      // Payload
      Ipv4Address destinationAddress;
      std::string helloMessage;
      };
    
    struct Adv
    {
      void Print(std::ostream& os) const;
      uint32_t GetSerializedSize(void) const;
      void Serialize(Buffer::Iterator& start) const;
      uint32_t Deserialize(Buffer::Iterator& start);
      std::string distances;
    };

    struct PathVec
    {
      void Print(std::ostream& os) const;
      uint32_t GetSerializedSize(void) const;
      void Serialize(Buffer::Iterator& start) const;
      uint32_t Deserialize(Buffer::Iterator& start);
      std::vector<std::vector<uint8_t>> paths;
      std::vector<std::unordered_set<uint8_t>> pathsets;
      uint32_t totalSerializedSize;
    };



  private:
    struct
      {
        PingReq pingReq;
        PingRsp pingRsp;
        HelloReq helloReq;
        HelloRsp helloRsp;
        Adv distanceVec;
        PathVec pathVec;
      } m_message;
    
  public:
    /**
     *  \returns PingReq Struct
     */
    PingReq GetPingReq ();

    /**
     *  \brief Sets PingReq message params
     *  \param message Payload String
     */

    void SetPingReq (Ipv4Address destinationAddress, std::string message);

    /**
     * \returns PingRsp Struct
     */
    PingRsp GetPingRsp ();
    /**
     *  \brief Sets PingRsp message params
     *  \param message Payload String
     */
    void SetPingRsp (Ipv4Address destinationAddress, std::string message);

    HelloReq GetHelloReq();
    void SetHelloReq(std::string message);

    HelloRsp GetHelloRsp();
    void SetHelloRsp(Ipv4Address destinationAddress, std::string message);

    Adv GetAdv();
    void SetAdv(std::string arr);

    PathVec GetPathVec();
    void SetPathVec(std::vector<std::vector<uint8_t>> arr, uint32_t totalNumNodes);

}; // class DVMessage

static inline std::ostream& operator<< (std::ostream& os, const DVMessage& message)
{
  message.Print (os);
  return os;
}

#endif
