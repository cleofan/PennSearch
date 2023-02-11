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

#ifndef PENN_CHORD_MESSAGE_H
#define PENN_CHORD_MESSAGE_H

#include "ns3/header.h"
#include "ns3/ipv4-address.h"
#include "ns3/object.h"
#include "ns3/packet.h"

using namespace ns3;

#define IPV4_ADDRESS_SIZE 4

class PennChordMessage : public Header
{
  public:
    PennChordMessage ();
    virtual ~PennChordMessage ();

    enum MessageType
    {
      PING_REQ = 1,
      PING_RSP = 2,
      JOIN_REQ = 3,
      JOIN_RSP = 4,
      NOTIFY = 5,
      STABILIZE = 6,
      STABILIZE_RSP = 7,
      RINGSTATE = 8,
      LEAVE_NOTICE_SUCC = 9,
      LEAVE_NOTICE_PRED = 10,
      LOOKUP = 11,
      LOOKUP_RSP = 12,
      FIXFINGER = 13,
      FIXFINGER_RSP = 14,
      SEARCH_CONTACT =15,
      // Define extra message types when needed
    };

    PennChordMessage (PennChordMessage::MessageType messageType, uint32_t transactionId);

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
     *  \brief Sets Transaction Id
     *  \param transactionId Transaction Id of the request
     */
    void SetTransactionId (uint32_t transactionId);

    /**
     *  \returns Transaction Id
     */
    uint32_t GetTransactionId () const;

  private:
    /**
     *  \cond
     */
    MessageType m_messageType;
    uint32_t m_transactionId;
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
        std::string pingMessage;
      };

    struct PingRsp
      {
        void Print (std::ostream &os) const;
        uint32_t GetSerializedSize (void) const;
        void Serialize (Buffer::Iterator &start) const;
        uint32_t Deserialize (Buffer::Iterator &start);
        // Payload
        std::string pingMessage;
      };

    
    struct JoinReq
      {
        void Print (std::ostream &os) const;
        uint32_t GetSerializedSize (void) const;
        void Serialize (Buffer::Iterator &start) const;
        uint32_t Deserialize (Buffer::Iterator &start);
        // Payload
        Ipv4Address originatorAddress;
      };

    struct JoinRsp
      {
        void Print (std::ostream &os) const;
        uint32_t GetSerializedSize (void) const;
        void Serialize (Buffer::Iterator &start) const;
        uint32_t Deserialize (Buffer::Iterator &start);
        // Payload
        Ipv4Address successorAddress;
      };

    struct Stabilize
      {
        void Print (std::ostream &os) const;
        uint32_t GetSerializedSize (void) const;
        void Serialize (Buffer::Iterator &start) const;
        uint32_t Deserialize (Buffer::Iterator &start);
        // Payload
        Ipv4Address curAddress;
      };
    
    struct StabilizeRsp
      {
        void Print (std::ostream &os) const;
        uint32_t GetSerializedSize (void) const;
        void Serialize (Buffer::Iterator &start) const;
        uint32_t Deserialize (Buffer::Iterator &start);
        // Payload
        Ipv4Address predAddress;
      };
    
    struct Notify
      {
        void Print (std::ostream &os) const;
        uint32_t GetSerializedSize (void) const;
        void Serialize (Buffer::Iterator &start) const;
        uint32_t Deserialize (Buffer::Iterator &start);
        // Payload
        Ipv4Address predecessorAddress;
      };

    struct LeaveNoticeSucc
      {
        void Print (std::ostream &os) const;
        uint32_t GetSerializedSize (void) const;
        void Serialize (Buffer::Iterator &start) const;
        uint32_t Deserialize (Buffer::Iterator &start);
        // Payload
        Ipv4Address predAddress;
        Ipv4Address curAddress;
      };
    struct LeaveNoticePred
      {
        void Print (std::ostream &os) const;
        uint32_t GetSerializedSize (void) const;
        void Serialize (Buffer::Iterator &start) const;
        uint32_t Deserialize (Buffer::Iterator &start);
        // Payload
        Ipv4Address curAddress;
        Ipv4Address succAddress;
      };

    struct RingState
      {
        void Print (std::ostream &os) const;
        uint32_t GetSerializedSize (void) const;
        void Serialize (Buffer::Iterator &start) const;
        uint32_t Deserialize (Buffer::Iterator &start);
        Ipv4Address originatorAddress;
        // Payload
      };

      struct FixFinger
      {
        void Print (std::ostream &os) const;
        uint32_t GetSerializedSize (void) const;
        void Serialize (Buffer::Iterator &start) const;
        uint32_t Deserialize (Buffer::Iterator &start);
        // Payload
        Ipv4Address originatorAddress;
        uint32_t number;
      };

      struct FixFingerRsp
      {
        void Print (std::ostream &os) const;
        uint32_t GetSerializedSize (void) const;
        void Serialize (Buffer::Iterator &start) const;
        uint32_t Deserialize (Buffer::Iterator &start);
        // Payload
        Ipv4Address successorAddress;
      };

      struct Lookup
      {
        void Print (std::ostream &os) const;
        uint32_t GetSerializedSize (void) const;
        void Serialize (Buffer::Iterator &start) const;
        uint32_t Deserialize (Buffer::Iterator &start);
        // Payload
        Ipv4Address originatorAddress;
        uint32_t idVal;
        uint8_t type;
      };

      struct LookupRsp
      {
        void Print (std::ostream &os) const;
        uint32_t GetSerializedSize (void) const;
        void Serialize (Buffer::Iterator &start) const;
        uint32_t Deserialize (Buffer::Iterator &start);
        
        // Payload
        Ipv4Address originatorAddress;
        uint8_t type;
        uint32_t idVal;
      };
      
      // struct SearchContact
      // {
      //   void Print (std::ostream &os) const;
      //   uint32_t GetSerializedSize (void) const;
      //   void Serialize (Buffer::Iterator &start) const;
      //   uint32_t Deserialize (Buffer::Iterator &start);
        
      //   // Payload
      //   std::vector<std::string> keywords;
      // };

  private:
    struct
      {
        PingReq pingReq;
        PingRsp pingRsp;
        JoinReq joinReq;
        JoinRsp joinRsp;
        Stabilize stabilize;
        StabilizeRsp stabilizeRsp;
        Notify notify;
        LeaveNoticeSucc leaveNoticeSucc;
        LeaveNoticePred leaveNoticePred;
        RingState ringState;
        FixFinger fixFinger;
        FixFingerRsp fixFingerRsp;
        Lookup lookup;
        LookupRsp lookupRsp;
      } m_message;
    // SearchContact searchContact;
  public:
    /**
     *  \returns PingReq Struct
     */
    PingReq GetPingReq ();

    /**
     *  \brief Sets PingReq message params
     *  \param message Payload String
     */

    void SetPingReq (std::string message);

    /**
     * \returns PingRsp Struct
     */
    PingRsp GetPingRsp ();
    /**
     *  \brief Sets PingRsp message params
     *  \param message Payload String
     */
    void SetPingRsp (std::string message);



    /**
     *  \returns JoinReq Struct
     */
    JoinReq GetJoinReq ();

    /**
     *  \brief Sets JoinReq message params
     *  \param message Payload String
     */

    void SetJoinReq (Ipv4Address targetAddress);

    /**
     * \returns JoinRsp Struct
     */
    JoinRsp GetJoinRsp ();
    /**
     *  \brief Sets JoinRsp message params
     *  \param message Payload successor address
     */
    void SetJoinRsp (Ipv4Address successorAddress);



    /**
     *  \returns Stabilize Struct
     */
    Stabilize GetStabilize ();

    /**
     *  \brief Sets stabilize message params
     *  \param message Payload String
     */

    void SetStabilize(Ipv4Address newAddress);


        /**
     *  \returns StabilizeRsp Struct
     */
    StabilizeRsp GetStabilizeRsp ();

    /**
     *  \brief Sets stabilizeRsp message params
     *  \param message Payload String
     */

    void SetStabilizeRsp(Ipv4Address pAddress);



    /**
     *  \returns Notify Struct
     */
    Notify GetNotify ();

    /**
     *  \brief Sets Notify message params
     *  \param message Payload String
     */

    void SetNotify (Ipv4Address targetAddress);

    /**
     * \returns Leave Struct
     */
    LeaveNoticeSucc GetLeaveNoticeSucc ();
    /**
     *  \brief Sets LeaveNoticeSucc message params
     *  \param message Payload successor address
     */
    void SetLeaveNoticeSucc (Ipv4Address nodePredAddress, Ipv4Address nodeAddress);


    /**
     * \returns Leave Struct
     */
    LeaveNoticePred GetLeaveNoticePred ();
    /**
     *  \brief Sets LeaveNoticePred message params
     *  \param message Payload successor address
     */
    void SetLeaveNoticePred (Ipv4Address nodeAddress, Ipv4Address nodeSuccAddress);


        /**
     *  \returns ringstate Struct
     */
    RingState GetRingState ();

    /**
     *  \brief Sets Notify message params
     *  \param message Payload String
     */

    void SetRingState (Ipv4Address targetAddress);

    /**
     * \returns Leave Struct
     */



    Lookup GetLookup ();
    void SetLookup (uint32_t hashKey, uint8_t type, Ipv4Address address);

    LookupRsp GetLookupRsp ();
    void SetLookupRsp (Ipv4Address address, uint8_t type, uint32_t idVal);

    FixFinger GetFixFinger ();
    void SetFixFinger (Ipv4Address address, uint32_t idVal);

    FixFingerRsp GetFixFingerRsp ();
    void SetFixFingerRsp (Ipv4Address targetAddress);

    // SearchContact GetSearchContact ();
    // void SetSearchContact (std::vector<std::string> keywords);

}; // class PennChordMessage

static inline std::ostream& operator<< (std::ostream& os, const PennChordMessage& message)
{
  message.Print (os);
  return os;
}

#endif
