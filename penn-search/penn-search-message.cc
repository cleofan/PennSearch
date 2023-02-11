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

#include "ns3/penn-search-message.h"
#include "ns3/log.h"


using namespace ns3;

NS_LOG_COMPONENT_DEFINE ("PennSearchMessage");
NS_OBJECT_ENSURE_REGISTERED (PennSearchMessage);

PennSearchMessage::PennSearchMessage ()
{
}

PennSearchMessage::~PennSearchMessage ()
{
}

PennSearchMessage::PennSearchMessage (PennSearchMessage::MessageType messageType, uint32_t transactionId)
{
  m_messageType = messageType;
  m_transactionId = transactionId;
}

TypeId 
PennSearchMessage::GetTypeId (void)
{
  static TypeId tid = TypeId ("PennSearchMessage")
    .SetParent<Header> ()
    .AddConstructor<PennSearchMessage> ()
  ;
  return tid;
}

TypeId
PennSearchMessage::GetInstanceTypeId (void) const
{
  return GetTypeId ();
}


uint32_t
PennSearchMessage::GetSerializedSize (void) const
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
      case PUBLISH_REQ:
        size += m_message.publishReq.GetSerializedSize();
        break;
      case SEARCH_REQ:
        size += m_message.searchReq.GetSerializedSize();
        break;
      case SEARCH_RSP:
        size += m_message.searchRsp.GetSerializedSize();
        break;
      case SEARCH_CONTACT:
        size += m_message.searchContact.GetSerializedSize();
        break;
      default:
        NS_ASSERT (false);
    }
  return size;
}

void
PennSearchMessage::Print (std::ostream &os) const
{
  os << "\n****PennSearchMessage Dump****\n" ;
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
      case PUBLISH_REQ:
        m_message.publishReq.Print(os);
        break;
      case SEARCH_REQ:
        m_message.searchReq.Print(os);
        break;
      case SEARCH_RSP:
        m_message.searchRsp.Print(os);
        break;
      case SEARCH_CONTACT:
        m_message.searchContact.Print(os);
        break;
      default:
        break;  
    }
  os << "\n****END OF MESSAGE****\n";
}

void
PennSearchMessage::Serialize (Buffer::Iterator start) const
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
      case PUBLISH_REQ:
        m_message.publishReq.Serialize (i);
        break;
      case SEARCH_REQ:
        m_message.searchReq.Serialize (i);
        break;
      case SEARCH_RSP:
        m_message.searchRsp.Serialize (i);
        break;
      case SEARCH_CONTACT:
        m_message.searchContact.Serialize (i);
        break;
      default:
        NS_ASSERT (false);   
    }
}

uint32_t 
PennSearchMessage::Deserialize (Buffer::Iterator start)
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
      case PUBLISH_REQ:
        size += m_message.publishReq.Deserialize (i);
        break;
      case SEARCH_REQ:
        size += m_message.searchReq.Deserialize (i);
        break;
      case SEARCH_RSP:
        size += m_message.searchRsp.Deserialize (i);
        break;
      case SEARCH_CONTACT:
        size += m_message.searchContact.Deserialize (i);
        break;
      default:
        NS_ASSERT (false);
    }
  return size;
}

/* PING_REQ */

uint32_t 
PennSearchMessage::PingReq::GetSerializedSize (void) const
{
  uint32_t size;
  size = sizeof(uint16_t) + pingMessage.length();
  return size;
}

void
PennSearchMessage::PingReq::Print (std::ostream &os) const
{
  os << "PingReq:: Message: " << pingMessage << "\n";
}

void
PennSearchMessage::PingReq::Serialize (Buffer::Iterator &start) const
{
  start.WriteU16 (pingMessage.length ());
  start.Write ((uint8_t *) (const_cast<char*> (pingMessage.c_str())), pingMessage.length());
}

uint32_t
PennSearchMessage::PingReq::Deserialize (Buffer::Iterator &start)
{  
  uint16_t length = start.ReadU16 ();
  char* str = (char*) malloc (length);
  start.Read ((uint8_t*)str, length);
  pingMessage = std::string (str, length);
  free (str);
  return PingReq::GetSerializedSize ();
}

void
PennSearchMessage::SetPingReq (std::string pingMessage)
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

PennSearchMessage::PingReq
PennSearchMessage::GetPingReq ()
{
  return m_message.pingReq;
}

/* PING_RSP */

uint32_t 
PennSearchMessage::PingRsp::GetSerializedSize (void) const
{
  uint32_t size;
  size = sizeof(uint16_t) + pingMessage.length();
  return size;
}

void
PennSearchMessage::PingRsp::Print (std::ostream &os) const
{
  os << "PingReq:: Message: " << pingMessage << "\n";
}

void
PennSearchMessage::PingRsp::Serialize (Buffer::Iterator &start) const
{
  start.WriteU16 (pingMessage.length ());
  start.Write ((uint8_t *) (const_cast<char*> (pingMessage.c_str())), pingMessage.length());
}

uint32_t
PennSearchMessage::PingRsp::Deserialize (Buffer::Iterator &start)
{  
  uint16_t length = start.ReadU16 ();
  char* str = (char*) malloc (length);
  start.Read ((uint8_t*)str, length);
  pingMessage = std::string (str, length);
  free (str);
  return PingRsp::GetSerializedSize ();
}

void
PennSearchMessage::SetPingRsp (std::string pingMessage)
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

PennSearchMessage::PingRsp
PennSearchMessage::GetPingRsp ()
{
  return m_message.pingRsp;
}


//
//
//

/* PUBLISH_REQ */
uint32_t 
PennSearchMessage::PublishReq::GetSerializedSize (void) const
{
  uint32_t size;
  uint32_t charNum = 0;
  for (auto iter = values.begin(); iter != values.end(); iter++) {
    charNum += (*iter).length();
  }
  size = sizeof(uint32_t) + key.length() + sizeof(uint32_t) + 
  values.size() * sizeof(uint32_t) + charNum;
  return size;
}

void
PennSearchMessage::PublishReq::Print (std::ostream &os) const
{
  os << "PublishReq:: Keyword: " << key << "\n";
}

void
PennSearchMessage::PublishReq::Serialize (Buffer::Iterator &start) const
{
  start.WriteU32 (key.length());
  // std::cout << "in serialize publish req: " << key << std::endl;
  start.Write ((uint8_t *) (const_cast<char*> (key.c_str())), key.length());
  start.WriteU32 (values.size());
  for (auto iter = values.begin(); iter != values.end(); iter++) {
    // std::cout << *iter << std::endl;
    start.WriteU32 ((*iter).size());
    start.Write ((uint8_t *) (const_cast<char*> ((*iter).c_str())), (*iter).length());
  }
}

uint32_t
PennSearchMessage::PublishReq::Deserialize (Buffer::Iterator &start)
{ 
  // std::cout << "in deserialize !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!" << std::endl;
  uint32_t keyLength = start.ReadU32 ();
  char* str = (char*) malloc (keyLength);
  start.Read ((uint8_t*)str, keyLength);
  key = std::string (str, keyLength);
  // std::cout << "in deserialize publish!!!!!!!!!!!!!!!" << key << std::endl;
  free (str);
  uint32_t setSize = start.ReadU32 ();
  for (uint32_t i = 0; i < setSize; i++) {
    uint32_t strLength = start.ReadU32 ();
    char* str2 = (char*) malloc (strLength);
    start.Read ((uint8_t*)str2, strLength);
    values.insert(std::string (str2, strLength));
    // std::cout << str2 << std::endl;
    free (str2); 
  }
  return PublishReq::GetSerializedSize ();
}

void
PennSearchMessage::SetPublishReq (std::string key, std::set<std::string> values)
{
  if (m_messageType == 0)
    {
      m_messageType = PUBLISH_REQ;
    }
  else
    {
      NS_ASSERT (m_messageType == PUBLISH_REQ);
    }
  m_message.publishReq.key = key;
  m_message.publishReq.values = values;
}

PennSearchMessage::PublishReq
PennSearchMessage::GetPublishReq ()
{
  return m_message.publishReq;
}

/*Search Req*/
uint32_t 
PennSearchMessage::SearchReq::GetSerializedSize (void) const
{
  uint32_t size;
  uint32_t charNum = 0;
  for (auto iter = keywords.begin(); iter != keywords.end(); iter++) {
    charNum += (*iter).length();
  }
  uint32_t charNumSet = 0;
   for (auto iterSet = obtainedResult.begin(); iterSet != obtainedResult.end(); iterSet++) {
    charNumSet += (*iterSet).length();
  }
  size = sizeof(uint32_t) + sizeof(uint32_t) +
  keywords.size() * sizeof(uint32_t) + charNum + 
  IPV4_ADDRESS_SIZE + sizeof(uint32_t) + 
  obtainedResult.size() * sizeof (uint32_t) + charNumSet;
  
  return size;
  // return 500;

}

void
PennSearchMessage::SearchReq::Print (std::ostream &os) const
{
  os << "PublishReq:: Keyword number: " << keyNumber << "\n";
}

void
PennSearchMessage::SearchReq::Serialize (Buffer::Iterator &start) const
{
  start.WriteHtonU32 (originatorAddress.Get ());
  start.WriteU32 (keyNumber);
  start.WriteU32 (keywords.size());
  for (auto iter = keywords.begin(); iter != keywords.end(); iter++) {
    start.WriteU32 ((*iter).size());
    start.Write ((uint8_t *) (const_cast<char*> ((*iter).c_str())), (*iter).length());
  }
  start.WriteU32 (obtainedResult.size());
  for (auto iter2 = obtainedResult.begin(); iter2 != obtainedResult.end(); iter2++) {
    start.WriteU32 ((*iter2).size());
    start.Write ((uint8_t *) (const_cast<char*> ((*iter2).c_str())), (*iter2).length());
  }
}

uint32_t
PennSearchMessage::SearchReq::Deserialize (Buffer::Iterator &start)
{  
  originatorAddress = Ipv4Address (start.ReadNtohU32 ());
  keyNumber = start.ReadU32();
  uint32_t keySize = start.ReadU32 ();
  for (uint32_t i = 0; i < keySize; i++) {
    uint32_t strLength = start.ReadU32 ();
    char* str = (char*) malloc (strLength);
    start.Read ((uint8_t*)str, strLength);
    keywords.push_back(std::string (str, strLength));
    free (str); 
  }
  uint32_t retrivedSize = start.ReadU32 ();
  for (uint32_t j = 0; j < retrivedSize; j++) {
    uint32_t strLength = start.ReadU32 ();
    char* str = (char*) malloc (strLength);
    start.Read ((uint8_t*)str, strLength);
    obtainedResult.insert(std::string (str, strLength));
    free (str); 
    
  }
  return SearchReq::GetSerializedSize ();
}

void
PennSearchMessage::SetSearchReq (std::set<std::string> intersectionSet, 
uint32_t keyNumber, std::vector<std::string> keywords, Ipv4Address originatorAddress)
{
  if (m_messageType == 0)
    {
      m_messageType = SEARCH_REQ;
    }
  else
    {
      NS_ASSERT (m_messageType == SEARCH_REQ);
    }
  m_message.searchReq.keywords = keywords;
  m_message.searchReq.keyNumber = keyNumber;
  m_message.searchReq.originatorAddress = originatorAddress;
  m_message.searchReq.obtainedResult = intersectionSet;
}

PennSearchMessage::SearchReq
PennSearchMessage::GetSearchReq ()
{
  return m_message.searchReq;
}


/*Search Rsp*/
uint32_t 
PennSearchMessage::SearchRsp::GetSerializedSize (void) const
{
  uint32_t size;
  uint32_t charNum = 0;
  for (auto iter = searchResult.begin(); iter != searchResult.end(); iter++) {
    charNum += (*iter).length();
  }
  size = charNum + sizeof(uint32_t) + 
  searchResult.size() * sizeof (uint32_t) ;
  
  return size;
}

void
PennSearchMessage::SearchRsp::Print (std::ostream &os) const
{
  os << "PublishReq:: search result size: " << searchResult.size() << "\n";
}

void
PennSearchMessage::SearchRsp::Serialize (Buffer::Iterator &start) const
{
  start.WriteU32 (searchResult.size());
  for (auto iter = searchResult.begin(); iter != searchResult.end(); iter++) {
    start.WriteU32 ((*iter).size());
    start.Write ((uint8_t *) (const_cast<char*> ((*iter).c_str())), (*iter).length());
  }
}

uint32_t
PennSearchMessage::SearchRsp::Deserialize (Buffer::Iterator &start)
{  
  uint32_t resultSize = start.ReadU32 ();
  for (uint32_t i = 0; i < resultSize; i++) {
    uint32_t strLength = start.ReadU32 ();
    char* str = (char*) malloc (strLength);
    start.Read ((uint8_t*)str, strLength);
    searchResult.insert(std::string (str, strLength));
    free (str); 
  }
  return SearchRsp::GetSerializedSize ();
}

void
PennSearchMessage::SetSearchRsp (std::set<std::string> intersectionSet)
{
  if (m_messageType == 0)
    {
      m_messageType = SEARCH_RSP;
    }
  else
    {
      NS_ASSERT (m_messageType == SEARCH_RSP);
    }
  m_message.searchRsp.searchResult = intersectionSet;
}

PennSearchMessage::SearchRsp
PennSearchMessage::GetSearchRsp ()
{
  return m_message.searchRsp;
}



/*Search Contact*/
uint32_t 
PennSearchMessage::SearchContact::GetSerializedSize (void) const
{
  uint32_t size;
  uint32_t charNum = 0;
  for (auto iter = keywords.begin(); iter != keywords.end(); iter++) {
    charNum += (*iter).length();
  }
  size = sizeof(uint32_t) + sizeof(uint32_t) +
  keywords.size() * sizeof(uint32_t) + charNum + IPV4_ADDRESS_SIZE;
  
  return size;
  // return 500;

  
}

void
PennSearchMessage::SearchContact::Print (std::ostream &os) const
{
  os << "SearchContact:: search 1st keyword: " << keywords[0] << "\n";
}

void
PennSearchMessage::SearchContact::Serialize (Buffer::Iterator &start) const
{
  
  // std::cout << keywords[0] << std::endl;
  start.WriteHtonU32 (originatorAddress.Get ());
  start.WriteU32 (keywords.size());
  for (auto iter = keywords.begin(); iter != keywords.end(); iter++) {
    start.WriteU32 ((*iter).size());
    // std::cout << (*iter).size() << std::endl;
    start.Write ((uint8_t *) (const_cast<char*> ((*iter).c_str())), (*iter).length());
    // std::cout << (*iter).c_str() << std::endl;
  }
}

uint32_t
PennSearchMessage::SearchContact::Deserialize (Buffer::Iterator &start)
{ 
  originatorAddress = Ipv4Address (start.ReadNtohU32 ());
  uint32_t keySize = start.ReadU32 ();
  for (uint32_t i = 0; i < keySize; i++) {
    uint32_t strLength = start.ReadU32 ();
    char* str = (char*) malloc (strLength);
    start.Read ((uint8_t*)str, strLength);
    keywords.push_back(std::string (str, strLength));
    free (str); 
  }
  return SearchContact::GetSerializedSize ();
}

void
PennSearchMessage::SetSearchContact (std::vector<std::string> keywords, Ipv4Address originatorAddress)
{
  if (m_messageType == 0)
    {
      m_messageType = SEARCH_CONTACT;
    }
  else
    {
      NS_ASSERT (m_messageType == SEARCH_CONTACT);
    }
  m_message.searchContact.keywords = keywords;
  m_message.searchContact.originatorAddress = originatorAddress;

}

PennSearchMessage::SearchContact
PennSearchMessage::GetSearchContact ()
{
  return m_message.searchContact;
}




void
PennSearchMessage::SetMessageType (MessageType messageType)
{
  m_messageType = messageType;
}

PennSearchMessage::MessageType
PennSearchMessage::GetMessageType () const
{
  return m_messageType;
}

void
PennSearchMessage::SetTransactionId (uint32_t transactionId)
{
  m_transactionId = transactionId;
}

uint32_t 
PennSearchMessage::GetTransactionId (void) const
{
  return m_transactionId;
}

