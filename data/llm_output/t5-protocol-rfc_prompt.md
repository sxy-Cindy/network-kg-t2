# t5-protocol-rfc — 方法C（LLM 抽取）提示词包

> 用法：把每个片段（连同上面的"角色/本体/输出格式/规则"说明）逐个发给 LLM，
> 收集返回的 JSON，按下面的汇总格式整理成 `t5-protocol-rfc_agent_llm.json`，然后执行
> `.venv/bin/python -m kgc.llm --topic t5-protocol-rfc --from-file data/llm_output/t5-protocol-rfc_agent_llm.json`

## 0. 发给 LLM 的系统提示

```
你是知识图谱抽取器。只输出 JSON，不要解释、不要 markdown 代码块。
```

## 1. 本体词汇（必须严格使用）

【本体类】(id | 中文 | 定义)
- SpecObject | 规范对象 | 规范域顶层概念
- Document | 规范文档 | RFC/BCP/STD 等文档
- RFC | RFC 文档 | 征求意见稿
- Section | 章节 | RFC 内的章节
- Protocol | 协议 | TCP/UDP/IP 等
- Layer | 协议分层 | 应用层/传输层/网络层/链路层
- MessageField | 报文域 | 首部字段
- NormativeKeyword | 规范性关键字 | RFC 2119 定义的关键字
- Obligation | 规范性要求 | 一条带关键字的规范要求
- Port | 端口号 | 传输层端口
- Extension | 扩展项 | 首部选项/扩展首部

【关系】(id | 中文 | 定义 | 头类 -> 尾类)
- defined_in | 定义于 | 协议/概念被哪个文档定义 | Protocol -> Document
- specifies | 规范 | 文档规范了某协议 | RFC -> Protocol
- contains | 包含章节 | 文档包含章节 | Document -> Section
- cites | 引用了 | 文档引用其他文档 | Document -> Document
- obsoletes | 废弃 | 新版废弃旧版 | Document -> Document
- updates | 更新 | 文档更新其他文档 | Document -> Document
- has_field | 含字段 | 协议首部包含某字段 | Protocol -> MessageField
- operates_at | 工作于 | 协议所属分层 | Protocol -> Layer
- keyword_of | 关键字属于 | 规范要求使用的关键字 | Obligation -> NormativeKeyword
- requires | 要求 | 规范要求约束某协议行为 | Document -> Obligation
- depends_on | 依赖 | 协议依赖另一协议 | Protocol -> Protocol
- has_extension | 含扩展 | 协议的扩展项 | Protocol -> Extension
- mentioned_in | 出现在 | 实体出现在来源文档中（结构关系） | None -> None

## 2. 输出格式与规则

```json
{
  "doc_id": "<片段所属文档 id，见片段标题>",
  "entities": [{"id": "类:id后缀", "label": "表面形式", "type": "类名"}],
  "relations": [{"source": "实体id", "relation": "关系名", "target": "实体id",
                  "evidence": "支撑该关系的原文片段（连续原文，≤120字）"}]
}
```

1. `type` 必须来自上面的类 id；`relation` 必须来自上面的关系 id，否则**不要输出该条**。
2. `id` 用 `类名:标签` 形式；同一实体在不同片段中用同一 id。
3. `evidence` 必须是**原文连续片段**，不得改写、不得翻译。
4. 只抽文本中明确出现的事实，不做推理延伸。

## 3. 语料片段（逐段粘贴）


===== 片段 1（doc=rfc2119 #1）=====

```
# source: https://www.rfc-editor.org/rfc/rfc2119.txt
# fetched: 2026-10-14






Network Working Group                                         S. Bradner
Request for Comments: 2119                            Harvard University
BCP: 14                                                       March 1997
Category: Best Current Practice


        Key words for use in RFCs to Indicate Requirement Levels

Status of this Memo

   This document specifies an Internet Best Current Practices for the
   Internet Community, and requests discussion and suggestions for
   improvements. Distribution of this memo is unlimited. Abstract

   In many standards track documents several words are used to signify
   the requirements in the specification. These words are often
   capitalized. This document defines these words as they should be
   interpreted in IETF documents. Authors who follow these guidelines
   should incorporate this phrase near the beginning of their document:

      The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL
      NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED",  "MAY", and
      "OPTIONAL" in this document are to be interpreted as described in
      RFC 2119. Note that the force of these words is modified by the requirement
   level of the document in which they are used. 1. MUST   This word, or the terms "REQUIRED" or "SHALL", mean that the
   definition is an absolute requirement of the specification. 2. MUST NOT   This phrase, or the phrase "SHALL NOT", mean that the
   definition is an absolute prohibition of the specification. 3. SHOULD   This word, or the adjective "RECOMMENDED", mean that there
   may exist valid reasons in particular circumstances to ignore a
   particular item, but the full implications must be understood and
   carefully weighed before choosing a different course. 4. SHOULD NOT   This phrase, or the phrase "NOT RECOMMENDED" mean that
   there may exist valid reasons in particular circumstances when the
   particular behavior is acceptable or even useful, but the full
   implications should be understood and the case carefully weighed
   before implementing any behavior described with this label. Bradner                  Best Current Practice                  [Page 1]

RFC 2119                     RFC Key Words                    March 1997


5. MAY   This word, or the adjective "OPTIONAL", mean that an item is
   truly optional. One vendor may choose to include the item because a
   particular marketplace requires it or because the vendor feels that
   it enhances the product while another vendor may omit the same item. An implementation which does not include a particular option MUST be
   prepared to interoperate with another implementation which does
   include the option, though perhaps with reduced functionality. In the
   same vein an implementation which does include a particular option
   MUST be prepared to interoperate with another implementation which
   does not include the option (except, of course, for the feature the
   option provides.)

6. Guidance in the use of these Imperatives

   Imperatives of the type defined in this memo must be used with care
   and sparingly. 
```

===== 片段 2（doc=rfc2119 #2）=====

```
In particular, they MUST only be used where it is
   actually required for interoperation or to limit behavior which has
   potential for causing harm (e.g., limiting retransmisssions)  For
   example, they must not be used to try to impose a particular method
   on implementors where the method is not required for
   interoperability. 7. Security Considerations

   These terms are frequently used to specify behavior with security
   implications. The effects on security of not implementing a MUST or
   SHOULD, or doing something the specification says MUST NOT or SHOULD
   NOT be done may be very subtle. Document authors should take the time
   to elaborate the security implications of not following
   recommendations or requirements as most implementors will not have
   had the benefit of the experience and discussion that produced the
   specification. 8. Acknowledgments

   The definitions of these terms are an amalgam of definitions taken
   from a number of RFCs. In addition, suggestions have been
   incorporated from a number of people including Robert Ullmann, Thomas
   Narten, Neal McBurnett, and Robert Elz. Bradner                  Best Current Practice                  [Page 2]

RFC 2119                     RFC Key Words                    March 1997


9. Author's Address

      Scott Bradner
      Harvard University
      1350 Mass. Ave. Cambridge, MA 02138

      phone - +1 617 495 3864

      email - sob@harvard.edu









































Bradner                  Best Current Practice                  [Page 3]

 
```

===== 片段 3（doc=rfc768 #1）=====

```
# source: https://www.rfc-editor.org/rfc/rfc768.txt
# fetched: 2026-10-14


RFC 768                                                        J. Postel
                                                                     ISI
                                                          28 August 1980



                         User Datagram Protocol
                         ----------------------

Introduction
------------

This User Datagram  Protocol  (UDP)  is  defined  to  make  available  a
datagram   mode  of  packet-switched   computer   communication  in  the
environment  of  an  interconnected  set  of  computer  networks. This
protocol  assumes  that the Internet  Protocol  (IP)  [1] is used as the
underlying protocol. This protocol  provides  a procedure  for application  programs  to send
messages  to other programs  with a minimum  of protocol mechanism. The
protocol  is transaction oriented, and delivery and duplicate protection
are not guaranteed. Applications requiring ordered reliable delivery of
streams of data should use the Transmission Control Protocol (TCP) [2]. Format
------

                                    
                  0      7 8     15 16    23 24    31  
                 +--------+--------+--------+--------+ 
                 |     Source      |   Destination   | 
                 |      Port       |      Port       | 
                 +--------+--------+--------+--------+ 
                 |                 |                 | 
                 |     Length      |    Checksum     | 
                 +--------+--------+--------+--------+ 
                 |                                     
                 |          data octets ... +---------------- ... User Datagram Header Format

Fields
------

Source Port is an optional field, when meaningful, it indicates the port
of the sending  process,  and may be assumed  to be the port  to which a
reply should  be addressed  in the absence of any other information. If
not used, a value of zero is inserted. Postel                                                          [page 1]


                                                             28 Aug 1980
User Datagram Protocol                                           RFC 768
Fields



Destination  Port has a meaning  within  the  context  of  a  particular
internet destination address. Length  is the length  in octets  of this user datagram  including  this
header  and the data. (This  means  the minimum value of the length is
eight.)

Checksum is the 16-bit one's complement of the one's complement sum of a
pseudo header of information from the IP header, the UDP header, and the
data,  padded  with zero octets  at the end (if  necessary)  to  make  a
multiple of two octets. The pseudo  header  conceptually prefixed to the UDP header contains the
source  address,  the destination  address,  the protocol,  and the  UDP
length. This information gives protection against misrouted datagrams. This checksum procedure is the same as is used in TCP. 
```

===== 片段 4（doc=rfc768 #2）=====

```
0      7 8     15 16    23 24    31 
                 +--------+--------+--------+--------+
                 |          source address           |
                 +--------+--------+--------+--------+
                 |        destination address        |
                 +--------+--------+--------+--------+
                 |  zero  |protocol|   UDP length    |
                 +--------+--------+--------+--------+

If the computed  checksum  is zero,  it is transmitted  as all ones (the
equivalent  in one's complement  arithmetic). An all zero  transmitted
checksum  value means that the transmitter  generated  no checksum  (for
debugging or for higher level protocols that don't care). User Interface
--------------

A user interface should allow

  the creation of new receive ports,

  receive  operations  on the receive  ports that return the data octets
  and an indication of source port and source address,

  and an operation  that allows  a datagram  to be sent,  specifying the
  data, source and destination ports and addresses to be sent. [page 2]                                                          Postel


28 Aug 1980
RFC 768                                           User Datagram Protocol
                                                            IP Interface



IP Interface
-------------

The UDP module  must be able to determine  the  source  and  destination
internet addresses and the protocol field from the internet header. One
possible  UDP/IP  interface  would return  the whole  internet  datagram
including all of the internet header in response to a receive operation. Such an interface  would  also allow  the UDP to pass  a  full  internet
datagram  complete  with header  to the IP to send. The IP would verify
certain fields for consistency and compute the internet header checksum. Protocol Application
--------------------

The major uses of this protocol is the Internet Name Server [3], and the
Trivial File Transfer [4]. Protocol Number
---------------

This is protocol  17 (21 octal)  when used  in  the  Internet  Protocol. Other protocol numbers are listed in [5]. References
----------

[1]     Postel,   J.,   "Internet  Protocol,"  RFC 760,  USC/Information
        Sciences Institute, January 1980. [2]     Postel,    J.,   "Transmission   Control   Protocol,"   RFC 761,
        USC/Information Sciences Institute, January 1980. [3]     Postel,  J.,  "Internet  Name Server,"  USC/Information Sciences
        Institute, IEN 116, August 1979. [4]     Sollins,  K.,  "The TFTP Protocol,"  Massachusetts  Institute of
        Technology, IEN 133, January 1980. [5]     Postel,   J.,   "Assigned   Numbers,"  USC/Information  Sciences
        Institute, RFC 762, January 1980. Postel                                                          [page 3]
 
```

===== 片段 5（doc=rfc791 #1）=====

```
# source: https://www.rfc-editor.org/rfc/rfc791.txt
# fetched: 2026-10-14


RFC:  791
                                    
                                    
                                    
                                    
                                    
                                    
                                    
                           INTERNET PROTOCOL
                                    
                                    
                         DARPA INTERNET PROGRAM
                                    
                         PROTOCOL SPECIFICATION
                                    
                                    
                                    
                             September 1981













                              prepared for

               Defense Advanced Research Projects Agency
                Information Processing Techniques Office
                         1400 Wilson Boulevard
                       Arlington, Virginia  22209







                                   by

                     Information Sciences Institute
                   University of Southern California
                           4676 Admiralty Way
                   Marina del Rey, California  90291



September 1981                                                          
                                                       Internet Protocol



                           TABLE OF CONTENTS

    PREFACE ........................................................ iii

1. INTRODUCTION ..................................................... 1

  1.1  Motivation .................................................... 1
  1.2  Scope ......................................................... 1
  1.3  Interfaces .................................................... 1
  1.4  Operation ..................................................... 2

2. OVERVIEW ......................................................... 5

  2.1  Relation to Other Protocols ................................... 9
  2.2  Model of Operation ............................................ 5
  2.3  Function Description .......................................... 7
  2.4  Gateways ...................................................... 9

3. SPECIFICATION ................................................... 11

  3.1  Internet Header Format ....................................... 11
  3.2  Discussion ................................................... 23
  3.3  Interfaces ................................................... 31

APPENDIX A:  Examples & Scenarios ................................... 34
APPENDIX B:  Data Transmission Order ................................ 39

GLOSSARY ............................................................ 41

REFERENCES .......................................................... 45





















                                                                [Page i]


                                                          September 1981
Internet Protocol






















































[Page ii]                                                               


September 1981                                                          
                                                       Internet Protocol



                                PREFACE



This document specifies the DoD Standard Internet Protocol. 
```

===== 片段 6（doc=rfc791 #2）=====

```
This
document is based on six earlier editions of the ARPA Internet Protocol
Specification, and the present text draws heavily from them. There have
been many contributors to this work both in terms of concepts and in
terms of text. This edition revises aspects of addressing, error
handling, option codes, and the security, precedence, compartments, and
handling restriction features of the internet protocol. Jon Postel

                                                           Editor




































                                                              [Page iii]



                                                          September 1981


RFC:  791
Replaces:  RFC 760
IENs 128, 123, 111,
80, 54, 44, 41, 28, 26

                           INTERNET PROTOCOL

                         DARPA INTERNET PROGRAM
                         PROTOCOL SPECIFICATION



                            1. INTRODUCTION

1.1. Motivation

  The Internet Protocol is designed for use in interconnected systems of
  packet-switched computer communication networks. Such a system has
  been called a "catenet" [1]. The internet protocol provides for
  transmitting blocks of data called datagrams from sources to
  destinations, where sources and destinations are hosts identified by
  fixed length addresses. The internet protocol also provides for
  fragmentation and reassembly of long datagrams, if necessary, for
  transmission through "small packet" networks. 1.2. Scope

  The internet protocol is specifically limited in scope to provide the
  functions necessary to deliver a package of bits (an internet
  datagram) from a source to a destination over an interconnected system
  of networks. There are no mechanisms to augment end-to-end data
  reliability, flow control, sequencing, or other services commonly
  found in host-to-host protocols. The internet protocol can capitalize
  on the services of its supporting networks to provide various types
  and qualities of service. 1.3. Interfaces

  This protocol is called on by host-to-host protocols in an internet
  environment. This protocol calls on local network protocols to carry
  the internet datagram to the next gateway or destination host. For example, a TCP module would call on the internet module to take a
  TCP segment (including the TCP header and user data) as the data
  portion of an internet datagram. The TCP module would provide the
  addresses and other parameters in the internet header to the internet
  module as arguments of the call. The internet module would then
  create an internet datagram and call on the local network interface to
  transmit the internet datagram. In the ARPANET case, for example, the internet module would call on a


                                                                [Page 1]


                                                          September 1981
Internet Protocol
Introduction



  local net module which would add the 1822 leader [2] to the internet
  datagram creating an ARPANET message to transmit to the IMP. The
  ARPANET address would be derived from the internet address by the
  local network interface and would be the address of some host in the
  ARPANET, that host might be a gateway to other networks. 1.4. Operation

  The internet protocol implements two basic functions:  addressing and
  fragmentation. 
```

===== 片段 7（doc=rfc791 #3）=====

```
The internet modules use the addresses carried in the internet header
  to transmit internet datagrams toward their destinations. The
  selection of a path for transmission is called routing. The internet modules use fields in the internet header to fragment and
  reassemble internet datagrams when necessary for transmission through
  "small packet" networks. The model of operation is that an internet module resides in each host
  engaged in internet communication and in each gateway that
  interconnects networks. These modules share common rules for
  interpreting address fields and for fragmenting and assembling
  internet datagrams. In addition, these modules (especially in
  gateways) have procedures for making routing decisions and other
  functions. The internet protocol treats each internet datagram as an independent
  entity unrelated to any other internet datagram. There are no
  connections or logical circuits (virtual or otherwise). The internet protocol uses four key mechanisms in providing its
  service:  Type of Service, Time to Live, Options, and Header Checksum. The Type of Service is used to indicate the quality of the service
  desired. The type of service is an abstract or generalized set of
  parameters which characterize the service choices provided in the
  networks that make up the internet. This type of service indication
  is to be used by gateways to select the actual transmission parameters
  for a particular network, the network to be used for the next hop, or
  the next gateway when routing an internet datagram. The Time to Live is an indication of an upper bound on the lifetime of
  an internet datagram. It is set by the sender of the datagram and
  reduced at the points along the route where it is processed. If the
  time to live reaches zero before the internet datagram reaches its
  destination, the internet datagram is destroyed. The time to live can
  be thought of as a self destruct time limit. [Page 2]                                                                


September 1981                                                          
                                                       Internet Protocol
                                                            Introduction



  The Options provide for control functions needed or useful in some
  situations but unnecessary for the most common communications. The
  options include provisions for timestamps, security, and special
  routing. The Header Checksum provides a verification that the information used
  in processing internet datagram has been transmitted correctly. The
  data may contain errors. If the header checksum fails, the internet
  datagram is discarded at once by the entity which detects the error. The internet protocol does not provide a reliable communication
  facility. There are no acknowledgments either end-to-end or
  hop-by-hop. There is no error control for data, only a header
  checksum. There are no retransmissions. There is no flow control. Errors detected may be reported via the Internet Control Message
  Protocol (ICMP) [3] which is implemented in the internet protocol
  module. 
```

===== 片段 8（doc=rfc791 #4）=====

```
[Page 3]


                                                          September 1981
Internet Protocol






















































[Page 4]                                                                


September 1981                                                          
                                                       Internet Protocol



                              2. OVERVIEW

2.1. Relation to Other Protocols

  The following diagram illustrates the place of the internet protocol
  in the protocol hierarchy:

                                    
                 +------+ +-----+ +-----+     +-----+  
                 |Telnet| | FTP | | TFTP| ... | ... |  
                 +------+ +-----+ +-----+     +-----+  
                       |   |         |           |     
                      +-----+     +-----+     +-----+  
                      | TCP |     | UDP | ... | ... |  
                      +-----+     +-----+     +-----+  
                         |           |           |     
                      +--------------------------+----+
                      |    Internet Protocol & ICMP   |
                      +--------------------------+----+
                                     |                 
                        +---------------------------+  
                        |   Local Network Protocol  |  
                        +---------------------------+  

                         Protocol Relationships

                               Figure 1. Internet protocol interfaces on one side to the higher level
  host-to-host protocols and on the other side to the local network
  protocol. In this context a "local network" may be a small network in
  a building or a large network such as the ARPANET. 2.2. Model of Operation

  The  model of operation for transmitting a datagram from one
  application program to another is illustrated by the following
  scenario:

    We suppose that this transmission will involve one intermediate
    gateway. The sending application program prepares its data and calls on its
    local internet module to send that data as a datagram and passes the
    destination address and other parameters as arguments of the call. The internet module prepares a datagram header and attaches the data
    to it. The internet module determines a local network address for
    this internet address, in this case it is the address of a gateway. [Page 5]


                                                          September 1981
Internet Protocol
Overview



    It sends this datagram and the local network address to the local
    network interface. The local network interface creates a local network header, and
    attaches the datagram to it, then sends the result via the local
    network. The datagram arrives at a gateway host wrapped in the local network
    header, the local network interface strips off this header, and
    turns the datagram over to the internet module. The internet module
    determines from the internet address that the datagram is to be
    forwarded to another host in a second network. The internet module
    determines a local net address for the destination host. It calls
    on the local network interface for that network to send the
    datagram. This local network interface creates a local network header and
    attaches the datagram sending the result to the destination host. 
```

===== 片段 9（doc=rfc791 #5）=====

```
At this destination host the datagram is stripped of the local net
    header by the local network interface and handed to the internet
    module. The internet module determines that the datagram is for an
    application program in this host. It passes the data to the
    application program in response to a system call, passing the source
    address and other parameters as results of the call. Application                                           Application
   Program                                                   Program
         \                                                   /      
       Internet Module      Internet Module      Internet Module    
             \                 /       \                /           
             LNI-1          LNI-1      LNI-2         LNI-2          
                \           /             \          /              
               Local Network 1           Local Network 2            



                            Transmission Path

                                Figure 2







[Page 6]                                                                


September 1981                                                          
                                                       Internet Protocol
                                                                Overview



2.3. Function Description

  The function or purpose of Internet Protocol is to move datagrams
  through an interconnected set of networks. This is done by passing
  the datagrams from one internet module to another until the
  destination is reached. The internet modules reside in hosts and
  gateways in the internet system. The datagrams are routed from one
  internet module to another through individual networks based on the
  interpretation of an internet address. Thus, one important mechanism
  of the internet protocol is the internet address. In the routing of messages from one internet module to another,
  datagrams may need to traverse a network whose maximum packet size is
  smaller than the size of the datagram. To overcome this difficulty, a
  fragmentation mechanism is provided in the internet protocol. Addressing

    A distinction is made between names, addresses, and routes [4]. A
    name indicates what we seek. An address indicates where it is. A
    route indicates how to get there. The internet protocol deals
    primarily with addresses. It is the task of higher level (i.e.,
    host-to-host or application) protocols to make the mapping from
    names to addresses. The internet module maps internet addresses to
    local net addresses. It is the task of lower level (i.e., local net
    or gateways) procedures to make the mapping from local net addresses
    to routes. Addresses are fixed length of four octets (32 bits). An address
    begins with a network number, followed by local address (called the
    "rest" field). There are three formats or classes of internet
    addresses:  in class a, the high order bit is zero, the next 7 bits
    are the network, and the last 24 bits are the local address; in
    class b, the high order two bits are one-zero, the next 14 bits are
    the network and the last 16 bits are the local address; in class c,
    the high order three bits are one-one-zero, the next 21 bits are the
    network and the last 8 bits are the local address. Care must be taken in mapping internet addresses to local net
    addresses; 
```

===== 片段 10（doc=rfc791 #6）=====

```
a single physical host must be able to act as if it were
    several distinct hosts to the extent of using several distinct
    internet addresses. Some hosts will also have several physical
    interfaces (multi-homing). That is, provision must be made for a host to have several physical
    interfaces to the network with each having several logical internet
    addresses. [Page 7]


                                                          September 1981
Internet Protocol
Overview



    Examples of address mappings may be found in "Address Mappings" [5]. Fragmentation

    Fragmentation of an internet datagram is necessary when it
    originates in a local net that allows a large packet size and must
    traverse a local net that limits packets to a smaller size to reach
    its destination. An internet datagram can be marked "don't fragment."  Any internet
    datagram so marked is not to be internet fragmented under any
    circumstances. If internet datagram marked don't fragment cannot be
    delivered to its destination without fragmenting it, it is to be
    discarded instead. Fragmentation, transmission and reassembly across a local network
    which is invisible to the internet protocol module is called
    intranet fragmentation and may be used [6]. The internet fragmentation and reassembly procedure needs to be able
    to break a datagram into an almost arbitrary number of pieces that
    can be later reassembled. The receiver of the fragments uses the
    identification field to ensure that fragments of different datagrams
    are not mixed. The fragment offset field tells the receiver the
    position of a fragment in the original datagram. The fragment
    offset and length determine the portion of the original datagram
    covered by this fragment. The more-fragments flag indicates (by
    being reset) the last fragment. These fields provide sufficient
    information to reassemble datagrams. The identification field is used to distinguish the fragments of one
    datagram from those of another. The originating protocol module of
    an internet datagram sets the identification field to a value that
    must be unique for that source-destination pair and protocol for the
    time the datagram will be active in the internet system. The
    originating protocol module of a complete datagram sets the
    more-fragments flag to zero and the fragment offset to zero. To fragment a long internet datagram, an internet protocol module
    (for example, in a gateway), creates two new internet datagrams and
    copies the contents of the internet header fields from the long
    datagram into both new internet headers. The data of the long
    datagram is divided into two portions on a 8 octet (64 bit) boundary
    (the second portion might not be an integral multiple of 8 octets,
    but the first must be). Call the number of 8 octet blocks in the
    first portion NFB (for Number of Fragment Blocks). The first
    portion of the data is placed in the first new internet datagram,
    and the total length field is set to the length of the first


[Page 8] 


September 1981 
                                                       Internet Protocol
                                                                Overview



    datagram. The more-fragments flag is set to one. 
```

===== 片段 11（doc=rfc791 #7）=====

```
The second
    portion of the data is placed in the second new internet datagram,
    and the total length field is set to the length of the second
    datagram. The more-fragments flag carries the same value as the
    long datagram. The fragment offset field of the second new internet
    datagram is set to the value of that field in the long datagram plus
    NFB. This procedure can be generalized for an n-way split, rather than
    the two-way split described. To assemble the fragments of an internet datagram, an internet
    protocol module (for example at a destination host) combines
    internet datagrams that all have the same value for the four fields:
    identification, source, destination, and protocol. The combination
    is done by placing the data portion of each fragment in the relative
    position indicated by the fragment offset in that fragment's
    internet header. The first fragment will have the fragment offset
    zero, and the last fragment will have the more-fragments flag reset
    to zero. 2.4. Gateways

  Gateways implement internet protocol to forward datagrams between
  networks. Gateways also implement the Gateway to Gateway Protocol
  (GGP) [7] to coordinate routing and other internet control
  information. In a gateway the higher level protocols need not be implemented and
  the GGP functions are added to the IP module. +-------------------------------+   
                   | Internet Protocol & ICMP & GGP|   
                   +-------------------------------+   
                           |                 |         
                 +---------------+   +---------------+ 
                 |   Local Net   |   |   Local Net   | 
                 +---------------+   +---------------+ 

                           Gateway Protocols

                               Figure 3. [Page 9]


                                                          September 1981
Internet Protocol






















































[Page 10]                                                               


September 1981                                                          
                                                       Internet Protocol



                           3. SPECIFICATION

3.1. 
```

===== 片段 12（doc=rfc791 #8）=====

```
Internet Header Format

  A summary of the contents of the internet header follows:

                                    
    0                   1                   2                   3   
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |Version|  IHL  |Type of Service|          Total Length         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |         Identification        |Flags|      Fragment Offset    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |  Time to Live |    Protocol   |         Header Checksum       |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                       Source Address                          |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Destination Address                        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Options                    |    Padding    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

                    Example Internet Datagram Header

                               Figure 4. Note that each tick mark represents one bit position. Version:  4 bits

    The Version field indicates the format of the internet header. This
    document describes version 4. IHL:  4 bits

    Internet Header Length is the length of the internet header in 32
    bit words, and thus points to the beginning of the data. Note that
    the minimum value for a correct header is 5. [Page 11]


                                                          September 1981
Internet Protocol
Specification



  Type of Service:  8 bits

    The Type of Service provides an indication of the abstract
    parameters of the quality of service desired. These parameters are
    to be used to guide the selection of the actual service parameters
    when transmitting a datagram through a particular network. Several
    networks offer service precedence, which somehow treats high
    precedence traffic as more important than other traffic (generally
    by accepting only traffic above a certain precedence at time of high
    load). The major choice is a three way tradeoff between low-delay,
    high-reliability, and high-throughput. Bits 0-2:  Precedence. Bit    3:  0 = Normal Delay,      1 = Low Delay. Bits   4:  0 = Normal Throughput, 1 = High Throughput. Bits   5:  0 = Normal Relibility, 1 = High Relibility. Bit  6-7:  Reserved for Future Use. 0     1     2     3     4     5     6     7
      +-----+-----+-----+-----+-----+-----+-----+-----+
      |                 |     |     |     |     |     |
      |   PRECEDENCE    |  D  |  T  |  R  |  0  |  0  |
      |                 |     |     |     |     |     |
      +-----+-----+-----+-----+-----+-----+-----+-----+

        Precedence

          111 - Network Control
          110 - Internetwork Control
          101 - CRITIC/ECP
          100 - Flash Override
          011 - Flash
          010 - Immediate
          001 - Priority
          000 - Routine

    The use of the Delay, Throughput, and Reliability indications may
    increase the cost (in some sense) of the service. In many networks
    better performance for one of these parameters is coupled with worse
    performance on another. Except for very unusual cases at most two
    of these three indications should be set. 
```

## 4. 汇总文件格式（供 `--from-file` 读取）

```json
{
  "model": "<模型名与版本>",
  "note": "生成日期 <YYYY-MM-DD>；prompt 见本文件；人工复核 <N> 条（另附复核记录）",
  "docs": [
    {{"doc_id": "rfc8200", "entities": [...], "relations": [...]}},
    {{"doc_id": "rfc2119", "entities": [...], "relations": [...]}}
  ]
}
```

⚠ 提交作业时必须一并附上：① 模型名/版本/日期；② 本文件（prompt 原文）；
③ 原始输出 JSON；④ ≥20 条人工复核记录（逐条判断"抽出的三元组是否被原文支持"）。
