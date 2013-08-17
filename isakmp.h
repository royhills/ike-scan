/*
 * The IKE Scanner (ike-scan) is Copyright (C) 2003-2007 Roy Hills,
 * NTA Monitor Ltd.
 *
 * This file is part of ike-scan.
 *
 * ike-scan is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * ike-scan is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with ike-scan.  If not, see <http://www.gnu.org/licenses/>.
 *
 * In addition, as a special exception, the copyright holders give
 * permission to link the code of portions of this program with the
 * OpenSSL library, and distribute linked combinations including the two.
 *
 * You must obey the GNU General Public License in all respects
 * for all of the code used other than OpenSSL.  If you modify
 * file(s) with this exception, you may extend this exception to your
 * version of the file(s), but you are not obligated to do so.  If you
 * do not wish to do so, delete this exception statement from your
 * version.
 *
 * If this license is unacceptable to you, I may be willing to negotiate
 * alternative licenses (contact ike-scan@nta-monitor.com).
 *
 * You are encouraged to send comments, improvements or suggestions to
 * me at ike-scan@nta-monitor.com.
 *
 * isakmp.h	-- Definitions for ISAKMP packet structures
 *
 * Author:	Roy Hills
 * Date:	31 July 2001
 *
 * Definitions for ISAKMP packet.  Adapted from FreeS/WAN "pluto/packet.h"
 * with additional definitions for IKEv2 from RFC 4306.
 *
 * Many of the types used come from <sys/types.h> which needs to be
 * included before this include file.
 */

/*
 * Define constants
 */

#define	COOKIE_SIZE	2	/* Size in 32-bit longwords */

#define OAKLEY_ENCRYPTION_ALGORITHM    1
#define OAKLEY_HASH_ALGORITHM          2
#define OAKLEY_AUTHENTICATION_METHOD   3
#define OAKLEY_GROUP_DESCRIPTION       4
#define OAKLEY_GROUP_TYPE              5
#define OAKLEY_GROUP_PRIME             6        /* B/V */
#define OAKLEY_GROUP_GENERATOR_ONE     7        /* B/V */
#define OAKLEY_GROUP_GENERATOR_TWO     8        /* B/V */
#define OAKLEY_GROUP_CURVE_A           9        /* B/V */
#define OAKLEY_GROUP_CURVE_B          10        /* B/V */
#define OAKLEY_LIFE_TYPE              11
#define OAKLEY_LIFE_DURATION          12        /* B/V */
#define OAKLEY_PRF                    13
#define OAKLEY_KEY_LENGTH             14
#define OAKLEY_FIELD_SIZE             15
#define OAKLEY_GROUP_ORDER            16        /* B/V */
#define OAKLEY_BLOCK_SIZE             17
#define OAKLEY_GSS_ID	              16384	/* From draft-ietf-ipsec-isakmp-gss-auth-07.txt */

#define SA_LIFE_TYPE_SECONDS   1
#define SA_LIFE_TYPE_KBYTES    2

#define ISAKMP_DOI_ISAKMP          0
#define ISAKMP_DOI_IPSEC           1

#define ISAKMP_NEXT_NONE       0	/* No other payload following */
#define ISAKMP_NEXT_SA         1	/* Security Association */
#define ISAKMP_NEXT_P          2	/* Proposal */
#define ISAKMP_NEXT_T          3	/* Transform */
#define ISAKMP_NEXT_KE         4	/* Key Exchange */
#define ISAKMP_NEXT_ID         5	/* Identification */
#define ISAKMP_NEXT_CERT       6	/* Certificate */
#define ISAKMP_NEXT_CR         7	/* Certificate Request */
#define ISAKMP_NEXT_HASH       8	/* Hash */
#define ISAKMP_NEXT_SIG        9	/* Signature */
#define ISAKMP_NEXT_NONCE      10	/* Nonce */
#define ISAKMP_NEXT_N          11	/* Notification */
#define ISAKMP_NEXT_D          12	/* Delete */
#define ISAKMP_NEXT_VID        13	/* Vendor ID */
#define ISAKMP_NEXT_V2_SA      33	/* IKE v2 Security Association */
#define ISAKMP_NEXT_V2_KE      34	/* IKE v2 Key Exchange */
#define ISAKMP_NEXT_V2_IDI     35	/* IKE v2 Identification - Initiator */
#define ISAKMP_NEXT_V2_IDR     36	/* IKE v2 Identification - Responder */
#define ISAKMP_NEXT_V2_CERT    37	/* IKE v2 Certificate */
#define ISAKMP_NEXT_V2_CERTREQ 38	/* IKE v2 Certificate Request */
#define ISAKMP_NEXT_V2_AUTH    39	/* IKE v2 Authentication */
#define ISAKMP_NEXT_V2_NONCE   40	/* IKE v2 Nonce */
#define ISAKMP_NEXT_V2_N       41	/* IKE v2 Notify */
#define ISAKMP_NEXT_V2_D       42	/* IKE v2 Delete */
#define ISAKMP_NEXT_V2_VID     43	/* IKE v2 Vendor ID */
#define ISAKMP_NEXT_V2_TSI     44	/* IKE v2 Traffic Selector - Init. */
#define ISAKMP_NEXT_V2_TSR     45	/* IKE v2 Traffic Selector - Resp. */
#define ISAKMP_NEXT_V2_E       46	/* IKE v2 Encrypted */
#define ISAKMP_NEXT_V2_CP      47	/* IKE v2 Configuration */
#define ISAKMP_NEXT_V2_EAP     48	/* IKE v2 Extensible Authentication */

#define ISAKMP_XCHG_NONE       0
#define ISAKMP_XCHG_BASE       1
#define ISAKMP_XCHG_IDPROT     2	/* ID Protection */
#define ISAKMP_XCHG_AO         3	/* Authentication Only */
#define ISAKMP_XCHG_AGGR       4	/* Aggressive */
#define ISAKMP_XCHG_INFO       5	/* Informational */
#define ISAKMP_XCHG_IKE_SA_INIT	34	/* IKE v2 */
#define ISAKMP_XCHG_IKE_AUTH   35
#define ISAKMP_XCHG_CREATE_CHILD_SA 36
#define ISAKMP_XCHG_INFORMATIONAL 37

#define SIT_IDENTITY_ONLY        0x01
#define SIT_SECRECY              0x02
#define SIT_INTEGRITY            0x04

#define PROTO_ISAKMP             1
#define PROTO_IPSEC_AH           2
#define PROTO_IPSEC_ESP          3
#define PROTO_IPCOMP             4

#define KEY_IKE               1

#define ID_NONE                     0
#define ID_IPV4_ADDR                1
#define ID_FQDN                     2
#define ID_USER_FQDN                3
#define ID_IPV4_ADDR_SUBNET         4
#define ID_IPV6_ADDR                5
#define ID_IPV6_ADDR_SUBNET         6
#define ID_IPV4_ADDR_RANGE          7
#define ID_IPV6_ADDR_RANGE          8
#define ID_DER_ASN1_DN              9
#define ID_DER_ASN1_GN              10
#define ID_KEY_ID                   11

#define OAKLEY_DES_CBC          1
#define OAKLEY_IDEA_CBC         2
#define OAKLEY_BLOWFISH_CBC     3
#define OAKLEY_RC5_R16_B64_CBC  4
#define OAKLEY_3DES_CBC         5
#define OAKLEY_CAST_CBC         6
#define OAKLEY_AES_CBC          7

#define OAKLEY_MD5      1
#define OAKLEY_SHA      2
#define OAKLEY_TIGER    3
#define OAKLEY_SHA2_256        4
#define OAKLEY_SHA2_384        5
#define OAKLEY_SHA2_512        6

/* IKEv2 transform types */
#define IKEV2_TYPE_ENCR		1
#define IKEV2_TYPE_PRF		2
#define IKEV2_TYPE_INTEG	3
#define IKEV2_TYPE_DH		4
#define IKEV2_TYPE_ESN		5

/* IKEv2 transform IDs for IKEV2_TYPE_ENCR */
#define IKEV2_ENCR_DES_IV64	1
#define IKEV2_ENCR_DES		2
#define IKEV2_ENCR_3DES		3
#define IKEV2_ENCR_RC5		4
#define IKEV2_ENCR_IDEA		5
#define IKEV2_ENCR_CAST		6
#define IKEV2_ENCR_BLOWFISH	7
#define IKEV2_ENCR_3IDEA	8
#define IKEV2_ENCR_DES_IV32	9
#define IKEV2_ENCR_NULL		11
#define IKEV2_ENCR_AES_CBC	12
#define IKEV2_ENCR_AES_CTR	13

/* IKEv2 transform IDs for IKEV2_TYPE_PRF */
#define IKEV2_PRF_HMAC_MD5	1
#define IKEV2_PRF_HMAC_SHA1	2
#define IKEV2_PRF_HMAC_TIGER	3
#define IKEV2_PRF_AES128_XCBC	4

/* IKEv2 transform IDs for IKEV2_TYPE_INTEG */
#define IKEV2_AUTH_HMAC_MD5_96	1
#define IKEV2_AUTH_HMAC_SHA1_96	2
#define IKEV2_AUTH_DES_MAC	3
#define IKEV2_AUTH_KPDK_MD5	4
#define IKEV2_AUTH_AES_XCBC_96	5

/*
 * Define packet structures
 */

/* a struct_desc describes a structure for the struct I/O routines.
 * This requires arrays of field_desc values to describe struct fields.
 */

typedef const struct struct_desc {
    const char *name;
    const struct field_desc *fields;
    size_t size;
} struct_desc;

/* Note: if an ft_af_enum field has the ISAKMP_ATTR_AF_TV bit set,
 * the subsequent ft_lv field will be interpreted as an immediate value.
 * This matches how attributes are encoded.
 * See draft-ietf-ipsec-isakmp-09.txt 3.3
 */

enum field_type {
    ft_mbz,     /* must be zero */
    ft_nat,     /* natural number (may be 0) */
    ft_len,     /* length of this struct and any following crud */
    ft_lv,      /* length/value field of attribute */
    ft_enum,    /* value from an enumeration */
    ft_loose_enum,      /* value from an enumeration with only some names known */
    ft_af_enum, /* Attribute Format + value from an enumeration */
    ft_set,     /* bits representing set */
    ft_raw,     /* bytes to be left in network-order */
    ft_end      /* end of field list */
};

typedef const struct field_desc {
    enum field_type field_type;
    int size;   /* size, in bytes, of field */
    const char *name;
    const void *desc;   /* enum_names for enum or char *[] for bits */
} field_desc;

/* ISAKMP Header: for all messages
 * layout from draft-ietf-ipsec-isakmp-09.txt section 3.1
 * This structure is the same for both IKEv1 and IKEv2, although IKEv2
 * calls the cookies "SPIs".
 *                      1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * !                          Initiator                            !
 * !                            Cookie                             !
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * !                          Responder                            !
 * !                            Cookie                             !
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * !  Next Payload ! MjVer ! MnVer ! Exchange Type !     Flags     !
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * !                          Message ID                           !
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * !                            Length                             !
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */

struct isakmp_hdr
{
    uint32_t   isa_icookie[COOKIE_SIZE];
    uint32_t   isa_rcookie[COOKIE_SIZE];
    uint8_t    isa_np;                 /* Next payload */
    uint8_t	isa_version;	/* high-order 4 bits: Major; low order 4: Minor */
    uint8_t    isa_xchg;		/* Exchange type */
    uint8_t    isa_flags;
    uint32_t   isa_msgid;		/* Message ID (RAW) */
    uint32_t   isa_length;		/* Length of message */
};

/* Generic portion of all ISAKMP payloads.
 * layout from draft-ietf-ipsec-isakmp-09.txt section 3.2
 * This describes the first 32-bit chunk of all payloads.
 * The previous next payload depends on the actual payload type.
 * This is essentially the same for both IKEv1 and IKEv2, except that
 * IKEv2 uses the top bit of the reserved field as "Critical".
 *
 *                      1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * ! Next Payload  !   RESERVED    !         Payload Length        !
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
struct isakmp_generic
{
    uint8_t    isag_np;
    uint8_t    isag_reserved;
    uint16_t   isag_length;
};

/* ISAKMP Data Attribute (generic representation within payloads)
 * layout from draft-ietf-ipsec-isakmp-09.txt section 3.3
 * This is not a payload type.
 * In TLV format, this is followed by a value field.
 * This structure has the same format for IKEv1 and IKEv2
 *
 *                      1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * !A!       Attribute Type        !    AF=0  Attribute Length     !
 * !F!                             !    AF=1  Attribute Value      !
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * .                   AF=0  Attribute Value                       .
 * .                   AF=1  Not Transmitted                       .
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
struct isakmp_attribute
{
    uint16_t isaat_af_type;   /* high order bit: AF; lower 15: rtype */
    uint16_t isaat_lv;			/* Length or value */
};

/* ISAKMP Security Association Payload
 * layout from draft-ietf-ipsec-isakmp-09.txt section 3.4
 * A variable length Situation follows.
 * Previous next payload: ISAKMP_NEXT_SA
 *                      1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * ! Next Payload  !   RESERVED    !         Payload Length        !
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * !              Domain of Interpretation  (DOI)                  !
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * !                                                               !
 * ~                           Situation                           ~
 * !                                                               !
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
struct isakmp_sa
{
    uint8_t  isasa_np;			/* Next payload */
    uint8_t  isasa_reserved;		/* MBZ */
    uint16_t isasa_length;		/* Payload length */
    uint32_t isasa_doi;			/* DOI */
    uint32_t isasa_situation;		/* Situation - 32 bits for IPsec DOI */
};

/* IKEv2 Security Association Payload
 * layout from RFC 4306 section 3.3
 * A variable length proposal payload follows
 * Previous next payload: ISAKMP_NEXT_V2_SA
 * Note that this is just the generic header followed by a proposal
 * sub-payload.
 *
 *                      1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * ! Next Payload  !   RESERVED    !         Payload Length        !
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * !              Domain of Interpretation  (DOI)                  !
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                          <Proposals>                          |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
struct isakmp_sa2
{
    uint8_t  isasa2_np;			/* Next payload */
    uint8_t  isasa2_reserved;		/* MBZ */
    uint16_t isasa2_length;		/* Payload length */
};

/* ISAKMP Proposal Payload
 * layout from draft-ietf-ipsec-isakmp-09.txt section 3.5
 * A variable length SPI follows.
 * Previous next payload: ISAKMP_NEXT_P
 * This structure is the same for both IKEv1 and IKEv2.
 *
 *                      1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * ! Next Payload  !   RESERVED    !         Payload Length        !
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * !  Proposal #   !  Protocol-Id  !    SPI Size   !# of Transforms!
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * !                        SPI (variable)                         !
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
struct isakmp_proposal
{
    uint8_t    isap_np;			/* Next payload */
    uint8_t    isap_reserved;		/* MBZ */
    uint16_t   isap_length;		/* Payload length */
    uint8_t    isap_proposal;		/* Proposal Number */
    uint8_t    isap_protoid;		/* Protocol ID */
    uint8_t    isap_spisize;		/* SPI Size */
    uint8_t    isap_notrans;		/* Number of transforms */
};

/* ISAKMP Transform Payload
 * layout from draft-ietf-ipsec-isakmp-09.txt section 3.6
 * Variable length SA Attributes follow.
 * Previous next payload: ISAKMP_NEXT_T
 *                      1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * ! Next Payload  !   RESERVED    !         Payload Length        !
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * !  Transform #  !  Transform-Id !           RESERVED2           !
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * !                                                               !
 * ~                        SA Attributes                          ~
 * !                                                               !
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
struct isakmp_transform
{
    uint8_t    isat_np;
    uint8_t    isat_reserved;
    uint16_t   isat_length;
    uint8_t    isat_transnum;		/* Number of the transform */
    uint8_t    isat_transid;
    uint16_t   isat_reserved2;
};

/* ISAKMP Transform Payload
 * layout from RFC 4306 section 3.3
 * Variable length Attributes follow.
 *
 *                      1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * ! Next Payload  !   RESERVED    !         Payload Length        !
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * !Transform Type !   RESERVED2   !         Transform ID          !
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * !                                                               !
 * ~                          Attributes                           ~
 * !                                                               !
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
struct isakmp_transform2
{
    uint8_t    isat2_np;		/* Next payload */
    uint8_t    isat2_reserved;		/* MBZ */
    uint16_t   isat2_length;		/* Payload length */
    uint8_t    isat2_transtype;		/* Transform Type */
    uint8_t    isat2_reserved2;		/* MBZ */
    uint16_t   isat2_transid;		/* Transform ID */
};

/* ISAKMP Key Exchange Payload
 *
 *                      1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * ! Next Payload  !   RESERVED    !         Payload Length        !
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * !                                                               !
 * ~                      Key Exchange Data                        ~
 * !                                                               !
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
struct isakmp_kx
{
    uint8_t    isakx_np;
    uint8_t    isakx_reserved;
    uint16_t   isakx_length;
};

/* IKEv2 Key Exchange Payload
 * From RFC 4360 Section 3.4
 *
 *                      1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * ! Next Payload  !   RESERVED    !         Payload Length        !
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * !          DH Group             !             Reserved          !
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * !                                                               !
 * ~                      Key Exchange Data                        ~
 * !                                                               !
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
struct isakmp_kx2
{
    uint8_t    isakx2_np;
    uint8_t    isakx2_reserved;
    uint16_t   isakx2_length;
    uint16_t   isakx2_dhgroup;
    uint16_t   isakx2_reserved2;
};

struct isakmp_nonce
{
    uint8_t    isanonce_np;
    uint8_t    isanonce_reserved;
    uint16_t   isanonce_length;
};

/* ISAKMP Identification Payload
 * layout from draft-ietf-ipsec-isakmp-09.txt section 3.8
 * See "struct identity" declared later.
 * Variable length Identification Data follow.
 * Previous next payload: ISAKMP_NEXT_ID
 *                      1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * ! Next Payload  !   RESERVED    !         Payload Length        !
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * !   ID Type     !             DOI Specific ID Data              !
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * !                                                               !
 * ~                   Identification Data                         ~
 * !                                                               !
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
struct isakmp_id
{
    uint8_t    isaid_np;
    uint8_t    isaid_reserved;
    uint16_t   isaid_length;
    uint8_t    isaid_idtype;
    uint8_t    isaid_doi_specific_a;
    uint16_t   isaid_doi_specific_b;
};

/* ISAKMP Notification Payload
 * layout from draft-ietf-ipsec-isakmp-09.txt section 3.14
 * This is followed by a variable length SPI
 * and then possibly by variable length Notification Data.
 * Previous next payload: ISAKMP_NEXT_N
 *                      1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * ! Next Payload  !   RESERVED    !         Payload Length        !
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * !              Domain of Interpretation  (DOI)                  !
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * !  Protocol-ID  !   SPI Size    !      Notify Message Type      !
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * !                                                               !
 * ~                Security Parameter Index (SPI)                 ~
 * !                                                               !
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * !                                                               !
 * ~                       Notification Data                       ~
 * !                                                               !
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
struct isakmp_notification
{
    uint8_t    isan_np;
    uint8_t    isan_reserved;
    uint16_t   isan_length;
    uint32_t   isan_doi;
    uint8_t    isan_protoid;
    uint8_t    isan_spisize;
    uint16_t   isan_type;
};

extern struct_desc isakmp_notification_desc;

/* IKEv2 Notification Payload
 * layout from RFC 4306 section 3.10
 * This is followed by a variable length SPI
 * and then possibly by variable length Notification Data.
 * Previous next payload: ISAKMP_NEXT_N
 *                      1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * ! Next Payload  !   RESERVED    !         Payload Length        !
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * !  Protocol-ID  !   SPI Size    !      Notify Message Type      !
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * !                                                               !
 * ~                Security Parameter Index (SPI)                 ~
 * !                                                               !
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * !                                                               !
 * ~                       Notification Data                       ~
 * !                                                               !
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
struct isakmp_notification2
{
    uint8_t    isan2_np;
    uint8_t    isan2_reserved;
    uint16_t   isan2_length;
    uint8_t    isan2_protoid;
    uint8_t    isan2_spisize;
    uint16_t   isan2_type;
};

/* ISAKMP Delete Payload
 * layout from draft-ietf-ipsec-isakmp-09.txt section 3.15
 * This is followed by a variable length SPI.
 * Previous next payload: ISAKMP_NEXT_D
 *                      1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * ! Next Payload  !   RESERVED    !         Payload Length        !
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * !              Domain of Interpretation  (DOI)                  !
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * !  Protocol-Id  !   SPI Size    !           # of SPIs           !
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * !                                                               !
 * ~               Security Parameter Index(es) (SPI)              ~
 * !                                                               !
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
struct isakmp_delete
{
    uint8_t    isad_np;
    uint8_t    isad_reserved;
    uint16_t   isad_length;
    uint32_t   isad_doi;
    uint8_t    isad_protoid;
    uint8_t    isad_spisize;
    uint16_t   isad_nospi;
};

/*
 *	Vendor ID (VID) payload - header only
 */
struct isakmp_vid
{
    uint8_t    isavid_np;
    uint8_t    isavid_reserved;
    uint16_t   isavid_length;
};

