/*
 * $Id$
 *
 * isakmp.h	-- Definitions for ISAKMP packet
 *
 * Author:	Roy Hills
 * Date:	31 July 2001
 *
 * Definitions for ISAKMP packet.  Adapted from FreeS/WAN "packet.h"
 *
 * Many of the types used come from <sys/types.h> which needs to be
 * included before this include file.
 *
 * Revision history:
 *
 * $Log$
 * Revision 1.1  2001/08/09 09:45:16  rsh
 * Initial revision
 *
 *
 */

/*
 * Define constants
 */

#define	COOKIE_SIZE	2	/* Size in 32-bit longwords */

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

#define ISAKMP_XCHG_NONE       0
#define ISAKMP_XCHG_BASE       1
#define ISAKMP_XCHG_IDPROT     2	/* ID Protection */
#define ISAKMP_XCHG_AO         3	/* Authentication Only */
#define ISAKMP_XCHG_AGGR       4	/* Aggressive */
#define ISAKMP_XCHG_INFO       5	/* Informational */

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

/*
 * Define packet structures
 */

/* ISAKMP Header: for all messages
 * layout from draft-ietf-ipsec-isakmp-09.txt section 3.1
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
    u_int32_t   isa_icookie[COOKIE_SIZE];
    u_int32_t   isa_rcookie[COOKIE_SIZE];
    u_int8_t    isa_np;                 /* Next payload */
    u_int8_t	isa_version;	/* high-order 4 bits: Major; low order 4: Minor */
    u_int8_t    isa_xchg;		/* Exchange type */
    u_int8_t    isa_flags;
    u_int32_t   isa_msgid;		/* Message ID (RAW) */
    u_int32_t   isa_length;		/* Length of message */
};

/* Generic portion of all ISAKMP payloads.
 * layout from draft-ietf-ipsec-isakmp-09.txt section 3.2
 * This describes the first 32-bit chunk of all payloads.
 * The previous next payload depends on the actual payload type.
 *                      1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * ! Next Payload  !   RESERVED    !         Payload Length        !
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
struct isakmp_generic
{
    u_int8_t    isag_np;
    u_int8_t    isag_reserved;
    u_int16_t   isag_length;
};

/* ISAKMP Data Attribute (generic representation within payloads)
 * layout from draft-ietf-ipsec-isakmp-09.txt section 3.3
 * This is not a payload type.
 * In TLV format, this is followed by a value field.
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
    u_int16_t isaat_af_type;   /* high order bit: AF; lower 15: rtype */
    u_int16_t isaat_lv;			/* Length or value */
};
/*
 *	This is a bodge for SA Attributes with 4-byte length.
 *	It is defined like this because I can't work out how to define
 *	the general case structure properly -rsh.
 */
struct isakmp_attribute2
{
    u_int16_t isaat_af_type;   /* high order bit: AF; lower 15: rtype */
    u_int16_t isaat_l;			/* Length - MUST BE 4 BYTES */
    u_int32_t isaat_v;		/* 32-bit value */
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
    u_int8_t  isasa_np;			/* Next payload */
    u_int8_t  isasa_reserved;
    u_int16_t isasa_length;		/* Payload length */
    u_int32_t isasa_doi;		/* DOI */
    u_int32_t isasa_situation;		/* Situation - 32 bits for IPsec DOI */
};

/* ISAKMP Proposal Payload
 * layout from draft-ietf-ipsec-isakmp-09.txt section 3.5
 * A variable length SPI follows.
 * Previous next payload: ISAKMP_NEXT_P
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
    u_int8_t    isap_np;
    u_int8_t    isap_reserved;
    u_int16_t   isap_length;
    u_int8_t    isap_proposal;
    u_int8_t    isap_protoid;
    u_int8_t    isap_spisize;
    u_int8_t    isap_notrans;		/* Number of transforms */
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
    u_int8_t    isat_np;
    u_int8_t    isat_reserved;
    u_int16_t   isat_length;
    u_int8_t    isat_transnum;		/* Number of the transform */
    u_int8_t    isat_transid;
    u_int16_t   isat_reserved2;
};

struct isakmp_kx
{
    u_int8_t    isakx_np;
    u_int8_t    isakx_reserved;
    u_int16_t   isakx_length;
    u_int32_t	isakx_data[32];
};

struct isakmp_nonce
{
    u_int8_t    isanonce_np;
    u_int8_t    isanonce_reserved;
    u_int16_t   isanonce_length;
    u_int32_t	isanonce_data[5];
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
    u_int8_t    isaid_np;
    u_int8_t    isaid_reserved;
    u_int16_t   isaid_length;
    u_int8_t    isaid_idtype;
    u_int8_t    isaid_doi_specific_a;
    u_int16_t   isaid_doi_specific_b;
    u_int8_t	isaid_data[8];		/* This is actually variable len. */
};

struct isakmp_vid
{
    u_int8_t    isavid_np;
    u_int8_t    isavid_reserved;
    u_int16_t   isavid_length;
    u_int32_t	isavid_data[10];
};
