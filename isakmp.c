/*
 * The IKE Scanner (ike-scan) is Copyright (C) 2003-2013 Roy Hills,
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
 * You are encouraged to submit comments, improvements or suggestions
 * at the github repository https://github.com/royhills/ike-scan
 *
 * Author: Roy Hills
 * Date: 7 November 2003
 *
 * Functions to construct ISAKMP headers and payloads.
 *
 */

#include "ike-scan.h"

const id_name_map notification_map[] = { /* From RFC 2408 3.14.1 */
   {0, "UNSPECIFIED"},
   {1, "INVALID-PAYLOAD-TYPE"},
   {2, "DOI-NOT-SUPPORTED"},
   {3, "SITUATION-NOT-SUPPORTED"},
   {4, "INVALID-COOKIE"},
   {5, "INVALID-MAJOR-VERSION"},
   {6, "INVALID-MINOR-VERSION"},
   {7, "INVALID-EXCHANGE-TYPE"},
   {8, "INVALID-FLAGS"},
   {9, "INVALID-MESSAGE-ID"},
   {10, "INVALID-PROTOCOL-ID"},
   {11, "INVALID-SPI"},
   {12, "INVALID-TRANSFORM-ID"},
   {13, "ATTRIBUTES-NOT-SUPPORTED"},
   {14, "NO-PROPOSAL-CHOSEN"},
   {15, "BAD-PROPOSAL-SYNTAX"},
   {16, "PAYLOAD-MALFORMED"},
   {17, "INVALID-KEY-INFORMATION"},
   {18, "INVALID-ID-INFORMATION"},
   {19, "INVALID-CERT-ENCODING"},
   {20, "INVALID-CERTIFICATE"},
   {21, "CERT-TYPE-UNSUPPORTED"},
   {22, "INVALID-CERT-AUTHORITY"},
   {23, "INVALID-HASH-INFORMATION"},
   {24, "AUTHENTICATION-FAILED"},
   {25, "INVALID-SIGNATURE"},
   {26, "ADDRESS-NOTIFICATION"},
   {27, "NOTIFY-SA-LIFETIME"},
   {28, "CERTIFICATE-UNAVAILABLE"},
   {29, "UNSUPPORTED-EXCHANGE-TYPE"},
   {30, "UNEQUAL-PAYLOAD-LENGTHS"},
   {9101, "Checkpoint-Firewall-1"},
   {9110, "Checkpoint-Firewall-1"},
   {24576, "RESPONDER-LIFETIME"},	/* Next 3 are from RFC 2407 4.6.3 */
   {24577, "REPLAY-STATUS"},
   {24578, "INITIAL-CONTACT"},
   {-1, NULL}
};
const id_name_map notification_map2[] = { /* From RFC 5996 3.10.1 */
   {0, "RESERVED"},
   {1, "UNSUPPORTED_CRITICAL_PAYLOAD"},
   {4, "INVALID_IKE_SPI"},
   {5, "INVALID_MAJOR_VERSION"},
   {7, "INVALID_SYNTAX"},
   {9, "INVALID_MESSAGE_ID"},
   {11, "INVALID_SPI"},
   {14, "NO_PROPOSAL_CHOSEN"},
   {17, "INVALID_KE_PAYLOAD"},
   {24, "AUTHENTICATION_FAILED"},
   {34, "SINGLE_PAIR_REQUIRED"},
   {35, "NO_ADDITIONAL_SAS"},
   {36, "INTERNAL_ADDRESS_FAILURE"},
   {37, "FAILED_CP_REQUIRED"},
   {38, "TS_UNACCEPTABLE"},
   {39, "INVALID_SELECTORS"},
   {43, "TEMPORARY_FAILURE"},
   {44, "CHILD_SA_NOT_FOUND"},
   {9101, "Checkpoint-Firewall-1"},
   {9110, "Checkpoint-Firewall-1"},
   {16384, "INITIAL_CONTACT"},
   {16385, "SET_WINDOW_SIZE"},
   {16386, "ADDITIONAL_TS_POSSIBLE"},
   {16387, "IPCOMP_SUPPORTED"},
   {16388, "NAT_DETECTION_SOURCE_IP"},
   {16389, "NAT_DETECTION_DESTINATION_IP"},
   {16390, "COOKIE"},
   {16391, "USE_TRANSPORT_MODE"},
   {16392, "HTTP_CERT_LOOKUP_SUPPORTED"},
   {16393, "REKEY_SA"},
   {16394, "ESP_TFC_PADDING_NOT_SUPPORTED"},
   {16395, "NON_FIRST_FRAGMENTS_ALSO"},
   {-1, NULL}
};
const id_name_map attr_map[] = {	/* From RFC 2409 App. A and */
   {1, "Enc"},			/* draft-ietf-ipsec-isakmp-gss-auth */
   {2, "Hash"},
   {3, "Auth"},
   {4, "Group"},
   {5, "GroupType"},
   {6, "GroupPrime/IrreduciblePolynomial"},
   {7, "GroupGeneratorOne"},
   {8, "GroupGeneratorTwo"},
   {9, "GroupCurve A"},
   {10, "GroupCurve B"},
   {11, "LifeType"},
   {12, "LifeDuration"},
   {13, "PRF"},
   {14, "KeyLength"},
   {15, "FieldSize"},
   {16, "GroupOrder"},
   {16384, "GSSIdentityName"},
   {-1, NULL}
};
const id_name_map trans_type_map[] = {	/* From RFC 5996 3.3.2 */
   {1, "Encr"},
   {2, "Prf"},
   {3, "Integ"},
   {4, "DH_Group"},
   {5, "ESN"},
   {-1, NULL}
};
const id_name_map enc_map[] = {	/* From RFC 2409 App. A */
   {1, "DES"},
   {2, "IDEA"},
   {3, "Blowfish"},
   {4, "RC5"},
   {5, "3DES"},
   {6, "CAST"},
   {7, "AES"},		/* RFC 3602 */
   {8, "Camellia"},	/* RFC 4312 */
   {65001, "Mars"},	/* Defined in strongSwan constants.h */
   {65002, "RC6"},	/* Defined in strongSwan constants.h */
   {65003, "ID_65003"},	/* Defined in strongSwan constants.h */
   {65004, "Serpent"},	/* Defined in strongSwan constants.h */
   {65005, "Twofish"},	/* Defined in strongSwan constants.h */
   {-1, NULL}
};
const id_name_map encr_map[] = {	/* From RFC 5996 (IKEv2) 3.3.2 */
   {1, "DES_IV64"},
   {2, "DES"},
   {3, "3DES"},
   {4, "RC5"},
   {5, "IDEA"},
   {6, "CAST"},
   {7, "Blowfish"},
   {8, "3IDEA"},
   {9, "DES_IV32"},
   {11, "NULL"},
   {12, "AES_CBC"},
   {13, "AES_CTR"},
   {14, "AES_CCM_ICV8"},		/* RFC 5282 */
   {15, "AES_CCM_ICV12"},		/* RFC 5282 */
   {16, "AES_CCM_ICV16"},		/* RFC 5282 */
   {18, "AES_GCM_ICV8"},		/* RFC 5282 */
   {19, "AES_GCM_ICV12"},		/* RFC 5282 */
   {20, "AES_GCM_ICV16"},		/* RFC 5282 */
   {23, "CAMELLIA_CBC"},		/* RFC 5996 */
   {-1, NULL}
};
const id_name_map hash_map[] = {	/* From RFC 2409 App. A */
   {1, "MD5"},
   {2, "SHA1"},
   {3, "Tiger"},
   {4, "SHA2-256"},
   {5, "SHA2-384"},
   {6, "SHA2-512"},
   {-1, NULL}
};
const id_name_map prf_map[] = {		/* From RFC 5996 3.3.2 */
   {1, "HMAC_MD5"},
   {2, "HMAC_SHA1"},
   {3, "HMAC_TIGER"},
   {4, "AES128_XCBC"},		/* RFC 4434 */
   {5, "HMAC_SHA2_256"},	/* RFC 4868 */
   {6, "HMAC_SHA2_384"},	/* RFC 4868 */
   {7, "HMAC_SHA2_512"},	/* RFC 4868 */
   {8, "HMAC_AES128_CMAC"},	/* RFC 4615 */
   {-1, NULL}
};
const id_name_map auth_map[] = {	/* From RFC 2409 App. A */
   {1, "PSK"},
   {2, "DSS"},
   {3, "RSA_Sig"},
   {4, "RSA_Enc"},
   {5, "RSA_RevEnc"},
   {6, "ElGamel_Enc"},
   {7, "ElGamel_RevEnc"},
   {8, "ECDSA_Sig"},
   {9, "ECDSA_SHA256"},		/* RFC 4754 */
   {10, "ECDSA_SHA384"},	/* RFC 4754 */
   {11, "ECDSA_SHA512"},	/* RFC 4754 */
   {128, "CRACK"},		/* draft-harkins-ipsra-crack-00 */
   {64221, "Hybrid_RSA"},	/* draft-ietf-ipsec-isakmp-hybrid-auth-05 */
   {64223, "Hybrid_DSS"},	/* draft-ietf-ipsec-isakmp-hybrid-auth-05 */
   {65001, "XAUTH_PSK"},	/* draft-ietf-ipsec-isakmp-xauth-06 */
   {65003, "XAUTH_DSS"},	/* draft-ietf-ipsec-isakmp-xauth-06 */
   {65005, "XAUTH_RSA"},	/* draft-ietf-ipsec-isakmp-xauth-06 */
   {65007, "XAUTH_RSA_Enc"},	/* draft-ietf-ipsec-isakmp-xauth-06 */
   {65009, "XAUTH_RSA_RevEnc"},	/* draft-ietf-ipsec-isakmp-xauth-06 */
   {-1, NULL}
};
const id_name_map integ_map[] = {	/* From RFC 5996 3.3.2 */
   {1, "HMAC_MD5_96"},
   {2, "HMAC_SHA1_96"},
   {3, "DES_MAC"},
   {4, "KPDK_MD5"},
   {5, "AES_XCBC_96"},
   {6, "HMAC_MD5_128"},		/* RFC 4595 */
   {7, "HMAC_SHA1_160"},	/* RFC 4595 */
   {8, "AES_CMAC_96"},		/* RFC 4494 */
   {9, "AES_128_GMAC"},		/* RFC 4543 */
   {10, "AES_192_GMAC"},	/* RFC 4543 */
   {11, "AES_256_GMAC"},	/* RFC 4543 */
   {12, "HMAC_SHA2_256_128"},	/* RFC 4868 */
   {13, "HMAC_SHA2_384_192"},	/* RFC 4868 */
   {14, "HMAC_SHA2_512_256"},	/* RFC 4868 */
   {-1, NULL}
};
const id_name_map dh_map[] = {	/* From RFC 2409 App. A */
   {1, "1:modp768"},
   {2, "2:modp1024"},
   {3, "3:ec2n155"},
   {4, "4:ec2n185"},
   {5, "5:modp1536"},	/* RFC 3526 */
   {6, "6:ec2n163"},
   {7, "7:ec2n163"},
   {8, "8:ec2n283"},
   {9, "9:ec2n283"},
   {10, "10:ec2n409"},
   {11, "11:ec2n409"},
   {12, "12:ec2n571"},
   {13, "13:ec2n571"},
   {14, "14:modp2048"},	/* RFC 3526 */
   {15, "15:modp3072"},	/* RFC 3526 */
   {16, "16:modp4096"},	/* RFC 3526 */
   {17, "17:modp6144"},	/* RFC 3526 */
   {18, "18:modp8192"},	/* RFC 3526 */
   {19, "19:ecp256"},	/* RFC 5903 */
   {20, "20:ecp384"},	/* RFC 5903 */
   {21, "21:ecp521"},	/* RFC 5903 */
   {22, "22:modp1024s160"},	/* RFC 5114 */
   {23, "23:modp2048s224"},	/* RFC 5114 */
   {24, "24:modp2048s256"},	/* RFC 5114 */
   {25, "25:ecp192"},	/* RFC 5114 */
   {26, "26:ecp224"},	/* RFC 5114 */
   {27, "27:brainpoolP224r1"},	/* RFC 6954 */
   {28, "28:brainpoolP256r1"},	/* RFC 6954 */
   {29, "29:brainpoolP384r1"},	/* RFC 6954 */
   {30, "30:brainpoolP512r1"},	/* RFC 6954 */
   {-1, NULL}
};
const id_name_map life_map[] = {	/* From RFC 2409 App. A */
   {1, "Seconds"},
   {2, "Kilobytes"},
   {-1, NULL}
};
const id_name_map payload_map[] = {	/* Payload types from RFC 2408 3.1 */
   {1, "SecurityAssociation"},		/* and RFC 4306 3.2 */
   {2, "Proposal"},
   {3, "Transform"},
   {4, "KeyExchange"},
   {5, "Identification"},
   {6, "Certificate"},
   {7, "CertificateRequest"},
   {8, "Hash"},
   {9, "Signature"},
   {10, "Nonce"},
   {11, "Notification"},
   {12, "Delete"},
   {13, "VendorID"},
   {20, "NAT-D"},		/* RFC 3947 NAT Discovery */
   {33, "SecurityAssociation"},	/* Values 33-48 are from RFC 5996 IKEv2 */
   {34, "KeyExchange"},
   {35, "IDI"},
   {36, "IDR"},
   {37, "Certificate"},
   {38, "CertificateRequest"},
   {39, "AUTH"},
   {40, "Nonce"},
   {41, "Notification"},
   {42, "Delete"},
   {43, "VendorID"},
   {44, "TSI"},
   {45, "TSR"},
   {46, "Encrypted"},
   {47, "Configuration"},
   {48, "EAP"},
   {49, "GSPM"},		/* RFC 6467 */
   {-1, NULL}
};
const id_name_map doi_map[] = {
   {0, "ISAKMP"},
   {1, "IPsec"},
   {2, "GDOI"},		/* RFC 6407 */
   {-1, NULL}
};
const id_name_map protocol_map[] = {
   {1, "PROTO_ISAKMP"},
   {2, "PROTO_IPSEC_AH"},
   {3, "PROTO_IPSEC_ESP"},
   {4, "PROTO_IPSEC_COMP"},
   {-1, NULL}
};
const id_name_map id_map[] = {	/* From RFC 2407 4.6.2.1 */
   {1, "ID_IPV4_ADDR"},
   {2, "ID_FQDN"},
   {3, "ID_USER_FQDN"},
   {4, "ID_IPV4_ADDR_SUBNET"},
   {5, "ID_IPV6_ADDR"},
   {6, "ID_IPV6_ADDR_SUBNET"},
   {7, "ID_IPV4_ADDR_RANGE"},
   {8, "ID_IPV6_ADDR_RANGE"},
   {9, "ID_DER_ASN1_DN"},
   {10, "ID_DER_ASN1_GN"},
   {11, "ID_KEY_ID"},
};
const id_name_map cert_map[] = {	/* From RFC 2408 Sec. 3.9 */
   {1, "PKCS #7 wrapped X.509 certificate"},
   {2, "PGP Certificate"},
   {3, "DNS Signed Key"},
   {4, "X.509 Certificate - Signature"},
   {5, "X.509 Certificate - Key Exchange"},
   {6, "Kerberos Tokens"},
   {7, "Certificate Revocation List (CRL)"},
   {8, "Authority Revocation List (ARL)"},
   {9, "SPKI Certificate"},
   {10, "X.509 Certificate - Attribute"},
   {-1, NULL}
};

extern psk_crack psk_values;
extern int mbz_value;

/*
 *	make_isakmp_hdr -- Construct an ISAKMP Header
 *
 *	Inputs:
 *
 *	xchg		Exchange Type (e.g. ISAKMP_XCHG_IDPROT for main mode)
 *	next		Next Payload Type
 *	length		ISAKMP Message total length
 *	header_version	Version number to put in the header
 *	hdr_flags	Flags to put in the header
 *	hdr_msgid	Message ID to put in the header
 *	rcookie_data	Responder cookie data, or NULL for default
 *	rcookie_data_len Length of responder cookie data (<=8)
 *
 *	Returns:
 *
 *	Pointer to created ISAKMP Header.
 *
 *	This constructs an ISAKMP header.  It fills in the static values.
 *	The initiator cookie should be changed to a unique per-host value
 *	before the packet is sent.
 */
unsigned char*
make_isakmp_hdr(unsigned xchg, unsigned next, unsigned length,
                int header_version, int hdr_flags, unsigned hdr_msgid,
                unsigned char *rcookie_data, size_t rcookie_data_len) {
   unsigned char *payload;
   struct isakmp_hdr* hdr;

   payload = Malloc(sizeof(struct isakmp_hdr));
   hdr = (struct isakmp_hdr*) payload;	/* Overlay header struct on payload */
   memset(hdr, mbz_value, sizeof(struct isakmp_hdr));

   hdr->isa_icookie[0] = 0xdeadbeef;	/* Initiator cookie */
   hdr->isa_icookie[1] = 0xdeadbeef;
   hdr->isa_rcookie[0] = 0;		/* Set responder cookie to 0 */
   hdr->isa_rcookie[1] = 0;
   if (rcookie_data) {
      memcpy(hdr->isa_rcookie, rcookie_data, rcookie_data_len);
   }
   hdr->isa_np = next;			/* Next Payload Type */
   hdr->isa_version = header_version;	/* v1.0 by default */
   hdr->isa_xchg = xchg;		/* Exchange type */
   hdr->isa_flags = hdr_flags;		/* Flags */
   hdr->isa_msgid = htonl(hdr_msgid);	/* Message ID */
   hdr->isa_length = htonl(length);	/* Total ISAKMP message length */

   return payload;
}

/*
 *	make_sa -- Construct an SA payload
 *
 *	Inputs:
 *
 *	outlen		(output) length of SA payload
 *	next    	Next Payload Type
 *	doi		Domain of interpretation
 *	situation	Situation
 *	proposals	Pointer to list of proposals
 *	proposal_len	length of proposal list
 *
 *	Returns:
 *
 *	Pointer to the SA payload.
 *
 *	This constructs an SA payload.
 */
unsigned char*
make_sa(size_t *outlen, unsigned next, unsigned doi, unsigned situation,
        unsigned char *proposals, size_t proposal_len) {
   unsigned char *payload;
   struct isakmp_sa* hdr;
   unsigned char *cp;
   size_t len;

   hdr = Malloc(sizeof(struct isakmp_sa));
   memset(hdr, mbz_value, sizeof(struct isakmp_sa));

   hdr->isasa_np = next;		/* Next Payload Type */
   hdr->isasa_doi = htonl(doi);	/* Default is IPsec DOI */
   hdr->isasa_situation = htonl(situation); /* Default SIT_IDENTITY_ONLY */

   len = sizeof(struct isakmp_sa) + proposal_len;
   hdr->isasa_length = htons(len);		/* SA Payload length */
   payload = Malloc(len);
   cp = payload;

   memcpy(cp, hdr, sizeof(struct isakmp_sa));
   cp += sizeof(struct isakmp_sa);
   memcpy(cp, proposals, proposal_len);

   *outlen = len;
   return payload;
}

/*
 *	make_sa2 -- Construct an IKEv2 SA payload
 *
 *	Inputs:
 *
 *	outlen		(output) length of SA payload
 *	next    	Next Payload Type
 *	proposals	Pointer to list of proposals
 *	proposal_len	length of proposal list
 *
 *	Returns:
 *
 *	Pointer to the SA payload.
 *
 *	This constructs an IKEv2 SA payload.
 */
unsigned char*
make_sa2(size_t *outlen, unsigned next,
         unsigned char *proposals, size_t proposal_len) {
   unsigned char *payload;
   struct isakmp_sa2* hdr;
   unsigned char *cp;
   size_t len;

   hdr = Malloc(sizeof(struct isakmp_sa2));
   memset(hdr, mbz_value, sizeof(struct isakmp_sa2));

   hdr->isasa2_np = next;		/* Next Payload Type */

   len = sizeof(struct isakmp_sa2) + proposal_len;
   hdr->isasa2_length = htons(len);		/* SA Payload length */
   payload = Malloc(len);
   cp = payload;

   memcpy(cp, hdr, sizeof(struct isakmp_sa2));
   free(hdr);
   cp += sizeof(struct isakmp_sa2);
   memcpy(cp, proposals, proposal_len);

   *outlen = len;
   return payload;
}

/*
 *	add_prop -- Add a proposal payload to the list of proposals
 *
 *	Inputs:
 *
 *	outlen		(output) Proposal payload length
 *	notrans		Number of transforms in this proposal
 *	protocol	Protocol
 *	spi_size	SPI Size
 *	transforms  Pointer to transform list
 *	transform_len   Length of transform list
 *
 *	Returns:
 *
 *	Pointer to proposal payload.
 *
 *  This function can either be called with finished = 0, in which case
 *  notrans, protocol, spi_size, transforms and transform_len must be
 *  specified, and the function will return NULL, OR it can be called with
 *  finished = 1 in which case notrans, protocol, spi_size, transforms and
 *  transform_len are ignored and the function will return a pointer to the
 *  finished payload and will set *length to the length of this payload.
 *
 *  ISAKMP SAs are only allowed to contain one proposal, RFC 2409 section 5
 *  states:
 *
 *	"To put it another way, for phase 1 exchanges there MUST NOT be
 *	multiple Proposal Payloads for a single SA payload and there MUST NOT
 *	be multiple SA payloads."
 *
 *  However, this function does not enforce this restriction.
 */
unsigned char*
add_prop(int finished, size_t *outlen,
         unsigned notrans, unsigned protocol, unsigned spi_size,
         unsigned char *transforms, size_t transform_len) {

   static int first_proposal = 1;
   static unsigned char *prop_start=NULL;	/* Start of set of proposals */
   static size_t cur_offset;			/* Start of current proposal */
   static size_t end_offset;			/* End of proposals */
   static unsigned prop_no=1;
   unsigned char *prop;			/* Proposal payload */
   size_t len;					/* Proposal length */
/*
 * Construct a proposal if we are not finalising.
 * Set next to ISAKMP_NEXT_P (more proposals), and increment prop_no for next
 * time round.
 */
   if (!finished) {
      prop = make_prop(&len, ISAKMP_NEXT_P, prop_no, notrans, protocol,
                       spi_size, transforms, transform_len);
      prop_no++;
      if (first_proposal) {
         cur_offset = 0;
         end_offset = len;
         prop_start = Malloc(end_offset);
         memcpy(prop_start, prop, len);
         first_proposal = 0;
      } else {
         cur_offset = end_offset;
         end_offset += len;
         prop_start = Realloc(prop_start, end_offset);
         memcpy(prop_start+cur_offset, prop, len);
      }
      free(prop);
      return NULL;
   } else {
      struct isakmp_proposal* hdr =
         (struct isakmp_proposal*) (prop_start+cur_offset);	/* Overlay */

      first_proposal = 1;
      hdr->isap_np = ISAKMP_NEXT_NONE;		/* No more proposals */
      *outlen = end_offset;
      return prop_start;
   }
}

/*
 *	make_prop -- Construct a proposal payload
 *
 *	Inputs:
 *
 *	outlen		(output) Proposal payload length
 *	next		next payload (2=more props, 0=no more props)
 *	number		proposal number
 *	notrans		Number of transforms in this proposal
 *	protocol	Protocol
 *	spi_size	SPI Size
 *	transforms  Pointer to transform list
 *	transform_len   Length of transform list
 *
 *	Returns:
 *
 *	Pointer to proposal payload.
 *
 *	This constructs a single proposal payload.
 */
unsigned char*
make_prop(size_t *outlen, unsigned next, unsigned number, unsigned notrans,
          unsigned protocol, unsigned spi_size, unsigned char *transforms,
          size_t transform_len) {
   unsigned char *payload;
   struct isakmp_proposal* hdr;
   unsigned char *cp;
   size_t len;

/* Allocate and initialise the proposal header */

   hdr = Malloc(sizeof(struct isakmp_proposal));
   memset(hdr, mbz_value, sizeof(struct isakmp_proposal));

   hdr->isap_np = next;
   hdr->isap_proposal = number;
   hdr->isap_protoid = protocol;
   hdr->isap_spisize = spi_size;	/* SPI Size */
   hdr->isap_notrans = notrans;		/* Number of transforms */

/* Determine total SA length and allocate payload memory */

   len = sizeof(struct isakmp_proposal) + spi_size + transform_len;
   hdr->isap_length = htons(len);	/* Proposal payload length */
   payload = Malloc(len);
   cp = payload;

/* Copy the proposal header to the payload */

   memcpy(cp, hdr, sizeof(struct isakmp_proposal));
   cp += sizeof(struct isakmp_proposal);
   free(hdr);

/* If the SPI size is non-zero, add a random SPI of the specified length */

   if (spi_size > 0) {
      unsigned i;

      for (i=0; i<spi_size; i++)
         *(cp++) = (unsigned char) random_byte();
   }

/* Add the transforms */

   memcpy(cp, transforms, transform_len);

   *outlen = len;
   return payload;
}

/*
 *	make_trans_simple -- Construct a single simple transform payload
 *
 *	Inputs:
 *
 *	length	(output) length of entire transform payload.
 *	next    Next Payload Type (3 = More transforms; 0=No more transforms)
 *	number	Transform number
 *	cipher	The encryption algorithm
 *	keylen	Key length for variable length keys (0=fixed key length)
 *	hash	Hash algorithm
 *	auth	Authentication method
 *	group	DH Group number
 *	lifetime	Lifetime in seconds (0=no lifetime)
 *	lifesize	Life in kilobytes (0=no life)
 *
 *	Returns:
 *
 *	Pointer to transform payload.
 *
 *	This constructs a single simple transform payload.
 *	Most of the values are defined in RFC 2409 Appendix A.
 *
 *	This function can only create a transform with a restricted set of
 *	attributes in a defined order. To create a transform with an arbitrary
 *	set of attributes in any order, use the make_transform function
 *	instead.
 */
unsigned char*
make_trans_simple(size_t *length, unsigned next, unsigned number,
           unsigned cipher, unsigned keylen, unsigned hash, unsigned auth,
           unsigned group, unsigned char *lifetime_data,
           size_t lifetime_data_len, unsigned char *lifesize_data,
           size_t lifesize_data_len, int gss_id_flag, unsigned char *gss_data,
           size_t gss_data_len, unsigned trans_id) {

   unsigned char *payload;
   unsigned char *attr;
   size_t attr_len;			/* Attribute Length */

/* Allocate and initialise the mandatory attributes */

   add_attr(0, NULL, 'B', OAKLEY_ENCRYPTION_ALGORITHM, 0, cipher, NULL);
   add_attr(0, NULL, 'B', OAKLEY_HASH_ALGORITHM, 0, hash, NULL);
   add_attr(0, NULL, 'B', OAKLEY_AUTHENTICATION_METHOD, 0, auth, NULL);
   add_attr(0, NULL, 'B', OAKLEY_GROUP_DESCRIPTION, 0, group, NULL);

/* Allocate and initialise the optional attributes */

   if (keylen)
      add_attr(0, NULL, 'B', OAKLEY_KEY_LENGTH, 0, keylen, NULL);

   if (lifetime_data_len) {
      add_attr(0, NULL, 'B', OAKLEY_LIFE_TYPE, 0, SA_LIFE_TYPE_SECONDS, NULL);
      add_attr(0, NULL, 'V', OAKLEY_LIFE_DURATION, lifetime_data_len, 0,
               lifetime_data);
   }

   if (lifesize_data_len) {
      add_attr(0, NULL, 'B', OAKLEY_LIFE_TYPE, 0, SA_LIFE_TYPE_KBYTES, NULL);
      add_attr(0, NULL, 'V', OAKLEY_LIFE_DURATION, lifesize_data_len, 0,
               lifesize_data);
   }

   if (gss_id_flag)
      add_attr(0, NULL, 'V', OAKLEY_GSS_ID, gss_data_len, 0, gss_data);

/* Finalise attributes and fill in length value */

   attr = add_attr(1, &attr_len, '\0', 0, 0, 0, NULL);

/* Create transform */

   payload = make_transform(length, next, number, trans_id, attr, attr_len);
   free(attr);

   return payload;
}

/*
 *	add_trans_simple -- Add a simple transform payload to set of transforms.
 *
 *	Inputs:
 *
 *	finished	0 if adding a new transform; 1 if finalising.
 *	length	(output) length of entire transform payload.
 *	cipher	The encryption algorithm
 *	keylen	Key length for variable length keys (0=fixed key length)
 *	hash	Hash algorithm
 *	auth	Authentication method
 *	group	DH Group number
 *	lifetime	Lifetime in seconds (0=no lifetime)
 *
 *	Returns:
 *
 *	Pointer to new set of transform payloads.
 *
 *	This function can either be called with finished = 0, in which case
 *	cipher, keylen, hash, auth, group and lifetime must be specified, and
 *	the function will return NULL, OR it can be called with finished = 1
 *	in which case cipher, keylen, hash, auth, group and lifetime are
 *	ignored and the function will return a pointer to the finished
 *	payload and will set *length to the length of this payload.
 *
 *	This function can only create transforms with a restricted set of
 *	attributes in a defined order. To create transforms with an arbitrary
 *	set of attributes in any order, use the add_transform function
 *	instead.
 */
unsigned char*
add_trans_simple(int finished, size_t *length, unsigned cipher,
                 unsigned keylen, unsigned hash, unsigned auth,
                 unsigned group, unsigned char *lifetime_data,
                 size_t lifetime_data_len, unsigned char *lifesize_data,
                 size_t lifesize_data_len, int gss_id_flag,
                 unsigned char *gss_data, size_t gss_data_len,
                 unsigned trans_id) {

   static int first_transform = 1;
   static unsigned char *trans_start=NULL;	/* Start of set of transforms */
   static size_t cur_offset;			/* Start of current transform */
   static size_t end_offset;			/* End of transforms */
   static unsigned trans_no=1;
   unsigned char *trans;			/* Transform payload */
   size_t len;					/* Transform length */
/*
 * Construct a transform if we are not finalising.
 * Set next to ISAKMP_NEXT_T (more transforms), and increment trans_no for
 * next time round.
 */
   if (!finished) {
      trans = make_trans_simple(&len, ISAKMP_NEXT_T, trans_no, cipher, keylen,
                                hash, auth, group, lifetime_data,
                                lifetime_data_len, lifesize_data,
                                lifesize_data_len, gss_id_flag, gss_data,
                                gss_data_len, trans_id);
      trans_no++;
      if (first_transform) {
         cur_offset = 0;
         end_offset = len;
         trans_start = Malloc(end_offset);
         memcpy(trans_start, trans, len);
         first_transform = 0;
      } else {
         cur_offset = end_offset;
         end_offset += len;
         trans_start = Realloc(trans_start, end_offset);
         memcpy(trans_start+cur_offset, trans, len);
      }
      free(trans);
      return NULL;
   } else {
      struct isakmp_transform* hdr =
         (struct isakmp_transform*) (trans_start+cur_offset);	/* Overlay */

      first_transform = 1;
      hdr->isat_np = 0;		/* No more transforms */
      *length = end_offset;
      return trans_start;
   }
}

/*
 *	make_transform -- Construct a single transform payload
 *
 *	Inputs:
 *
 *	length	(output) length of entire transform payload.
 *	next    Next Payload Type (3 = More transforms; 0=No more transforms)
 *	number	Transform number
 *	trans_id Transform ID (generally KEY_IKE)
 *	attr	Pointer to list of attributes
 *	attr_len Attribute length in bytes
 *
 *	Returns:
 *
 *	Pointer to transform payload.
 *
 *	This constructs a single transform payload.
 *	Most of the values are defined in RFC 2409 Appendix A.
 */
unsigned char*
make_transform(size_t *length, unsigned next, unsigned number,
               unsigned trans_id, unsigned char *attr, size_t attr_len) {

   struct isakmp_transform* hdr;	/* Transform header */
   unsigned char *payload;
   unsigned char *cp;
   size_t len;				/* Payload Length */

/* Allocate and initialise the transform header */

   hdr = Malloc(sizeof(struct isakmp_transform));
   memset(hdr, mbz_value, sizeof(struct isakmp_transform));

   hdr->isat_np = next;			/* Next payload type */
   hdr->isat_transnum = number;		/* Transform Number */
   hdr->isat_transid = trans_id;

   len = attr_len + sizeof(struct isakmp_transform);
   hdr->isat_length = htons(len);	/* Transform length */
   *length = len;

/* Allocate memory for payload and copy structures to payload */

   payload = Malloc(len);

   cp = payload;
   memcpy(cp, hdr, sizeof(struct isakmp_transform));
   free(hdr);
   cp += sizeof(struct isakmp_transform);
   memcpy(cp, attr, attr_len);

   return payload;
}

/*
 *	add_transform -- Add a transform payload to set of transforms.
 *
 *	Inputs:
 *
 *	finished	0 if adding a new transform; 1 if finalising.
 *	length	(output) length of entire transform payload.
 *	trans_id	Transform ID
 *	attr		Pointer to list of attributes
 *	attr_len	Length of attribute list
 *
 *	Returns:
 *
 *	Pointer to new set of transform payloads.
 *
 *	This function can either be called with finished = 0, in which case
 *	attr and attr_len must be specified, and the function will return NULL,
 *	OR it can be called with finished = 1 in which case attr and attr_len
 *	are ignored and the function will return a pointer to the finished
 *	payload and will set *length to the length of this payload.
 */
unsigned char*
add_transform(int finished, size_t *length, unsigned trans_id,
              unsigned char *attr, size_t attr_len) {

   static int first_transform = 1;
   static unsigned char *trans_start=NULL;	/* Start of set of transforms */
   static size_t cur_offset;			/* Start of current transform */
   static size_t end_offset;			/* End of transforms */
   static unsigned trans_no=1;
   unsigned char *trans;			/* Transform payload */
   size_t len;					/* Transform length */
/*
 * Construct a transform if we are not finalising.
 * Set next to ISAKMP_NEXT_T (more transforms), and increment trans_no for
 * next time round.
 */
   if (!finished) {
      trans = make_transform(&len, ISAKMP_NEXT_T, trans_no, trans_id, attr,
                             attr_len);
      trans_no++;
      if (first_transform) {
         cur_offset = 0;
         end_offset = len;
         trans_start = Malloc(end_offset);
         memcpy(trans_start, trans, len);
         first_transform = 0;
      } else {
         cur_offset = end_offset;
         end_offset += len;
         trans_start = Realloc(trans_start, end_offset);
         memcpy(trans_start+cur_offset, trans, len);
      }
      free(trans);
      return NULL;
   } else {
      struct isakmp_transform* hdr =
         (struct isakmp_transform*) (trans_start+cur_offset);	/* Overlay */

      first_transform = 1;
      hdr->isat_np = ISAKMP_NEXT_NONE;		/* No more transforms */
      *length = end_offset;
      return trans_start;
   }
}

/*
 *	make_transform2 -- Construct a single IKEv2 transform payload
 *
 *	Inputs:
 *
 *	length		(output) length of entire transform payload.
 *	next		Next Payload Type (3 = More transforms; 0=No more transforms)
 *	trans_type	Transform type
 *	trans_id	Transform ID
 *	attr		Pointer to list of attributes, or NULL for no attributes
 *	attr_len 	Attribute length in bytes. Zero if no attributes.
 *
 *	Returns:
 *
 *	Pointer to transform payload.
 *
 *	This constructs a single IKEv2 transform payload.
 *	Most of the values are defined in RFC 5996 Section 3.3.
 */
unsigned char*
make_transform2(size_t *length, unsigned next, unsigned trans_type,
                unsigned trans_id, unsigned char *attr, size_t attr_len) {

   struct isakmp_transform2* hdr;	/* Transform header */
   unsigned char *payload;
   unsigned char *cp;
   size_t len;				/* Payload Length */

/* Allocate and initialise the transform header */

   hdr = Malloc(sizeof(struct isakmp_transform2));
   memset(hdr, mbz_value, sizeof(struct isakmp_transform2));

   hdr->isat2_np = next;		/* Next payload type */
   hdr->isat2_transtype = trans_type;	/* Transform Type */
   hdr->isat2_transid = htons(trans_id);	/* Transform ID */

   len = attr_len + sizeof(struct isakmp_transform2);
   hdr->isat2_length = htons(len);	/* Transform length */
   *length = len;

/* Allocate memory for payload and copy structures to payload */

   payload = Malloc(len);

   cp = payload;
   memcpy(cp, hdr, sizeof(struct isakmp_transform2));
   free(hdr);
   cp += sizeof(struct isakmp_transform2);
   memcpy(cp, attr, attr_len);

   return payload;
}

/*
 *	add_transform2 -- Add a transform payload to set of transforms.
 *
 *	Inputs:
 *
 *	finished	0 if adding a new transform; 1 if finalising.
 *	length	(output) length of entire transform payload.
 *	trans_type	Transform type
 *	trans_id	Transform ID
 *	attr		Pointer to list of attributes
 *	attr_len	Length of attribute list
 *
 *	Returns:
 *
 *	Pointer to new set of transform payloads.
 *
 *	This function can either be called with finished = 0, in which case
 *	attr and attr_len must be specified, and the function will return NULL,
 *	OR it can be called with finished = 1 in which case attr and attr_len
 *	are ignored and the function will return a pointer to the finished
 *	payload and will set *length to the length of this payload.
 */
unsigned char*
add_transform2(int finished, size_t *length, unsigned trans_type,
               unsigned trans_id, unsigned char *attr, size_t attr_len) {

   static int first_transform = 1;
   static unsigned char *trans_start=NULL;	/* Start of set of transforms */
   static size_t cur_offset;			/* Start of current transform */
   static size_t end_offset;			/* End of transforms */
   unsigned char *trans;			/* Transform payload */
   size_t len;					/* Transform length */
/*
 * Construct a transform if we are not finalising.
 * Set next to ISAKMP_NEXT_T (more transforms)
 */
   if (!finished) {
      trans = make_transform2(&len, ISAKMP_NEXT_T, trans_type, trans_id, attr,
                              attr_len);
      if (first_transform) {
         cur_offset = 0;
         end_offset = len;
         trans_start = Malloc(end_offset);
         memcpy(trans_start, trans, len);
         first_transform = 0;
      } else {
         cur_offset = end_offset;
         end_offset += len;
         trans_start = Realloc(trans_start, end_offset);
         memcpy(trans_start+cur_offset, trans, len);
      }
      free(trans);
      return NULL;
   } else {
      struct isakmp_transform2* hdr =
         (struct isakmp_transform2*) (trans_start+cur_offset);	/* Overlay */

      first_transform = 1;
      hdr->isat2_np = ISAKMP_NEXT_NONE;		/* No more transforms */
      *length = end_offset;
      return trans_start;
   }
}

/*
 *	make_attr -- Construct a transform attribute
 *
 *	Inputs:
 *
 *	outlen	(output) Total length of transform attribute.
 *	type	Attribute Type.  'B' = basic, 'V' = variable.
 *	class	Attribute Class
 *	length	Attribute data length for variable type (ignored for basic).
 *	b_value	Basic Attribute Value
 *	v_value	Pointer to Variable Attribute Value
 *
 *	Returns:
 *
 *	Pointer to transform attribute.
 *
 *	For variable attribute types, the data must be in network byte
 *	order, and its length should be a multiple of 4 bytes to avoid
 *	alignment issues.
 *
 *	If type is "B", then length and v_value are ignored.  If type is "V",
 *	then b_value is ignored.
 */
unsigned char *
make_attr(size_t *outlen, int type, unsigned class, size_t length,
          unsigned b_value, void *v_value) {
   struct isakmp_attribute *hdr;
   unsigned char *cp;
   size_t total_len;

   total_len = sizeof(struct isakmp_attribute);
   if (type == 'V')
      total_len += length;

   cp = Malloc(total_len);
   hdr = (struct isakmp_attribute *) cp;
   memset(hdr, mbz_value, sizeof(struct isakmp_attribute));

   if (type == 'B') {	/* Basic Attribute */
      hdr->isaat_af_type = htons(class | 0x8000);
      hdr->isaat_lv = htons(b_value);
   } else {		/* Variable Attribute */
      hdr->isaat_af_type = htons(class);
      hdr->isaat_lv = htons(length);
      memcpy(cp+sizeof(struct isakmp_attribute), v_value, length);
   }

   *outlen = total_len;
   return cp;
}

/*
 *	add_attr -- Add a new attribute onto the list of attributes
 *
 *	Inputs:
 *
 *	finished	0 if adding a new attribute; 1 if finalising.
 *	outlen	(output) Total length of attribute list.
 *	type	Attribute Type.  'B' = basic, 'V' = variable.
 *	class	Attribute Class
 *	length	Attribute data length for variable type (ignored for basic).
 *	b_value	Basic Attribute Value
 *	v_value	Pointer to Variable Attribute Value
 *
 *	Returns:
 *
 *	Pointer to attribute list
 *
 *	This function can either be called with finished = 0, in which case
 *	type, class, length and either b_value or v_value must be specified,
 *	and the function will return NULL; or it can be called with
 *	finished = 1 in which case type, class, length,  b_value and v_value
 *	are ignored and the function will return a pointer to the finished
 *	attribute list and will set *outlen to the length of the attribute
 *	list.
 */
unsigned char *
add_attr(int finished, size_t *outlen, int type, unsigned class, size_t length,
         unsigned b_value, void *v_value) {

   static int first_attr=1;
   unsigned char *attr;
   static unsigned char *attr_start=NULL;	/* Start of attr list */
   static size_t cur_offset;			/* Start of current attr */
   static size_t end_offset;			/* End of attr list */
   size_t len;					/* Attr length */
/*
 *	Construct a new attribute if we are not finalising.
 */
   if (!finished) {
      attr = make_attr(&len, type, class, length, b_value, v_value);
      if (first_attr) {
         cur_offset = 0;
         end_offset = len;
         attr_start = Malloc(end_offset);
         memcpy(attr_start, attr, len);
         first_attr = 0;
      } else {
         cur_offset = end_offset;
         end_offset += len;
         attr_start = Realloc(attr_start, end_offset);
         memcpy(attr_start+cur_offset, attr, len);
      }
      return NULL;
   } else {
      first_attr = 1;
      *outlen = end_offset;
      return attr_start;
   }
}

/*
 *	make_vid -- Construct a vendor id payload
 *
 *	Inputs:
 *
 *	length	(output) length of Vendor ID payload.
 *	next		Next Payload Type
 *	vid_data	Vendor ID data
 *	vid_data_len	Vendor ID data length
 *
 *	Returns:
 *
 *	Pointer to vendor id payload.
 *
 *	This constructs a vendor id payload.  It fills in the static values.
 *	The next pointer value must be filled in later.
 */
unsigned char*
make_vid(size_t *length, unsigned next, unsigned char *vid_data,
         size_t vid_data_len) {
   unsigned char *payload;
   struct isakmp_vid* hdr;

   payload = Malloc(sizeof(struct isakmp_vid)+vid_data_len);
   hdr = (struct isakmp_vid*) payload;	/* Overlay vid struct on payload */
   memset(hdr, mbz_value, sizeof(struct isakmp_vid));

   hdr->isavid_np = next;		/* Next payload type */
   hdr->isavid_length = htons(sizeof(struct isakmp_vid)+vid_data_len);

   memcpy(payload+sizeof(struct isakmp_vid), vid_data, vid_data_len);
   *length = sizeof(struct isakmp_vid) + vid_data_len;

   return payload;
}

/*
 *	add_vid -- Add a vendor ID payload to the set of VIDs.
 *
 *	Inputs:
 *
 *      finished        0 if adding a new VIDs; 1 if finalising.
 *      length  (output) length of entire VID payload set.
 *      vid_data        Vendor ID data
 *      vid_data_len    Vendor ID data length
 *	ike_version	IKE version
 *	next		Next payload type (only when finished == 1)
 *
 *	Returns:
 *
 *	Pointer to the VID payload.
 *
 *	This function can either be called with finished = 0, in which case
 *	vid_data and vid_data_len must be specified, and
 *	the function will return NULL, OR it can be called with finished = 1
 *	in which case vid_data and vid_data_len are
 *	ignored and the function will return a pointer to the finished
 *	payload and will set *length to the length of this payload.
 */
unsigned char*
add_vid(int finished, size_t *length, unsigned char *vid_data,
        size_t vid_data_len, int ike_version, unsigned next) {
   static int first_vid = 1;
   static unsigned char *vid_start=NULL;	/* Start of set of VIDs */
   static size_t cur_offset;			/* Start of current VID */
   static size_t end_offset;			/* End of VIDs */
   unsigned char *vid;				/* VID payload */
   size_t len;					/* VID length */
/*
 * Construct a VID if we are not finalising.
 */
   if (!finished) {
      if (ike_version == 1) {
         vid = make_vid(&len, ISAKMP_NEXT_VID, vid_data, vid_data_len);
      } else {
         vid = make_vid(&len, ISAKMP_NEXT_V2_VID, vid_data, vid_data_len);
      }
      if (first_vid) {
         cur_offset = 0;
         end_offset = len;
         vid_start = Malloc(end_offset);
         memcpy(vid_start, vid, len);
         first_vid = 0;
      } else {
         cur_offset = end_offset;
         end_offset += len;
         vid_start = Realloc(vid_start, end_offset);
         memcpy(vid_start+cur_offset, vid, len);
      }
      return NULL;
   } else {
      struct isakmp_vid* hdr =
         (struct isakmp_vid*) (vid_start+cur_offset);   /* Overlay */

      hdr->isavid_np = next;
      *length = end_offset;
      return vid_start;
   }
}

/*
 *	make_ke	-- Make a Key Exchange payload
 *
 *	Inputs:
 *
 *      length		(output) length of key exchange payload.
 *      next		Next Payload Type
 *      kx_data_len	Key exchange data length
 *
 *	Returns:
 *
 *	Pointer to key exchange payload.
 *
 *	A real implementation would fill in the key exchange payload with the
 *	Diffie Hellman public value.  However, we just use random data.
 */
unsigned char*
make_ke(size_t *length, unsigned next, size_t kx_data_len) {
   unsigned char *payload;
   struct isakmp_kx* hdr;
   unsigned char *kx_data;
   unsigned i;

   if (kx_data_len % 4)
      err_msg("Key exchange data length %zu is not a multiple of 4",
              kx_data_len);

   payload = Malloc(sizeof(struct isakmp_kx)+kx_data_len);
   hdr = (struct isakmp_kx*) payload;	/* Overlay kx struct on payload */
   memset(hdr, mbz_value, sizeof(struct isakmp_kx));

   kx_data = payload + sizeof(struct isakmp_kx);
   for (i=0; i<kx_data_len; i++)
      *(kx_data++) = (unsigned char) random_byte();

   hdr->isakx_np = next;		/* Next payload type */
   hdr->isakx_length = htons(sizeof(struct isakmp_kx)+kx_data_len);

   *length = sizeof(struct isakmp_kx) + kx_data_len;

   return payload;
}

/*
 *	make_ke2	-- Make an IKEv2 Key Exchange payload
 *
 *	Inputs:
 *
 *      length		(output) length of key exchange payload.
 *      next		Next Payload Type
 *	dh_group	Diffie Hellman group number
 *      kx_data_len	Key exchange data length
 *
 *	Returns:
 *
 *	Pointer to key exchange payload.
 *
 *	A real implementation would fill in the key exchange payload with the
 *	Diffie Hellman public value.  However, we just use random data.
 */
unsigned char*
make_ke2(size_t *length, unsigned next, unsigned dh_group, size_t kx_data_len) {
   unsigned char *payload;
   struct isakmp_kx2* hdr;
   unsigned char *kx_data;
   unsigned i;

   if (kx_data_len % 4)
      err_msg("Key exchange data length %zu is not a multiple of 4",
              kx_data_len);

   payload = Malloc(sizeof(struct isakmp_kx2)+kx_data_len);
   hdr = (struct isakmp_kx2*) payload;	/* Overlay kx struct on payload */
   memset(hdr, mbz_value, sizeof(struct isakmp_kx2));

   kx_data = payload + sizeof(struct isakmp_kx2);
   for (i=0; i<kx_data_len; i++)
      *(kx_data++) = (unsigned char) random_byte();

   hdr->isakx2_np = next;		/* Next payload type */
   hdr->isakx2_length = htons(sizeof(struct isakmp_kx2)+kx_data_len);
   hdr->isakx2_dhgroup = htons(dh_group);

   *length = sizeof(struct isakmp_kx2) + kx_data_len;

   return payload;
}

/*
 *	make_nonce	-- Make a Nonce payload
 *
 *	Inputs:
 *
 *	length		(output) length of nonce payload.
 *      next		Next Payload Type
 *	nonce_len	Length of nonce data.
 *
 *	Returns:
 *
 *	Pointer to nonce payload.
 *
 *	RFC 2409 states that: "The length of nonce payload MUST be between 8
 *	and 256 bytes inclusive".  However, this function doesn't enforce the
 *	restriction.
 */
unsigned char*
make_nonce(size_t *length, unsigned next, size_t nonce_len) {
   unsigned char *payload;
   struct isakmp_nonce* hdr;
   unsigned char *cp;
   unsigned i;

   payload = Malloc(sizeof(struct isakmp_nonce)+nonce_len);
   hdr = (struct isakmp_nonce*) payload;  /* Overlay nonce struct on payload */
   memset(hdr, mbz_value, sizeof(struct isakmp_nonce));

   hdr->isanonce_np = next;		/* Next payload type */
   hdr->isanonce_length = htons(sizeof(struct isakmp_nonce)+nonce_len);

   cp = payload+sizeof(struct isakmp_vid);
   for (i=0; i<nonce_len; i++)
      *(cp++) = (unsigned char) random_byte();

   *length = sizeof(struct isakmp_nonce)+nonce_len;
   return payload;
}

/*
 *	make_id	-- Make an Identification payload
 *
 *	Inputs:
 *
 *      length		(output) length of ID payload.
 *      next		Next Payload Type
 *	idtype		Identification Type
 *      id_data		ID data
 *      id_data_len	ID data length
 *
 */
unsigned char*
make_id(size_t *length, unsigned next, unsigned idtype, unsigned char *id_data,
        size_t id_data_len) {
   unsigned char *payload;
   struct isakmp_id* hdr;

   payload = Malloc(sizeof(struct isakmp_id)+id_data_len);
   hdr = (struct isakmp_id*) payload;	/* Overlay ID struct on payload */
   memset(hdr, mbz_value, sizeof(struct isakmp_id));

   hdr->isaid_np = next;		/* Next payload type */
   hdr->isaid_length = htons(sizeof(struct isakmp_id)+id_data_len);
   hdr->isaid_idtype = idtype;
/*
 *	RFC 2407 4.6.2: "During Phase I negotiations, the ID port and protocol
 *	fields MUST be set to zero or to UDP port 500"
 */
   hdr->isaid_doi_specific_a = 17;		/* Protocol: UDP */
   hdr->isaid_doi_specific_b = htons(500);	/* Port: 500 */

   memcpy(payload+sizeof(struct isakmp_id), id_data, id_data_len);
   *length = sizeof(struct isakmp_id) + id_data_len;

   return payload;
}

/*
 *      make_udphdr -- Construct a UDP header for encapsulated IKE
 *
 *      Inputs:
 *
 *      length  (output) length of UDP header
 *      sport           UDP source port
 *      dport           UDP destination port
 *      udplen          UDP length
 *
 *      Returns:
 *
 *      Pointer to constructed UDP header
 *
 *      This constructs a UDP header which is used for IKE
 *      encapsulated within TCP.
 */
unsigned char*
make_udphdr(size_t *length, unsigned sport, unsigned dport, unsigned udplen) {
   unsigned char *payload;
   ike_udphdr *hdr;

   payload = Malloc(sizeof(ike_udphdr));
   hdr = (ike_udphdr*) payload; /* Overlay UDP hdr on payload */

   hdr->source = htons(sport);
   hdr->dest   = htons(dport);
   hdr->len    = htons(udplen);
   hdr->check  = 0; /* should use in_cksum() */

   *length = sizeof(ike_udphdr);

   return payload;
}

/*
 *	make_cr -- Construct a certificate request payload
 *
 *	Inputs:
 *
 *	length	(output) length of certificate request payload.
 *	next		Next Payload Type
 *	cr_data		Certificate request data
 *	cr_data_len	Certificate request data length
 *
 *	Returns:
 *
 *	Pointer to certificate request payload.
 *
 *	This constructs a certificate request payload.
 */
unsigned char*
make_cr(size_t *length, unsigned next, unsigned char *cr_data,
        size_t cr_data_len) {
   unsigned char *payload;
   struct isakmp_generic* hdr;

   payload = Malloc(sizeof(struct isakmp_generic)+cr_data_len);
   hdr = (struct isakmp_generic*) payload;
   memset(hdr, mbz_value, sizeof(struct isakmp_generic));

   hdr->isag_np = next;		/* Next payload type */
   hdr->isag_length = htons(sizeof(struct isakmp_generic)+cr_data_len);

   memcpy(payload+sizeof(struct isakmp_generic), cr_data, cr_data_len);
   *length = sizeof(struct isakmp_generic) + cr_data_len;

   return payload;
}

/*
 *	skip_payload -- Skip an ISAMKP payload
 *
 *	Inputs:
 *
 *	cp	Pointer to start of payload to skip
 *	len	Packet length remaining
 *	next	Next payload type.
 *
 *	Returns:
 *
 *	Pointer to start of next payload, or NULL if no next payload.
 */
unsigned char *
skip_payload(unsigned char *cp, size_t *len, unsigned *next) {
   struct isakmp_generic hdr;

/*
 *	Signal no more payloads by setting length to zero, next
 *	payload to none and returning NULL if the packet length is
 *	less that the ISAKMP generic header size.
 */
   if (*len < sizeof(struct isakmp_generic)) {
      *len=0;
      *next=ISAKMP_NEXT_NONE;
      return NULL;
   }
/*
 *	Fill in the generic header from the packet.  We must do this
 *	by copying rather than overlaying because we cannot be sure
 *	that "cp" is suitably aligned.
 */
   memcpy(&hdr, cp, sizeof(hdr));
/*
 *	Signal no more payloads if:
 *
 *	The payload length is greater than the packet length; or
 *	The payload length is less than the size of the generic header; or
 *	There is no next payload.
 *
 *	Also set *next to none and return null.
 */
   if (ntohs(hdr.isag_length) >= *len ||
       ntohs(hdr.isag_length) < sizeof(struct isakmp_generic) ||
       hdr.isag_np == ISAKMP_NEXT_NONE) {
      *len=0;
      *next=ISAKMP_NEXT_NONE;
      return NULL;
   }
/*
 *	There is another payload after this one, so adjust length and
 *	return pointer to next payload.
 */
   *len = *len - ntohs(hdr.isag_length);
   *next = hdr.isag_np;
   return cp + ntohs(hdr.isag_length);
}

/*
 *	process_isakmp_hdr -- Process ISAKMP header
 *
 *	Inputs:
 *
 *	cp	Pointer to start of ISAKMP header
 *	len	Packet length remaining
 *	next	Next payload type.
 *	type	Exchange type
 *	hdr_descr	ISAKMP Header description string
 *
 *	Returns:
 *
 *	Pointer to start of next payload, or NULL if no next payload.
 */
unsigned char *
process_isakmp_hdr(unsigned char *cp, size_t *len, unsigned *next,
                   unsigned *type, char **hdr_descr) {
   struct isakmp_hdr *hdr = (struct isakmp_hdr *) cp;
   char *msg;
   char *msg2;
/*
 *	Signal no more payloads by setting length to zero if:
 *
 *	The packet length is less than the ISAKMP header size; or
 *	The payload length is less than the size of the header; or
 *	There is no next payload.
 *
 *	Also set *next to none and return null.
 */
   if (*len < sizeof(struct isakmp_hdr) ||
       ntohl(hdr->isa_length) < sizeof(struct isakmp_hdr) ||
       hdr->isa_np == ISAKMP_NEXT_NONE) {
      *hdr_descr = NULL;
      *len=0;
      *next=ISAKMP_NEXT_NONE;
      *type=ISAKMP_XCHG_NONE;
      return NULL;
   }
/*
 *	Create ISAKMP header description string.
 */
   msg2 = hexstring((unsigned char *)hdr->isa_rcookie, 8);
   msg = make_message("HDR=(CKY-R=%s", msg2);
   free(msg2);
   if (hdr->isa_version != 0x10) {	/* Version not 1.0 */
      msg2 = msg;
      if (hdr->isa_version == 0x20) {
         msg = make_message("%s, IKEv2", msg2);
      } else {
         msg = make_message("%s, version=0x%.2x", msg2,
                            hdr->isa_version);
      }
      free(msg2);
   }
   if ((hdr->isa_version==0x10 && hdr->isa_flags != 0) ||
       (hdr->isa_version==0x20 && hdr->isa_flags != 0x20)) {
      msg2 = msg;
      msg = make_message("%s, flags=0x%.2x", msg2, hdr->isa_flags);
      free(msg2);
   }
   if (hdr->isa_msgid != 0) {	/* Non-Zero msgid - shouldn't happen */
      msg2 = msg;
      msg = make_message("%s, msgid=%.8x", msg2, ntohl(hdr->isa_msgid));
      free(msg2);
   }
   msg2 = msg;
   msg = make_message("%s)", msg2);
   free(msg2);
/*
 *	There is another payload after this one, so adjust length and
 *	return pointer to next payload.
 */
   *hdr_descr = msg;
   *len = *len - sizeof(struct isakmp_hdr);
   *next = hdr->isa_np;
   *type = hdr->isa_xchg;
   return cp + sizeof(struct isakmp_hdr);
}

/*
 *	process_sa -- Process SA Payload
 *
 *	Inputs:
 *
 *	cp	Pointer to start of SA payload
 *	len	Packet length remaining
 *	type	Exchange type.
 *	quiet	Only print the basic info if nonzero
 *	multiline	Split decodes across lines if nonzero
 *	hdr_descr	ISAKMP Header description string
 *
 *	Returns:
 *
 *	Pointer to SA description string.
 *
 *	The description string pointer returned points to malloc'ed storage
 *	which should be free'ed by the caller when it's no longer needed.
 */
char *
process_sa(unsigned char *cp, size_t len, unsigned type, int quiet,
           int multiline, char *hdr_descr) {
   struct isakmp_sa *sa_hdr = (struct isakmp_sa *) cp;
   struct isakmp_proposal *prop_hdr =
      (struct isakmp_proposal *) (cp + sizeof(struct isakmp_sa));
   char *msg;
   char *msg2;
   char *msg3;
   unsigned char *attr_ptr;
   size_t safelen;	/* Shorter of actual and claimed length */

   safelen = (ntohs(sa_hdr->isasa_length)<len)?ntohs(sa_hdr->isasa_length):len;
/*
 *	Return with a "too short to decode" message if either the remaining
 *	packet length or the claimed payload length is less than the combined
 *	size of the SA, Proposal, and transform headers.
 */
   if (safelen < sizeof(struct isakmp_sa) + sizeof(struct isakmp_proposal) +
       sizeof(struct isakmp_transform))
      return make_message("IKE Handshake returned (packet too short to decode)");
/*
 *	Build the first part of the message based on the exchange type.
 */
   if (type == ISAKMP_XCHG_IDPROT) {		/* Main Mode */
      msg = make_message("Main Mode Handshake returned");
   } else if (type == ISAKMP_XCHG_AGGR) {	/* Aggressive Mode */
      msg = make_message("Aggressive Mode Handshake returned");
   } else {
      msg = make_message("UNKNOWN Mode Handshake returned (%u)", type);
   }
/*
 *	If quiet is not in effect, add the ISAKMP header details to the message.
 */
   if (!quiet) {
      msg2 = msg;
      msg = make_message("%s%s%s", msg2, multiline?"\n\t":" ", hdr_descr);
      free(msg2);
   }
/*
 *	We should have exactly one transform in the server's response.
 *	If there is not exactly one transform, then add this fact to the
 *	message.  This normally means that we've received our own output.
 */
   if (prop_hdr->isap_notrans != 1) {
      msg2 = msg;
      msg = make_message("%s (%d transforms)", msg2, prop_hdr->isap_notrans);
      free(msg2);
   }
/*
 *	If quiet is not in effect, and we have exactly one transform, add the
 *	transform details to the message.
 */
   if (!quiet && prop_hdr->isap_notrans==1) {
      int firstloop=1;

      msg2 = msg;
      msg = make_message("%s%sSA=(", msg2, multiline?"\n\t":" ");
      free(msg2);
      if (prop_hdr->isap_spisize != 0) {	/* Non-Zero SPI */
         msg2 = msg;
         msg3 = hexstring(cp + sizeof(struct isakmp_sa) +
                          sizeof(struct isakmp_proposal),
                          prop_hdr->isap_spisize);
         msg = make_message("%sSPI=%s ", msg2, msg3);
         free(msg2);
         free(msg3);
      }
      attr_ptr = (cp + sizeof(struct isakmp_sa) +
                  sizeof(struct isakmp_proposal) + prop_hdr->isap_spisize +
                  sizeof(struct isakmp_transform));
      safelen -= sizeof(struct isakmp_sa) +
                 sizeof(struct isakmp_proposal) + prop_hdr->isap_spisize +
                 sizeof(struct isakmp_transform);

      while (safelen) {
         msg2 = msg;
         msg3 = process_attr(&attr_ptr, &safelen);
         if (firstloop) {	/* Don't need leading space for 1st attr */
            msg = make_message("%s%s", msg2, msg3);
            firstloop=0;
         } else {
            msg = make_message("%s %s", msg2, msg3);
         }
         free(msg2);
         free(msg3);
      }
      msg2 = msg;
      msg = make_message("%s)", msg2);
      free(msg2);
   }

   return msg;
}

/*
 *	process_sa2 -- Process an IKEv2 SA Payload
 *
 *	Inputs:
 *
 *	cp	Pointer to start of SA payload
 *	len	Packet length remaining
 *	type	Exchange type.
 *	quiet	Only print the basic info if nonzero
 *	multiline	Split decodes across lines if nonzero
 *	hdr_descr	ISAKMP Header description string
 *
 *	Returns:
 *
 *	Pointer to SA description string.
 *
 *	The description string pointer returned points to malloc'ed storage
 *	which should be free'ed by the caller when it's no longer needed.
 */
char *
process_sa2(unsigned char *cp, size_t len, unsigned type, int quiet,
            int multiline, char *hdr_descr) {
   struct isakmp_sa2 *sa_hdr = (struct isakmp_sa2 *) cp;
   struct isakmp_proposal *prop_hdr =
      (struct isakmp_proposal *) (cp + sizeof(struct isakmp_sa2));
   char *msg;
   char *msg2;
   char *msg3;
   unsigned char *trans_ptr;
   size_t safelen;	/* Shorter of actual and claimed length */

   safelen = (ntohs(sa_hdr->isasa2_length)<len)?ntohs(sa_hdr->isasa2_length):len;
/*
 *	Return with a "too short to decode" message if either the remaining
 *	packet length or the claimed payload length is less than the combined
 *	size of the SA, Proposal, and transform headers.
 */
   if (safelen < sizeof(struct isakmp_sa2) + sizeof(struct isakmp_proposal) +
       sizeof(struct isakmp_transform2))
      return make_message("IKEv2 Handshake returned (packet too short to decode)");
/*
 *	Build the first part of the message based on the exchange type.
 */
   if (type == ISAKMP_XCHG_IKE_SA_INIT) {
      msg = make_message("IKEv2 SA_INIT Handshake returned");
   } else {
      msg = make_message("UNKNOWN Mode Handshake returned (%u)", type);
   }
/*
 *	If quiet is not in effect, add the ISAKMP header details to the message.
 */
   if (!quiet) {
      msg2 = msg;
      msg = make_message("%s%s%s", msg2, multiline?"\n\t":" ", hdr_descr);
      free(msg2);
   }
/*
 *	We should have exactly one proposal in the server's response.
 *	If there is not exactly one proposal, then add this fact to the
 *	message.  This normally means that we've received our own output.
 */
   if (prop_hdr->isap_np != ISAKMP_NEXT_NONE) {
      msg2 = msg;
      msg = make_message("%s (multiple proposals)", msg2);
      free(msg2);
   }
/*
 *	If quiet is not in effect, and we have exactly one proposal, add the
 *	proposal details to the message.
 */
   if (!quiet && prop_hdr->isap_np == ISAKMP_NEXT_NONE) {
      int firstloop=1;

      msg2 = msg;
      msg = make_message("%s%sSA=(", msg2, multiline?"\n\t":" ");
      free(msg2);
      if (prop_hdr->isap_spisize != 0) {	/* Non-Zero SPI */
         msg2 = msg;
         msg3 = hexstring(cp + sizeof(struct isakmp_sa2) +
                          sizeof(struct isakmp_proposal),
                          prop_hdr->isap_spisize);
         msg = make_message("%sSPI=%s ", msg2, msg3);
         free(msg2);
         free(msg3);
      }
      trans_ptr = cp + sizeof(struct isakmp_sa2) +
                  sizeof(struct isakmp_proposal) + prop_hdr->isap_spisize;
      safelen -= sizeof(struct isakmp_sa2) +
                 sizeof(struct isakmp_proposal) + prop_hdr->isap_spisize;

      while (safelen) {
         msg2 = msg;
         msg3 = process_transform2(&trans_ptr, &safelen);
         if (firstloop) {	/* Don't need leading space for 1st attr */
            msg = make_message("%s%s", msg2, msg3);
            firstloop=0;
         } else {
            msg = make_message("%s %s", msg2, msg3);
         }
         free(msg2);
         free(msg3);
      }
      msg2 = msg;
      msg = make_message("%s)", msg2);
      free(msg2);
   }

   return msg;
}

/*
 *	process_attr -- Process transform attribute
 *
 *	Inputs:
 *
 *	cp	Pointer to start of attribute
 *	len	Packet length remaining
 *
 *	Returns:
 *
 *	Pointer to attribute description string.
 *
 *	The description string pointer returned points to malloc'ed storage
 *	which should be free'ed by the caller when it's no longer needed.
 */
char *
process_attr(unsigned char **cp, size_t *len) {
   char *msg;
   struct isakmp_attribute *attr_hdr = (struct isakmp_attribute *) *cp;
   char attr_type;	/* B=Basic, V=Variable */
   unsigned attr_class;
   unsigned attr_value=0;
   char *attr_class_str;
   char *attr_value_str;
   size_t value_len;
   size_t size;

   if (ntohs(attr_hdr->isaat_af_type) & 0x8000) {	/* Basic attribute */
      attr_type = 'B';
      attr_class = ntohs (attr_hdr->isaat_af_type) & 0x7fff;
      attr_value = ntohs (attr_hdr->isaat_lv);
      value_len = 0;	/* Value is in length field */
   } else {					/* Variable attribute */
      attr_type = 'V';
      attr_class = ntohs (attr_hdr->isaat_af_type);
      value_len = ntohs (attr_hdr->isaat_lv);
   }

   attr_class_str = make_message("%s", id_to_name(attr_class, attr_map));

   if (attr_type == 'B') {
      switch (attr_class) {
      case 1:		/* Encryption Algorithm */
         attr_value_str = make_message("%s", id_to_name(attr_value, enc_map));
         break;
      case 2:		/* Hash Algorithm */
         attr_value_str = make_message("%s", id_to_name(attr_value, hash_map));
         break;
      case 3:		/* Authentication Method */
         attr_value_str = make_message("%s", id_to_name(attr_value, auth_map));
         break;
      case 4:		/* Group Description */
         attr_value_str = make_message("%s", id_to_name(attr_value, dh_map));
         break;
      case 11:		/* Life Type */
         attr_value_str = make_message("%s", id_to_name(attr_value, life_map));
         break;
      default:
         attr_value_str = make_message("%u", attr_value);
         break;
      }
   } else {
      attr_value_str = hexstring((*cp) + sizeof (struct isakmp_attribute),
                                 value_len);
   }

   if (attr_type == 'B')
      msg = make_message("%s=%s", attr_class_str, attr_value_str);
   else
      msg = make_message("%s(%zu)=0x%s", attr_class_str, value_len,
                         attr_value_str);

   free(attr_class_str);
   free(attr_value_str);

   size=sizeof (struct isakmp_attribute) + value_len;
   if (size >= *len) {
      *len=0;
   } else {
      *len -= size;
      (*cp) += size;
   }

   return msg;
}

/*
 *	process_transform2 -- Process IKEv2 transforms
 *
 *	Inputs:
 *
 *	cp	Pointer to start of transform
 *	len	Packet length remaining
 *
 *	Returns:
 *
 *	Pointer to transform description string.
 *
 *	The description string pointer returned points to malloc'ed storage
 *	which should be free'ed by the caller when it's no longer needed.
 */
char *
process_transform2(unsigned char **cp, size_t *len) {
   char *msg;
   struct isakmp_transform2 *trans_hdr = (struct isakmp_transform2 *) *cp;
   unsigned trans_type;
   unsigned trans_id;
   char *trans_type_str;
   char *trans_id_str;
   size_t size;

   trans_type = trans_hdr->isat2_transtype;
   trans_id = ntohs(trans_hdr->isat2_transid);

   trans_type_str = make_message("%s", id_to_name(trans_type, trans_type_map));

   switch (trans_type) {
   case 1:		/* Encryption Algorithm */
      trans_id_str = make_message("%s", id_to_name(trans_id, encr_map));
      break;
   case 2:		/* Pseudo-random Function */
      trans_id_str = make_message("%s", id_to_name(trans_id, prf_map));
      break;
   case 3:		/* Integrity Algorithm */
      trans_id_str = make_message("%s", id_to_name(trans_id, integ_map));
      break;
   case 4:		/* Diffie-Hellman Group */
      trans_id_str = make_message("%s", id_to_name(trans_id, dh_map));
      break;
   default:
      trans_id_str = make_message("%u", trans_id);
      break;
   }

   size=ntohs(trans_hdr->isat2_length);
   if (size > sizeof(struct isakmp_transform2)) {	/* Attributes present */
      unsigned char *attr_ptr = (*cp) + sizeof(struct isakmp_transform2);
      struct isakmp_attribute *attr_hdr = (struct isakmp_attribute *) attr_ptr;
      unsigned attr_class=0;
      unsigned attr_value=0;

      if (ntohs(attr_hdr->isaat_af_type) & 0x8000) {	/* Basic attribute */
         attr_class = ntohs (attr_hdr->isaat_af_type) & 0x7fff;
         attr_value = ntohs (attr_hdr->isaat_lv);
      } else {					/* Variable attribute */
         warn_msg("WARNING: Ignoring IKEv2 variable length transform attribute");
      }
      msg = make_message("%s=%s,%s=%u", trans_type_str, trans_id_str,
                         id_to_name(attr_class, attr_map), attr_value);
   } else {	/* No attributes */
      msg = make_message("%s=%s", trans_type_str, trans_id_str);
   }

   free(trans_type_str);
   free(trans_id_str);

   if (size >= *len) {
      *len=0;
   } else {
      *len -= size;
      (*cp) += size;
   }

   return msg;
}

/*
 *	process_vid -- Process Vendor ID Payload
 *
 *	Inputs:
 *
 *	cp	Pointer to start of Vendor ID payload
 *	len	Packet length remaining
 *	vidlist	List of Vendor ID patterns.
 *
 *	Returns:
 *
 *	Pointer to Vendor ID description string.
 *
 *	The description string pointer returned points to malloc'ed storage
 *	which should be free'ed by the caller when it's no longer needed.
 */
char *
process_vid(unsigned char *cp, size_t len, vid_pattern_list *vidlist) {
   struct isakmp_vid *hdr = (struct isakmp_vid *) cp;
   char *msg;
   char *hexvid;
   char *p;
   unsigned char *vid_data;
   size_t data_len;
   vid_pattern_list *ve;

   if (len < sizeof(struct isakmp_vid) ||
        ntohs(hdr->isavid_length) < sizeof(struct isakmp_vid))
      return make_message("VID (packet too short to decode)");

   vid_data = cp + sizeof(struct isakmp_vid);  /* Points to start of VID data */
   data_len = ntohs(hdr->isavid_length) < len ? ntohs(hdr->isavid_length) : len;
   data_len -= sizeof(struct isakmp_vid);

   hexvid = hexstring(vid_data, data_len);
   msg=make_message("VID=%s", hexvid);
/*
 *	Try to find a match in the Vendor ID pattern list.
 */
   ve = vidlist;
   while(ve != NULL) {
      if (!(regexec(ve->regex, hexvid, 0, NULL, 0))) {
         p=msg;
         msg=make_message("%s (%s)", p, ve->name);
         free(p);
         break;	/* Stop looking after first match */
      }
      ve=ve->next;
   }
   free(hexvid);
   return msg;
}

/*
 *	process_notify -- Process notify Payload
 *
 *	Inputs:
 *
 *	cp		Pointer to start of notify payload
 *	len		Packet length remaining
 *	quiet		Only print the basic info if nonzero
 *	multiline	Split decodes across lines if nonzero
 *	hdr_descr	ISAKMP Header description string
 *
 *	Returns:
 *
 *	Pointer to notify description string.
 *
 *	This function is only used for notification messages that are part
 *	of an informational exchange.  Notification messages that are part
 *	of another exchange type are handled with process_notification()
 *	instead.  This is an ugly hack.
 *
 *	The description string pointer returned points to malloc'ed storage
 *	which should be free'ed by the caller when it's no longer needed.
 */
char *
process_notify(unsigned char *cp, size_t len, int quiet, int multiline,
               char *hdr_descr) {
   struct isakmp_notification *hdr = (struct isakmp_notification *) cp;
   char *msg;
   char *msg2;
   unsigned msg_type;
   size_t msg_len;
   unsigned char *msg_data;
   char *notify_msg;

   if (len < sizeof(struct isakmp_notification) ||
        ntohs(hdr->isan_length) < sizeof(struct isakmp_notification))
      return make_message("Notify message (packet too short to decode)");

   msg_type = ntohs(hdr->isan_type);
   msg_len = ntohs(hdr->isan_length) - sizeof(struct isakmp_notification);
   msg_data = cp + sizeof(struct isakmp_notification);

   if (msg_type == 9101 || msg_type == 9110) {	/* Firewall-1 message types */
      notify_msg = printable(msg_data, msg_len);
      msg=make_message("Notify message %u (Firewall-1) Message=\"%s\"",
                       msg_type, notify_msg);
      free(notify_msg);
   } else {			/* All other Message Types */
      msg=make_message("Notify message %u (%s)", msg_type,
                       id_to_name(msg_type, notification_map));
   }
/*
 *	If quiet is not in effect, add the ISAKMP header details to the message.
 */
   if (!quiet) {
      msg2 = msg;
      msg = make_message("%s%s%s", msg2, multiline?"\n\t":" ", hdr_descr);
      free(msg2);
   }

   return msg;
}

/*
 *	process_notify2 -- Process IKEv2 notify Payload
 *
 *	Inputs:
 *
 *	cp		Pointer to start of notify payload
 *	len		Packet length remaining
 *	quiet		Only print the basic info if nonzero
 *	multiline	Split decodes across lines if nonzero
 *	hdr_descr	ISAKMP Header description string
 *
 *	Returns:
 *
 *	Pointer to notify description string.
 *
 *	This function is only used for notification messages that are part
 *	of an informational exchange.  Notification messages that are part
 *	of another exchange type are handled with process_notification()
 *	instead.  This is an ugly hack.
 *
 *	The description string pointer returned points to malloc'ed storage
 *	which should be free'ed by the caller when it's no longer needed.
 */
char *
process_notify2(unsigned char *cp, size_t len, int quiet, int multiline,
                char *hdr_descr) {
   struct isakmp_notification2 *hdr = (struct isakmp_notification2 *) cp;
   char *msg;
   char *msg2;
   unsigned msg_type;
   size_t msg_len;
   unsigned char *msg_data;
   char *notify_msg;

   if (len < sizeof(struct isakmp_notification2) ||
        ntohs(hdr->isan2_length) < sizeof(struct isakmp_notification2))
      return make_message("Notify message (packet too short to decode)");

   msg_type = ntohs(hdr->isan2_type);
   msg_len = ntohs(hdr->isan2_length) - sizeof(struct isakmp_notification2);
   msg_data = cp + sizeof(struct isakmp_notification2);

   if (msg_type == 9101 || msg_type == 9110) {	/* Firewall-1 message types */
      notify_msg = printable(msg_data, msg_len);
      msg=make_message("Notify message %u (Firewall-1) Message=\"%s\"",
                       msg_type, notify_msg);
      free(notify_msg);
   } else {			/* All other Message Types */
      msg=make_message("Notify message %u (%s)", msg_type,
                       id_to_name(msg_type, notification_map2));
   }
/*
 *	If quiet is not in effect, add the ISAKMP header details to the message.
 */
   if (!quiet) {
      msg2 = msg;
      msg = make_message("%s%s%s", msg2, multiline?"\n\t":" ", hdr_descr);
      free(msg2);
   }

   return msg;
}

/*
 *	process_notification -- Process notification Payload
 *
 *	Inputs:
 *
 *	cp	Pointer to start of notify payload
 *	len	Packet length remaining
 *
 *	Returns:
 *
 *	Pointer to notify description string.
 *
 *	The description string pointer returned points to malloc'ed storage
 *	which should be free'ed by the caller when it's no longer needed.
 */
char *
process_notification(unsigned char *cp, size_t len) {
   struct isakmp_notification *hdr = (struct isakmp_notification *) cp;
   char *msg;
   char *msg2;
   unsigned msg_type;
   size_t msg_len;
   unsigned char *msg_data;
   char *hex_spi;
   unsigned char *notification_spi;
   char *hex_data;
   size_t spi_len;
   uint32_t doi;
   unsigned proto_id;

   if (len < sizeof(struct isakmp_notification) ||
        ntohs(hdr->isan_length) < sizeof(struct isakmp_notification))
      return make_message("Notification (packet too short to decode)");

   doi = ntohl(hdr->isan_doi);
   proto_id = hdr->isan_protoid;
   msg_type = ntohs(hdr->isan_type);
   notification_spi = cp + sizeof(struct isakmp_notification);
   spi_len = hdr->isan_spisize;
   hex_spi = hexstring(notification_spi, spi_len);
   msg_len = ntohs(hdr->isan_length) - sizeof(struct isakmp_notification) -
             spi_len;
   msg_data = cp + sizeof(struct isakmp_notification) + spi_len;
   hex_data = hexstring(msg_data, msg_len);

   msg=make_message("Notification=(");
   if (doi != 1) {	/* DOI not IPsec */
      msg2 = msg;
      msg = make_message("%sDOI=%s, ", msg2, id_to_name(doi, doi_map));
      free(msg2);
   }
   if (proto_id != 1) {	/* Protocol ID not ISAKMP */
      msg2 = msg;
      msg = make_message("%sProto_ID=%s, ", msg2,
                         id_to_name(proto_id, protocol_map));
      free(msg2);
   }
   msg2 = msg;
   msg=make_message("%sType=%s, SPI=%s, Data=%s)", msg2,
                    id_to_name(msg_type, notification_map),
                    hex_spi, hex_data);
   free(msg2);
   free(hex_spi);
   free(hex_data);

   return msg;
}

/*
 *	process_id -- Process identification Payload
 *
 *	Inputs:
 *
 *	cp	Pointer to start of identification payload
 *	len	Packet length remaining
 *
 *	Returns:
 *
 *	Pointer to identification description string.
 *
 *	The description string pointer returned points to malloc'ed storage
 *	which should be free'ed by the caller when it's no longer needed.
 */
char *
process_id(unsigned char *cp, size_t len) {
   struct isakmp_id *hdr = (struct isakmp_id *) cp;
   unsigned idtype;
   char *msg;
   char *msg2;
   unsigned char *id_data;
   size_t data_len;

   if (len < sizeof(struct isakmp_id) ||
        ntohs(hdr->isaid_length) < sizeof(struct isakmp_id))
      return make_message("ID (packet too short to decode)");

   id_data = cp + sizeof(struct isakmp_id);  /* Points to start of ID data */
   data_len = ntohs(hdr->isaid_length) < len ? ntohs(hdr->isaid_length) : len;
   data_len -= sizeof(struct isakmp_id);
   idtype = hdr->isaid_idtype;

   switch(idtype) {
      char *id;			/* Printable ID */
      struct in_addr in;	/* IPv4 Address */
      struct in_addr in2;	/* IPv4 Address */
      unsigned char *mask;	/* Netmask */

      case ID_IPV4_ADDR:
         if (data_len >= sizeof(struct in_addr)) {
            memcpy(&in, id_data, sizeof(struct in_addr));
            msg=make_message("Value=%s", inet_ntoa(in));
         } else {
            msg=make_message("Value too short to decode");
         }
         break;
      case ID_IPV4_ADDR_SUBNET:
         if (data_len >= sizeof(struct in_addr) + 4) {
            memcpy(&in, id_data, sizeof(struct in_addr));
            mask = id_data + sizeof(struct in_addr);
            msg=make_message("Value=%s/%u.%u.%u.%u", inet_ntoa(in),
                             mask[0], mask[1], mask[2], mask[3]);
         } else {
            msg=make_message("Value too short to decode");
         }
         break;
      case ID_IPV4_ADDR_RANGE:
         if (data_len >=  2 * sizeof(struct in_addr)) {
            memcpy(&in, id_data, sizeof(struct in_addr));
            memcpy(&in2, id_data+sizeof(struct in_addr),
                   sizeof(struct in_addr));
            msg=make_message("Value=%s-%s", inet_ntoa(in), inet_ntoa(in2));
         } else {
            msg=make_message("Value too short to decode");
         }
         break;
      case ID_FQDN:
      case ID_USER_FQDN:
         id = printable(id_data, data_len);
         msg=make_message("Value=%s", id);
         free(id);
         break;
      case ID_KEY_ID:
         id = hexstring(id_data, data_len);
         msg = make_message("Value=%s", id);
         free(id);
         break;
      case ID_IPV6_ADDR:
      case ID_IPV6_ADDR_SUBNET:
      case ID_IPV6_ADDR_RANGE:
      case ID_DER_ASN1_DN:
      case ID_DER_ASN1_GN:
         msg=make_message("Decode not supported for this type");
         break;
      default:
         msg = make_message("Unknown ID Type");
         break;
   }

   msg2=msg;
   msg=make_message("ID(Type=%s, %s)", id_to_name(idtype,id_map), msg2);
   free(msg2);

   return msg;
}

/*
 *	process_cert -- Process Certificate Payload
 *
 *	Inputs:
 *
 *	cp	Pointer to start of certificate payload
 *	len	Packet length remaining
 *	next	The previous next payload type
 *
 *	Returns:
 *
 *	Pointer to certificate description string.
 *
 *	The description string pointer returned points to malloc'ed storage
 *	which should be free'ed by the caller when it's no longer needed.
 */
char *
process_cert(unsigned char *cp, size_t len, unsigned next) {
   struct isakmp_generic *hdr = (struct isakmp_generic *) cp;
   char *msg;
   unsigned char cert_type;
   unsigned char *cert_data;
   size_t data_len;

   if (len < sizeof(struct isakmp_generic) + 1 ||
        ntohs(hdr->isag_length) < sizeof(struct isakmp_generic) + 1)
      return make_message("Certificate (packet too short to decode)");

   cert_data = cp + sizeof(struct isakmp_generic);
   cert_type = *cert_data++;
   data_len = ntohs(hdr->isag_length) < len ? ntohs(hdr->isag_length) : len;
   data_len -= sizeof(struct isakmp_generic) + 1;

   msg=make_message("%s(Type=%s, Length=%zu bytes)",
                    id_to_name(next, payload_map),
                    id_to_name(cert_type, cert_map), data_len);

   return msg;
}

/*
 *	process_delete -- Process Delete Payload
 *
 *	Inputs:
 *
 *	cp	Pointer to start of Delete payload
 *	len	Packet length remaining
 *
 *	Returns:
 *
 *	Pointer to Delete description string.
 *
 *	The description string pointer returned points to malloc'ed storage
 *	which should be free'ed by the caller when it's no longer needed.
 */
char *
process_delete(unsigned char *cp, size_t len) {
   struct isakmp_delete *hdr = (struct isakmp_delete *) cp;
   char *msg;
   char *hex_spi;
   unsigned char *delete_spi;
   size_t spi_len;

   if (len < sizeof(struct isakmp_delete) ||
        ntohs(hdr->isad_length) < sizeof(struct isakmp_delete))
      return make_message("Delete (packet too short to decode)");

   delete_spi = cp + sizeof(struct isakmp_delete);
   spi_len = ntohs(hdr->isad_length) < len ? ntohs(hdr->isad_length) : len;
   spi_len -= sizeof(struct isakmp_delete);

   hex_spi = hexstring(delete_spi, spi_len);
   msg=make_message("Delete=(SPI_Size=%u, SPI_Count=%u, SPI_Data=%s)",
                    hdr->isad_spisize, ntohs(hdr->isad_nospi), hex_spi);
   free(hex_spi);

   return msg;
}

/*
 *	process_generic -- Process Generic ISAKMP Payload
 *
 *	Inputs:
 *
 *	cp	Pointer to start of Delete payload
 *	len	Packet length remaining
 *
 *	Returns:
 *
 *	Pointer to payload description string.
 *
 *	The description string pointer returned points to malloc'ed storage
 *	which should be free'ed by the caller when it's no longer needed.
 */
char *
process_generic(unsigned char *cp, size_t len, unsigned next) {
   struct isakmp_generic *hdr = (struct isakmp_generic *) cp;
   char *msg;

   if (len < sizeof(struct isakmp_generic) ||
        ntohs(hdr->isag_length) < sizeof(struct isakmp_generic)) {
      msg = make_message("%s (packet too short to decode)",
                          id_to_name(next, payload_map));
      return msg;
   }

   msg=make_message("%s(%u bytes)", id_to_name(next, payload_map),
                    ntohs(hdr->isag_length) -
                    sizeof(struct isakmp_generic));

   return msg;
}

/*
 *	add_isakmp_payload -- Add an ISAKMP payload to the current packet
 *
 *	Inputs:
 *
 *	payload		Pointer to the payload to add
 *	payload_len	Length of the payload
 *	new_payload	Pointer to the new payload within the packet
 *
 *	Returns:
 *
 *	A pointer to the ISAKMP packet.
 *
 *	This function assumes that "payload" is a pointer to malloc'ed
 *	storage, and will free it after use.
 */
unsigned char *
add_isakmp_payload(unsigned char *payload, size_t payload_len,
                   unsigned char **new_payload) {

   static unsigned char *isakmp_packet = NULL;
   static size_t offset = 0;
   unsigned char *payload_ptr;
/*
 *	Allocate memory for the packet on the first call.
 */
   if (isakmp_packet == NULL) {
      isakmp_packet = Malloc(MAXUDP);
   }
/*
 *	Calculate position within the packet to add the new payload.
 *	Copy the new payload starting at this position, then free the
 *	payload memory.
 */
   payload_ptr = isakmp_packet+offset;
   memcpy(payload_ptr, payload, payload_len);
   free(payload);
/*
 *	Set the new_payload argument to the position of the newly added
 *	payload within the packet, and return the address of the start
 *	of the packet.
 */
   *new_payload = payload_ptr;
   return isakmp_packet;
}

/*
 *	print_payload -- Print an ISAKMP payload in hex
 *
 *	Inputs:
 *
 *	cp	Pointer to start of ISAKMP payload
 *	payload	Numeric value of this payload type, 0 = ISAKMP header
 *	dir	Direction: 'I' for initiator or 'R' for responder
 *
 *	Returns:
 *
 *	None
 *
 *	This function is used for debugging.  It trusts the length in the
 *	generic ISAKMP header, and so could misbehave with corrupted packets.
 */
void
print_payload(unsigned char *cp, unsigned payload, int dir) {
   struct isakmp_generic *hdr = (struct isakmp_generic *) cp;
   struct isakmp_hdr *ihdr = (struct isakmp_hdr *) cp;
   char *hexdata;
   unsigned char *data;
   size_t data_len;

   if (payload) {	/* Some other payload */
      data = cp + sizeof(struct isakmp_generic);  /* Points to start of data */
      data_len = ntohs(hdr->isag_length);
      data_len -= sizeof(struct isakmp_generic);
      hexdata = hexstring(data, data_len);
      switch (payload) {
         case ISAKMP_NEXT_SA:
            printf("sa%c_b_hex=\"%s\"\n", (dir=='I')?'i':'r', hexdata);
            break;
         case ISAKMP_NEXT_KE:
            printf("g_x%c_hex=\"%s\"\n", (dir=='I')?'i':'r', hexdata);
            break;
         case ISAKMP_NEXT_ID:
            printf("idi%c_b_hex=\"%s\"\n", (dir=='I')?'i':'r', hexdata);
            break;
         case ISAKMP_NEXT_HASH:
            printf("expected_hash_%c_hex=\"%s\"\n", (dir=='I')?'i':'r', hexdata);
            break;
         case ISAKMP_NEXT_NONCE:
            printf("n%c_b_hex=\"%s\"\n", (dir=='I')?'i':'r', hexdata);
            break;
         default:
            printf("UNKNOWN PAYLOAD TYPE: %d\n", payload);
            break;
      }
      free(hexdata);
   } else {	/* ISAKMP Header */
      hexdata = hexstring((unsigned char *)ihdr->isa_icookie, 8);
      printf("cky_i_hex=\"%s\"\n", hexdata);
      free(hexdata);
      hexdata = hexstring((unsigned char *)ihdr->isa_rcookie, 8);
      printf("cky_r_hex=\"%s\"\n", hexdata);
      free(hexdata);
   }
}

/*
 *	add_psk_crack_payload -- Add an ISAKMP payload to PSK crack structure
 *
 *	Inputs:
 *
 *	cp	Pointer to start of ISAKMP payload
 *	payload	Numeric value of this payload type, 0 = ISAKMP header
 *	dir	Direction: 'I' for initiator or 'R' for responder
 *
 *	Returns:
 *
 *	None
 *
 *	This function trusts the length in the generic ISAKMP header, so
 *	could misbehave with corrupted packets.
 */
void
add_psk_crack_payload(unsigned char *cp, unsigned payload, int dir) {
   struct isakmp_generic *hdr = (struct isakmp_generic *) cp;
   struct isakmp_hdr *ihdr = (struct isakmp_hdr *) cp;
   unsigned char *data;
   size_t data_len;

   if (payload) {	/* Normal ISAKMP payload */
      data_len = ntohs(hdr->isag_length) - sizeof(struct isakmp_generic);
      data = Malloc(data_len);
      memcpy(data, cp + sizeof(struct isakmp_generic), data_len);

      switch (payload) {
         case ISAKMP_NEXT_SA:
            if (dir == 'I') {
               psk_values.sai_b = data;
               psk_values.sai_b_len = data_len;
            }
            break;
         case ISAKMP_NEXT_KE:
            if (dir == 'I') {
               psk_values.g_xi = data;
               psk_values.g_xi_len = data_len;
            } else {
               psk_values.g_xr = data;
               psk_values.g_xr_len = data_len;
            }
            break;
         case ISAKMP_NEXT_ID:
            if (dir == 'R') {
               psk_values.idir_b = data;
               psk_values.idir_b_len = data_len;
            }
            break;
         case ISAKMP_NEXT_HASH:
            if (dir == 'R') {
               psk_values.hash_r = data;
               psk_values.hash_r_len = data_len;
            }
            break;
         case ISAKMP_NEXT_NONCE:
            if (dir == 'I') {
               psk_values.ni_b = data;
               psk_values.ni_b_len = data_len;
            } else {
               psk_values.nr_b = data;
               psk_values.nr_b_len = data_len;
            }
            break;
         default:
            warn_msg("add_psk_crack_payload: UNKNOWN PAYLOAD TYPE: %d\n",
                     payload);
            break;
      }
   } else {	/* ISAKMP Header */
      data_len=8;	/* ISAKMP cookies are 8 bytes long */
      data=Malloc(data_len);
      memcpy(data, (unsigned char *)ihdr->isa_rcookie, 8);
      psk_values.cky_r = data;
      psk_values.cky_r_len = data_len;

      data=Malloc(data_len);
      memcpy(data, (unsigned char *)ihdr->isa_icookie, 8);
      psk_values.cky_i = data;
      psk_values.cky_i_len = data_len;
   }
}

/*
 *	print_psk_crack_values -- Display the PSK crack values
 *
 *	Inputs:
 *
 *	psk_crack_file	Name of PSK data output file, or NULL for stdout
 *
 *	Returns:
 *
 *	None
 *
 *	This function prints the PSK crack values in the following format:
 *
 *	g_xr:g_xi:cky_r:cky_i:sai_b:idir_b:ni_b:nr_b:hash_r
 */
void
print_psk_crack_values(const char *psk_crack_file) {
   char *hexdata;
   FILE *fp;

   if (psk_crack_file[0]) {
      if ((fp = fopen(psk_crack_file, "w")) == NULL) {
         err_sys("ERROR: fopen");
      }
   } else {
      fp = stdout;
      printf("IKE PSK parameters (g_xr:g_xi:cky_r:cky_i:sai_b:idir_b:ni_b:nr_b:hash_r):\n");
   }

   hexdata=hexstring(psk_values.g_xr, psk_values.g_xr_len);
   fprintf(fp, "%s:", hexdata);
   free(hexdata);
   hexdata=hexstring(psk_values.g_xi, psk_values.g_xi_len);
   fprintf(fp, "%s:", hexdata);
   free(hexdata);
   hexdata=hexstring(psk_values.cky_r, psk_values.cky_r_len);
   fprintf(fp, "%s:", hexdata);
   free(hexdata);
   hexdata=hexstring(psk_values.cky_i, psk_values.cky_i_len);
   fprintf(fp, "%s:", hexdata);
   free(hexdata);
   hexdata=hexstring(psk_values.sai_b, psk_values.sai_b_len);
   fprintf(fp, "%s:", hexdata);
   free(hexdata);
   hexdata=hexstring(psk_values.idir_b, psk_values.idir_b_len);
   fprintf(fp, "%s:", hexdata);
   free(hexdata);
   hexdata=hexstring(psk_values.ni_b, psk_values.ni_b_len);
   fprintf(fp, "%s:", hexdata);
   free(hexdata);
   hexdata=hexstring(psk_values.nr_b, psk_values.nr_b_len);
   fprintf(fp, "%s:", hexdata);
   free(hexdata);
   hexdata=hexstring(psk_values.hash_r, psk_values.hash_r_len);
   fprintf(fp, "%s\n", hexdata);
   free(hexdata);

   if (psk_crack_file[0]) {
      fclose(fp);
   }
}

/*
 *	clone_payload -- Clone the ISAKMP payload
 *
 *	Inputs:
 *
 *	pkt_ptr		Pointer to the payload to clone
 *	bytes_left	Number of bytes remaining in the packet
 *
 *	Returns:
 *
 *	Pointer to the cloned payload or NULL if no payload.
 *
 *	This function clones the ISAKMP payload starting at pkt_ptr, with
 *	a maximum size of bytes_left.  It copies the payload to a newly
 *	allocated memory block to ensure that it is suitably aligned for
 *	those CPUs that have alignment restrictions.
 *
 *	The return value points to Malloc'ed memory, which should be
 *	free'ed when it is no longer required.
 */
unsigned char *
clone_payload(const unsigned char *pkt_ptr, size_t bytes_left) {
   struct isakmp_generic hdr;
   unsigned char *clone_ptr;
   size_t payload_len;
/*
 *	Ensure that there is sufficient data to fill the generic
 *	header.
 */
   if (bytes_left < sizeof(struct isakmp_generic)) {
      return NULL;
   }
/*
 *	Fill in the generic header from the packet.  We must do this
 *	by copying rather than overlaying because we cannot be sure
 *	that "pkt_ptr" is suitably aligned.
 */
   memcpy(&hdr, pkt_ptr, sizeof(hdr));
/*
 *	Determine the length of the payload.
 */
   payload_len = ntohs(hdr.isag_length);
   if (payload_len > bytes_left)
      payload_len = bytes_left;
/*
 *	Allocate memory and copy payload.
 */
   clone_ptr = Malloc(payload_len);
   memcpy(clone_ptr, pkt_ptr, payload_len);

   return clone_ptr;
}
