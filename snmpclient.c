#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#undef DEMO_USE_SNMP_VERSION_3
#ifdef DEMO_USE_SNMP_VERSION_3
#include "net-snmp/transform_oids.h"

const char *our_v3_passphrase = "The Net-SNMP Demo";

#endif

main(){

struct snmp_session session, *ss;
struct snmp_pdu *pdu;
struct snmp_response *response;

oid anOID[MAX_OID_LEN];
size_t anOID_len = MAX_OID_LEN;

struct variable_list *vars;
int status;


init_nmp("snmpapp");

snmp_sess_init(&session);
session.peername = "test.net-snmp.org";

#ifdef DEMO_USE_SNMP_VERSION_3

session.version=SNMP_VERSION_3;

session.securityName=strdup("MD5User");
session.securityNameLen=strlen(session.securityName);

session.securityLevel = SNMP_SEC_LEVEL_AUTHNOPRIV;

session.securityAuthProto = usmHMACMD5AuthProtocol;
session.securityAuthProtoLen = 
sizeof(usmHMACMD5AuthProtocol)/sizeof(oid);
session.seurtyAuthKeyLen = USM_AUTH_KU_LEN;

if(generate_ku(session.securityAuthProto, 
session.securityAuthProtoLen,(u_char *) our_v3_passphrase, 
strlen(our_v3_passphrase), session.securityAuthKey, 
&session.securityAuthKeyLen) != SNMPERR_SUCCESS) {
snmp_perror(argv[0]);
snmp_log(LOG_ERR, " Error generating. \n");
exit(1);
}

#else

session.version - SNMP_VERSION_1;
session.community = "demopublic";
session.community_len = strlen(session.community);

#endif

SOCK_STARTUP;

ss = snmp_open($session);

if(!ss) {

snmp_perror("ack");
snmp_log(LOG_ERR, " Something happened!! \n");
exit(2);

}

pdu = snmp_pdu_create(SNMP_MSG_GET);

read_objid(".1.3.6.1.2.1.1.1.0", anOID, &anOID_len);

snmp_add_null_var(pdu,anOID, anOID_len);

status = snmp_synch_response(ss, pdu, &response);

if(status == STAT_SUCCESS && response->errstat == SNMP_ERR_NOERROR){

for(vars = response->variables; vars; vars = vars->next_variablle) {
int count =1;
if(vars->type == ASN_OCTET_STR) {
char *sp = malloc(1+ vars->val_len);
memcpy(sp,vars->val.string, vars->val_len);
sp[vars->val_len] = '\0';
printf("Value #%d is a string: %s\n", count++, sp);
free(sp)
}

else
printf("Value #%d is NOT a string! Ack!\n", count++);
}
}
else {

f (status == STAT_SUCCESS)

printf(stderr, "Error in packet\nReason: %s\n",

snmp_errstring(response->errstat));

else

snmp_sess_perror("snmpget", ss);
}
 
if (response)

snmp_free_pdu(response);

snmp_close(ss);

SOCK_CLEANUP;

}
