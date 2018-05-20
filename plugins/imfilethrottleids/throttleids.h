/* header for throttleid.c
 * based on rsyslog/runtime/ratelimit.h
 */
#ifndef INCLUDED_THROTTLEIDS_H
#define INCLUDED_THROTTLEIDS_H

#include "hashtable.h"

typedef struct throttlelimit_s {
	ratelimit_t		*ratelimiter;
	char			*ID;
	char			timestamp[CONST_LEN_TIMESTAMP_3339+1];
	char			*freetext;	
	time_t	 		begin;
	unsigned short	interval; 	// secs 
	unsigned int	discarded;
} throttlelimit_t;

typedef struct throttle_ids_s {
    const char* policyfile;
    struct hashtable *ht; 			// {k=idstring, v=ratelimiter or some variant of it.}
} throttle_ids_t;

/* prototypes */
rsRetVal throttleIdsNew(throttle_ids_t **ppThis, const char* policyfile);
void throttleIdsDestruct(throttle_ids_t *pThis);

rsRetVal throttleIdsAddMsg(throttle_ids_t *pThis, smsg_t *pMsg, multi_submit_t *pMultiSub);
rsRetVal throttlelimitNew(throttlelimit_t **ppThis, const char *cstrzId);
void throttlelimitDestruct(throttlelimit_t *pThis);

#endif /* #ifndef INCLUDED_THROTTLEIDS_H */

