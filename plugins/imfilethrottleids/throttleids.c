/* throttleid.c
 * support for throttling by id in message which is the first string in a comma
 * separated message, e.g. "id1, timestamp, free text"
 * handles repeated n times" processing and is based on the ratelimit processing found in
 * rsyslog runtime library.
 * 
 */

#include "config.h"
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "rsyslog.h"
#include "errmsg.h"
#include "ratelimit.h"
#include "datetime.h"
#include "parser.h"
#include "unicode-helper.h"
#include "msg.h"
#include "rsconf.h"
#include "dirty.h"

#include "throttleids.h"

/* definitions for objects we access */
// disable these for now.
#if 0
//DEFobjStaticHelpers
//DEFobjCurrIf(errmsg)
//DEFobjCurrIf(glbl)
//DEFobjCurrIf(datetime)
//DEFobjCurrIf(parser)
#endif

// static functions
static rsRetVal
readPolicyFile(struct hashtable *pHt, const char* policy)
{
	DEFiRet;
	 //if (!pThis) { ABORT_FINALIZE(RS_RET_ERR); }

	 if (!pHt) { ABORT_FINALIZE(RS_RET_ERR); }
	/* read in the policy file 
	 * hard code it in /etc/rsyslog/.
	 */
    FILE *fpolicy = NULL; /* policy file */
	if ((fpolicy = fopen(policy, "rb")) != NULL) {

		char linebuf[128];
		while (fgets(linebuf, sizeof(linebuf), fpolicy)) {
			//dbgprintf("line: %s", linebuf);
			char idtag[128];
			int throttle_rate = 0;

			// TODO: better to parse using strtok
			sscanf(linebuf, "%[^,],%d", idtag, &throttle_rate);
			dbgprintf("[idtag: %s, throttle_rate: %d]\n", idtag, throttle_rate);

			// TODO: save it someplace, leave it for now.
			// let's save it in the hashtable
			//CHKmalloc(new_tag = malloc(sizeof(tag_elm_t)));
			throttlelimit_t *pThrottlelimiter;
			CHKiRet(throttlelimitNew(&pThrottlelimiter, idtag));
            ratelimit_t *ratelimiter = pThrottlelimiter->ratelimiter;
	        ratelimitSetLinuxLike(ratelimiter, 1, throttle_rate);
			ratelimiter->bReduceRepeatMsgs = 1; //for testing

 			unsigned int hash = hash_from_string((char*)idtag);
			unsigned int *pKey;

			if (NULL == (pKey = (unsigned int *)malloc(sizeof(unsigned int))))
			{
				DBGPRINTF("memory allocation for key failed\n");
				ABORT_FINALIZE(RS_RET_ERR);
			}
			*pKey = hash;

			if (!hashtable_insert(pHt, pKey, pThrottlelimiter))
			{
				DBGPRINTF("inserting throttlelimiter into hashtable failed\n");
				free(pKey);
				throttlelimitDestruct(pThrottlelimiter);
				ABORT_FINALIZE(RS_RET_ERR);
			}
		}
		fclose(fpolicy);
	}
finalize_it:
	RETiRet;
}

rsRetVal
throttleIdsNew(throttle_ids_t **ppThis, const char* policyfile) 
{
	DEFiRet;
	throttle_ids_t *pThis;

	CHKmalloc(pThis = calloc(1, sizeof(throttle_ids_t)));
	pThis->policyfile 	= policyfile;

	if (NULL == (pThis->ht = create_hashtable(10, hash_from_string, key_equals_string, (void (*)(void *))throttlelimitDestruct)))
	{
		dbgprintf("could not create hashtable!\n");
		assert(0);
		ABORT_FINALIZE(RS_RET_ERR);
	}

    readPolicyFile(pThis->ht, policyfile);
	*ppThis = pThis;

finalize_it:
	RETiRet;
}

void 
throttleIdsDestruct(throttle_ids_t *pThis) 
{
	hashtable_destroy(pThis->ht, 1);
}

rsRetVal
throttlelimitNew(throttlelimit_t **ppThis, const char *cstrzId)
{
	DEFiRet;
	throttlelimit_t *pThis;

	CHKmalloc(pThis = calloc(1, sizeof(throttlelimit_t)));

	// initialize ratelimiter
	if ((RS_RET_OK != ratelimitNew(&(pThis->ratelimiter), "imfilethrottleid", cstrzId))) {
		DBGPRINTF("memory allocation for value failed\n");
		throttlelimitDestruct(pThis);
		ABORT_FINALIZE(RS_RET_ERR);
		assert(0);
	}

	pThis->begin	= 0;
	pThis->interval	= 60;
	pThis->discarded= 0;
	*ppThis 		= pThis;

finalize_it:
	RETiRet;
}

void
throttlelimitDestruct(throttlelimit_t *pThis)
{
	if (pThis->ratelimiter) {
		ratelimitDestruct(pThis->ratelimiter);
	}
	if (pThis->ID) 			{	free(pThis->ID);		}
	if (pThis->timestamp) 	{	free(pThis->timestamp);	}
	if (pThis->freetext) 	{	free(pThis->freetext);	}
}

static sbool 
parseMsg(const char *pStr, char **pIdText, char **pTimestamp, char **pFreetext)
{
	char 	dupStr[1028];
	strncpy(dupStr, pStr, sizeof(dupStr)-1);
	
	DBGPRINTF("%s() ENTER\n", __FUNCTION__);
	char *pToken = strtok(dupStr, ", ");
	if (!pToken) { return 0; }
	*pIdText = strdup(pToken);
	DBGPRINTF("%s() ID: %s\n", __FUNCTION__, *pIdText);

	// timestamp
	pToken = strtok(NULL, ", ");
	if (!pToken) { return 0; }
	*pTimestamp = strdup(pToken);
	DBGPRINTF("%s() Timestamp: %s\n", __FUNCTION__, *pTimestamp);

	// Freetext 
	pToken = strtok(NULL, ", ");
	if (!pToken) { return 0; }
	*pFreetext = strdup(pToken);
	DBGPRINTF("%s() Freetext: %s\n", __FUNCTION__, *pFreetext);
	return 1;
}

static throttlelimit_t *
getThrottlelimiter(throttle_ids_t *pThis, const char *cstrzId)
{
	unsigned int hash = hash_from_string((char*) cstrzId);
	return hashtable_search(pThis->ht, &hash);
}

/* helper: tell how many messages we lost due to linux-like ratelimiting */
static void
tellLostCnt(ratelimit_t *ratelimit)
{
	uchar msgbuf[1024];
	if(ratelimit->missed) {
		snprintf((char*)msgbuf, sizeof(msgbuf),
			 "%s: %u messages lost due to rate-limiting",
			 ratelimit->name, ratelimit->missed);
		ratelimit->missed = 0;
		logmsgInternal(RS_RET_RATE_LIMITED, LOG_SYSLOG|LOG_INFO, msgbuf, 0);
	}
}

/* Linux-like ratelimiting, modelled after the linux kernel
 * returns 1 if message is within rate limit and shall be 
 * processed, 0 otherwise.
 * This implementation is NOT THREAD-SAFE and must not 
 * be called concurrently.
 */
static int ATTR_NONNULL()
withinThrottlelimit(ratelimit_t *__restrict__ const ratelimit,
	time_t tt,
	const char*const appname)
{
	int ret;
	uchar msgbuf[1024];

	if(ratelimit->bThreadSafe) {
		pthread_mutex_lock(&ratelimit->mut);
	}

	if(ratelimit->interval == 0) {
		ret = 1;
		goto finalize_it;
	}

	/* we primarily need "NoTimeCache" mode for imjournal, as it
	 * sets the message generation time to the journal timestamp.
	 * As such, we do not get a proper indication of the actual
	 * message rate. To prevent this, we need to query local
	 * system time ourselvs.
	 */
	if(ratelimit->bNoTimeCache)
		tt = time(NULL);

	assert(ratelimit->burst != 0);

	if(ratelimit->begin == 0)
		ratelimit->begin = tt;

	/* resume if we go out of time window or if time has gone backwards */
	if((tt > ratelimit->begin + ratelimit->interval) || (tt < ratelimit->begin) ) {
		ratelimit->begin = 0;
		ratelimit->done = 0;
		tellLostCnt(ratelimit);
		// create rate limiting message.
	}

	/* do actual limit check */
	if(ratelimit->burst > ratelimit->done) {
		ratelimit->done++;
		ret = 1;
	} else {
		ratelimit->missed++;
		if(ratelimit->missed == 1) {
			snprintf((char*)msgbuf, sizeof(msgbuf),
				"%s from <%s>: begin to drop messages due to rate-limiting",
				ratelimit->name, appname);
			logmsgInternal(RS_RET_RATE_LIMITED, LOG_SYSLOG|LOG_INFO, msgbuf, 0);
		}
		ret = 0;
	}

finalize_it:
	if(ratelimit->bThreadSafe) {
		pthread_mutex_unlock(&ratelimit->mut);
	}
	return ret;
}

/* generate a "repeated n times" message */
static smsg_t *
throttlelimitGenDiscardedMsg(throttlelimit_t *throttlelimit)
{
	smsg_t *repMsg;
	size_t lenRepMsg;
	uchar szRepMsg[1024];

	ratelimit_t *ratelimit = throttlelimit->ratelimiter;

	if(ratelimit->nsupp == 1) { /* we simply use the original message! */
		repMsg = MsgAddRef(ratelimit->pMsg);
	} else {/* we need to duplicate, original message may still be in use in other
		 	 * parts of the system!  */
		if((repMsg = MsgDup(ratelimit->pMsg)) == NULL) {
			DBGPRINTF("Message duplication failed, dropping repeat message.\n");
			goto done;
		}
		lenRepMsg = snprintf((char*)szRepMsg, sizeof(szRepMsg),
					" %s, %s, throttled %d messages",
					throttlelimit->timestamp, throttlelimit->ID, throttlelimit->discarded);

		// set the ruleset to the same as the originating message
		MsgSetRuleset(repMsg, ratelimit->pMsg->pRuleset);

		MsgReplaceMSG(repMsg, szRepMsg, lenRepMsg);
	}

done:	return repMsg;
}

static rsRetVal
doLastMessageDiscardedNTimes(throttlelimit_t *throttlelimit, smsg_t *pMsg, smsg_t **ppRepMsg)
{
	int bNeedUnlockMutex = 0;
	DEFiRet;

	ratelimit_t *ratelimit = throttlelimit->ratelimiter;
	time_t tt = time(NULL);
	if (throttlelimit->begin == 0)
	{
		throttlelimit->begin = tt;
	}

	if(ratelimit->bThreadSafe) {
		pthread_mutex_lock(&ratelimit->mut);
		bNeedUnlockMutex = 1;
	}

	if( ratelimit->pMsg != NULL &&
	    getMSGLen(pMsg) == getMSGLen(ratelimit->pMsg) &&
	    !ustrcmp(getMSG(pMsg), getMSG(ratelimit->pMsg)) &&
	    !strcmp(getHOSTNAME(pMsg), getHOSTNAME(ratelimit->pMsg)) &&
	    !strcmp(getPROCID(pMsg, LOCK_MUTEX), getPROCID(ratelimit->pMsg, LOCK_MUTEX)) &&
	    !strcmp(getAPPNAME(pMsg, LOCK_MUTEX), getAPPNAME(ratelimit->pMsg, LOCK_MUTEX))) {
		ratelimit->nsupp++;
		DBGPRINTF("msg repeated %d times\n", ratelimit->nsupp);
		/* use current message, so we have the new timestamp
		 * (means we need to discard previous one) */
		msgDestruct(&ratelimit->pMsg);
		ratelimit->pMsg = pMsg;
		ABORT_FINALIZE(RS_RET_DISCARDMSG);
	} else {/* new message, do "repeat processing" & save it */
		if(ratelimit->pMsg != NULL) {
			if ((tt > throttlelimit->begin + throttlelimit->interval) || (tt < throttlelimit->begin)) {
				if (ratelimit->nsupp > 0)
				{
					*ppRepMsg = throttlelimitGenDiscardedMsg(throttlelimit);
					ratelimit->nsupp = 0;
					throttlelimit->begin = 0;
					throttlelimit->discarded = 0;
				}
				msgDestruct(&ratelimit->pMsg);
			}
		}
		ratelimit->pMsg = MsgAddRef(pMsg);
	}

finalize_it:
	if(bNeedUnlockMutex)
		pthread_mutex_unlock(&ratelimit->mut);
	RETiRet;
}

/* ratelimit a message, that means:
 * - handle "last message repeated n times" logic
 * - handle actual (discarding) rate-limiting
 * This function returns RS_RET_OK, if the caller shall process
 * the message regularly and RS_RET_DISCARD if the caller must
 * discard the message. The caller should also discard the message
 * if another return status occurs. This places some burden on the
 * caller logic, but provides best performance. Demanding this
 * cooperative mode can enable a faulty caller to thrash up part
 * of the system, but we accept that risk (a faulty caller can
 * always do all sorts of evil, so...)
 * If *ppRepMsg != NULL on return, the caller must enqueue that
 * message before the original message.
 */
static rsRetVal
throttlelimitMsg(throttlelimit_t *__restrict__ const throttlelimit, smsg_t *pMsg, smsg_t **ppRepMsg)
{
	DEFiRet;
	ratelimit_t *ratelimit = throttlelimit->ratelimiter;

	*ppRepMsg = NULL;
#if 0
	rsRetVal localRet;
	if((pMsg->msgFlags & NEEDS_PARSING) != 0) {
		if((localRet = parser.ParseMsg(pMsg)) != RS_RET_OK)  {
			DBGPRINTF("Message discarded, parsing error %d\n", localRet);
			ABORT_FINALIZE(RS_RET_DISCARDMSG);
		}
	}
#endif
	/* Only the messages having severity level at or below the
	 * threshold (the value is >=) are subject to ratelimiting. */
	// ignore severity 
	if(ratelimit->interval) {
		char namebuf[512]; /* 256 for FGDN adn 256 for APPNAME should be enough */
		snprintf(namebuf, sizeof namebuf, "%s:%s", getHOSTNAME(pMsg),
			getAPPNAME(pMsg, 0));
		if(withinThrottlelimit(ratelimit, pMsg->ttGenTime, namebuf) == 0) {
			msgDestruct(&pMsg);
			// update the number in throttle limiter
			throttlelimit->discarded++;
			ABORT_FINALIZE(RS_RET_DISCARDMSG);
		}
	}

	CHKiRet(doLastMessageDiscardedNTimes(throttlelimit, pMsg, ppRepMsg));

finalize_it:
	if(Debug) {
		if(iRet == RS_RET_DISCARDMSG)
			DBGPRINTF("message discarded by ratelimiting\n");
	}
	RETiRet;
}


/* add a message to a ratelimiter/multisubmit structure.
 * ratelimiting is automatically handled according to the ratelimit
 * settings.
 * if pMultiSub == NULL, a single-message enqueue happens (under reconsideration)
 */
rsRetVal
_throttlelimitAddMsg(throttlelimit_t *throttlelimit, multi_submit_t *pMultiSub, smsg_t *pMsg)
{
	rsRetVal localRet;

	smsg_t *repMsg;
	DEFiRet;

	if(pMultiSub == NULL) {
		localRet = throttlelimitMsg(throttlelimit, pMsg, &repMsg);
		if(repMsg != NULL)
			CHKiRet(submitMsg2(repMsg));
		if(localRet == RS_RET_OK)
			CHKiRet(submitMsg2(pMsg));
	} else {
		localRet = throttlelimitMsg(throttlelimit, pMsg, &repMsg);
dbgprintf("RRRRRR: localRet %d\n", localRet);
		if(repMsg != NULL) {
			pMultiSub->ppMsgs[pMultiSub->nElem++] = repMsg;
			if(pMultiSub->nElem == pMultiSub->maxElem)
				CHKiRet(multiSubmitMsg2(pMultiSub));
		}
		if(localRet == RS_RET_OK) {
			pMultiSub->ppMsgs[pMultiSub->nElem++] = pMsg;
			if(pMultiSub->nElem == pMultiSub->maxElem)
				CHKiRet(multiSubmitMsg2(pMultiSub));
		//} else if(localRet == RS_RET_DISCARDMSG) { /////
			//msgDestruct(&pMsg); /////
		}
	}

finalize_it:
	RETiRet;
}

rsRetVal
throttleIdsAddMsg(throttle_ids_t *pThis, smsg_t *pMsg, multi_submit_t *pMultiSub)
{
	DEFiRet;
	char	*pMsgStr = NULL;
	int 	len = 0;

	getRawMsg(pMsg, (uchar**)&pMsgStr, &len);

	char	*pIdText = NULL;
	char	*pTimestamp = NULL;
	char  	*pFreetext = NULL;
	parseMsg((const char*)pMsgStr, &pIdText, &pTimestamp, &pFreetext);
	assert(pIdText);

	throttlelimit_t *throttlelimiter = getThrottlelimiter(pThis, (char*)pIdText);
	// no throttle limiter configured, just submit it.
	if (throttlelimiter)
	{
		// update the other fields
		throttlelimiter->ID = pIdText;
		strncpy(throttlelimiter->timestamp, pTimestamp, sizeof(throttlelimiter->timestamp) - 1);
		throttlelimiter->freetext = pFreetext;
		DBGPRINTF("throttlelimiter: [%s], %s, %s, [%p]\n", throttlelimiter->ID,
				  throttlelimiter->timestamp,
				  throttlelimiter->freetext,
				  throttlelimiter->ratelimiter);
		ratelimit_t *ratelimiter = throttlelimiter->ratelimiter;
		assert(ratelimiter);

		iRet = _throttlelimitAddMsg(throttlelimiter, pMultiSub, pMsg);

		// print out some basic info about the ratelimit
		DBGPRINTF("%s(): iRet=%d, (key: %s, ratelimiter: %p, missed: %d)\n",
				  __FUNCTION__, iRet, pIdText, ratelimiter, ratelimiter->missed);
	} else {
		// submit and don't throttle
		if (pMultiSub == NULL) {
			CHKiRet(submitMsg2(pMsg));
		} else {
			pMultiSub->ppMsgs[pMultiSub->nElem++] = pMsg;
			if (pMultiSub->nElem == pMultiSub->maxElem)
				CHKiRet(multiSubmitMsg2(pMultiSub));
			//} else if(localRet == RS_RET_DISCARDMSG) { /////
			//msgDestruct(&pMsg); /////
		}
	}
finalize_it:
	RETiRet;
}
