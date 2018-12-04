/* imdocker.c
 * This is an implementation of the docker container log input module. It uses the
 * Docker API in order to stream all container logs available on a host. Will also
 * update relevant container metadata.
 *
 * This file is part of rsyslog.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *       -or-
 *       see COPYING.ASL20 in the source distribution
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifdef __sun
#define _XPG4_2
#endif
#include "config.h"
#include "rsyslog.h"
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <errno.h>
#include <curl/curl.h>
#include <json.h>
#include "cfsysline.h"  /* access to config file objects */
#include "unicode-helper.h"
#include "module-template.h"
#include "srUtils.h"    /* some utility functions */
#include "errmsg.h"
#include "net.h"
#include "glbl.h"
#include "msg.h"
#include "parser.h"
#include "prop.h"
#include "debug.h"
#include "ruleset.h"
#include "statsobj.h"
#include "datetime.h"
#include "hashtable.h"
#include "ratelimit.h"
#include "linkedlist.h"

#if !defined(_AIX)
#pragma GCC diagnostic ignored "-Wswitch-enum"
#endif

MODULE_TYPE_INPUT
MODULE_TYPE_NOKEEP
MODULE_CNFNAME("imdocker")

extern int Debug;

//#define ENABLE_DEBUG_BYTE_BUFFER
//#define ENABLE_IMDOCKER_UNIT_TESTS

/* defines */
#define DOCKER_CONTAINER_ID_PARSE_NAME      "Id"
#define DOCKER_CONTAINER_NAMES_PARSE_NAME   "Names"
#define DOCKER_CONTAINER_IMAGEID_PARSE_NAME "ImageID"
#define DOCKER_CONTAINER_LABELS_PARSE_NAME  "Labels"

/* DEFAULT VALUES */
#define DFLT_pollingInterval   60      /* polling interval in seconds */
#define DFLT_containersLimit   25      /* maximum number of containers */
#define DFLT_trimLineOverBytes 4194304 /* limit log lines to the value - 4MB default */

#ifdef ENABLE_IMDOCKER_UNIT_TESTS
#include "imdocker_unit_tests.h"
#endif

enum {
	dst_invalid = -1,
	dst_stdin,
	dst_stdout,
	dst_stderr,
	dst_stream_type_count
} docker_stream_type_t;

/* imdocker specific structs */
typedef struct imdocker_buf_s {
	uchar  *data;
	size_t len;
	size_t data_size;
} imdocker_buf_t;

typedef struct docker_cont_logs_buf_s {
	imdocker_buf_t *buf;
	int8_t         stream_type;
	size_t         bytes_remaining;
} docker_cont_logs_buf_t;

struct docker_cont_logs_inst_s;
typedef rsRetVal (*submitmsg_funcptr) (struct docker_cont_logs_inst_s *pInst, docker_cont_logs_buf_t *pBufdata,
		const uchar* pszTag);
typedef submitmsg_funcptr SubmitMsgFuncPtr;

/* curl request instance */
typedef struct docker_cont_logs_req_s {
	CURL     *curl;
	docker_cont_logs_buf_t* data_bufs[dst_stream_type_count];
	SubmitMsgFuncPtr submitMsg;
} docker_cont_logs_req_t;

typedef struct imdocker_req_s {
	CURL           *curl;
	imdocker_buf_t *buf;
} imdocker_req_t;

typedef struct docker_container_info_s {
	uchar *name;
	uchar *image_id;
	/* json string container labels */
	uchar *json_str_labels;
} docker_container_info_t;

typedef struct docker_cont_logs_inst_s {
	char* id;
	char short_id[12];
	docker_container_info_t *container_info;
	docker_cont_logs_req_t  *logsReq;
} docker_cont_logs_inst_t;

/* set of curl requests */
typedef struct imdocker_reqs_s {
	size_t          size;
	imdocker_req_t  **reqs;
	size_t          capacity;
} imdocker_reqs_t;

typedef struct docker_cont_log_instances_s {
	linkedList_t  ll_container_log_insts;  /* linkedlist of type	docker_cont_logs_inst_t */
	CURLM         *curlm;
} docker_cont_log_instances_t;

/* FORWARD DEFINITIONS */

/* imdocker_buf_t */
static rsRetVal imdockerBufNew(imdocker_buf_t **ppThis);
static void imdockerBufDestruct(imdocker_buf_t *pThis);

/* docker_cont_logs_buf_t */
static rsRetVal dockerContLogsBufNew(docker_cont_logs_buf_t **ppThis);
static void dockerContLogsBufDestruct(docker_cont_logs_buf_t *pThis);
static rsRetVal dockerContLogsBufWrite(docker_cont_logs_buf_t *pThis, const uchar *pdata, size_t write_size);

/* imdocker_req_t */
static rsRetVal imdockerReqNew(imdocker_req_t **ppThis);
static void imdockerReqDestruct(imdocker_req_t *pThis);

/* docker_cont_logs_req_t */
static rsRetVal dockerContLogsReqNew(docker_cont_logs_req_t **ppThis, SubmitMsgFuncPtr submitMsg);
static void dockerContLogsReqDestruct(docker_cont_logs_req_t *pThis);

/* docker_cont_logs_inst_t */
static rsRetVal dockerContLogsInstNew(docker_cont_logs_inst_t **ppThis, const char* id, SubmitMsgFuncPtr submitMsg);
static void dockerContLogsInstDestruct(docker_cont_logs_inst_t *pThis);
static rsRetVal dockerContLogsInstSetUrlById (docker_cont_logs_inst_t *pThis, CURLM *curlm, const char* containerId);
static rsRetVal dockerContLogReqsDestructForLinkedList(void *pData);

/* docker_cont_log_instances_t */
static rsRetVal llKeyDestruct(void __attribute__((unused)) *pData);
static rsRetVal dockerContLogReqsNew(docker_cont_log_instances_t **ppThis);
static rsRetVal dockerContLogReqsDestruct(docker_cont_log_instances_t *pThis);
static rsRetVal dockerContLogReqsGet(docker_cont_log_instances_t *pThis,
		docker_cont_logs_inst_t** ppContLogsInst, const char *id);
static rsRetVal dockerContLogReqsPrint(docker_cont_log_instances_t *pThis);
static rsRetVal dockerContLogReqsAdd(docker_cont_log_instances_t *pThis, docker_cont_logs_inst_t *pContLogsReqInst);
static rsRetVal dockerContLogReqsRemove(docker_cont_log_instances_t *pThis, const char *id);

/* docker_container_info_t */
static rsRetVal dockerContainerInfoNew(docker_container_info_t **pThis);
static void dockerContainerInfoDestruct(docker_container_info_t *pThis);

/* utility functions */
static rsRetVal SubmitMsg(docker_cont_logs_inst_t *pInst, docker_cont_logs_buf_t *pBufData, const uchar* pszTag);
static size_t imdocker_container_list_curlCB(void *data, size_t size, size_t nmemb, void *buffer);
static size_t imdocker_container_logs_curlCB(void *data, size_t size, size_t nmemb, void *buffer);
static sbool get_stream_info(const uchar* data, size_t size, int8_t *stream_type, size_t *payload_size);
static int8_t is_valid_stream_type(int8_t stream_type);

/* unit tests */
#ifdef ENABLE_IMDOCKER_UNIT_TESTS
static void UnitTests_imdocker_run();
#endif

/* Module static data */
DEF_IMOD_STATIC_DATA
DEFobjCurrIf(glbl)
DEFobjCurrIf(prop)
DEFobjCurrIf(parser)
DEFobjCurrIf(datetime)
DEFobjCurrIf(statsobj)
DEFobjCurrIf(ruleset)

statsobj_t *modStats;
STATSCOUNTER_DEF(ctrSubmit, mutCtrSubmit)
STATSCOUNTER_DEF(ctrLostRatelimit, mutCtrLostRatelimit)
STATSCOUNTER_DEF(ctrCurlError, mutctrCurlError)

const char* DFLT_dockerAPIUnixSockAddr  = "/var/run/docker.sock";
const char* DFLT_dockerAPIAdd           = "http://localhost:2375";
const char* DFLT_apiVersionStr          = "v1.27";
const char* DFLT_listContainersOptions  = "";
const char* DFLT_getContainerLogOptions = "timestamps=0&follow=1&stdout=1&stderr=1";

/* config vars for the legacy config system */
static struct configSettings_s {
	int       iFacility;
	int       iSeverity;
	/* Docker API urls */
	uchar     *apiVersionStr;
	uchar     *listContainersOptions;
	uchar     *getContainerLogOptions;
	int       iPollInterval;  /* in seconds */
	uchar     *dockerApiUnixSockAddr;
	uchar     *dockerApiAddr;
	int       containersLimit;
	int       trimLineOverBytes;
} cs;

/* Overall module configuration structure here. */
struct modConfData_s {
	rsconf_t *pConf;  /* our overall config object */
	int      iFacility;
	int      iSeverity;
	uchar    *apiVersionStr;
	uchar    *listContainersOptions;
	uchar    *getContainerLogOptions;
	int      iPollInterval;  /* in seconds */
	uchar    *dockerApiUnixSockAddr;
	uchar    *dockerApiAddr;
	int      containersLimit;
	int      trimLineOverBytes;
};

static modConfData_t *loadModConf = NULL;
static modConfData_t *runModConf = NULL;

static prop_t *pInputName = NULL;   /* our inputName currently is always "imdocker", and this will hold it */
static prop_t *pLocalHostIP = NULL; /* a pseudo-constant propterty for 127.0.0.1 */

static ratelimit_t *ratelimiter = NULL;

/* module-global parameters */
static struct cnfparamdescr modpdescr[] = {
	{ "apiversionstr", eCmdHdlrString, 0 },
	{ "dockerapiunixsockaddr", eCmdHdlrString, 0 },
	{ "dockerapiaddr", eCmdHdlrString, 0 },
	{ "listcontainersoptions", eCmdHdlrString, 0 },
	{ "getcontainerlogoptions", eCmdHdlrString, 0 },
	{ "pollinginterval", eCmdHdlrPositiveInt, 0 },
	{ "trimlineoverbytes", eCmdHdlrPositiveInt, 0 },
	{ "ruleset", eCmdHdlrString, 0 }
};

static struct cnfparamblk modpblk =
	{ CNFPARAMBLK_VERSION,
		sizeof(modpdescr)/sizeof(struct cnfparamdescr),
		modpdescr
	};

static int bLegacyCnfModGlobalsPermitted; /* are legacy module-global config parameters permitted? */

/* imdocker specific functions */
static rsRetVal
imdockerBufNew(imdocker_buf_t **ppThis) {
	DEFiRet;

	imdocker_buf_t *pThis = (imdocker_buf_t*) calloc(1, sizeof(imdocker_buf_t));
	CHKmalloc(pThis);
	*ppThis = pThis;

finalize_it:
	RETiRet;
}

static void
imdockerBufDestruct(imdocker_buf_t *pThis) {
	if (pThis) {
		if (pThis->data) {
			free(pThis->data);
			pThis->data = NULL;
		}
		free(pThis);
		pThis = NULL;
	}
}

static rsRetVal
dockerContLogsBufNew(docker_cont_logs_buf_t **ppThis) {
	DEFiRet;

	docker_cont_logs_buf_t *pThis = (docker_cont_logs_buf_t*) calloc(1, sizeof(docker_cont_logs_buf_t));
	CHKmalloc(pThis);
	imdockerBufNew(&pThis->buf);
	pThis->stream_type = dst_invalid;
	pThis->bytes_remaining = 0;
	*ppThis = pThis;

finalize_it:
	RETiRet;
}

static void
dockerContLogsBufDestruct(docker_cont_logs_buf_t *pThis) {
	if (pThis) {
		if (pThis->buf) {
			imdockerBufDestruct(pThis->buf);
		}
		free(pThis);
		pThis=NULL;
	}
}

static rsRetVal
dockerContLogsBufWrite(docker_cont_logs_buf_t *pThis, const uchar *pdata, size_t write_size) {
	DEFiRet;

	imdocker_buf_t *mem = pThis->buf;
	if (mem->len + write_size > mem->data_size) {
		uchar *pbuf=NULL;
		if ((pbuf = realloc(mem->data, mem->len + write_size + 1)) == NULL) {
			LogError(errno, RS_RET_ERR, "%s() - realloc failed!\n", __FUNCTION__);
			ABORT_FINALIZE(RS_RET_OUT_OF_MEMORY);
		}
		mem->data = pbuf;
		mem->data_size = mem->len+ write_size + 1;
	}
	/* copy the bytes, and advance pdata */
	memcpy(&(mem->data[mem->len]), pdata, write_size);
	mem->len += write_size;
	mem->data[mem->len] = '\0';

	if (write_size > pThis->bytes_remaining) {
		pThis->bytes_remaining = 0;
	} else {
		pThis->bytes_remaining -= write_size;
	}

finalize_it:
	return iRet;
}

rsRetVal imdockerReqNew(imdocker_req_t **ppThis) {
	DEFiRet;

	imdocker_req_t *pThis = (imdocker_req_t*) calloc(1, sizeof(imdocker_req_t));
	CHKmalloc(pThis);
	pThis->curl = curl_easy_init();
	if (!pThis->curl) {
		ABORT_FINALIZE(RS_RET_ERR);
	}

	imdockerBufNew(&(pThis->buf));
	*ppThis = pThis;

finalize_it:
	RETiRet;
}

void imdockerReqDestruct(imdocker_req_t *pThis) {
	if (pThis) {
		if (pThis->buf) {
			imdockerBufDestruct(pThis->buf);
		}

		if (pThis->curl) {
			curl_easy_cleanup(pThis->curl);
			pThis->curl = NULL;
		}
		free(pThis);
		pThis = NULL;
	}
}

static rsRetVal
dockerContLogsReqNew(docker_cont_logs_req_t **ppThis, SubmitMsgFuncPtr submitMsg) {
	DEFiRet;

	docker_cont_logs_req_t *pThis = (docker_cont_logs_req_t*) calloc(1, sizeof(docker_cont_logs_req_t));
	CHKmalloc(pThis);
	pThis->submitMsg = submitMsg;
	pThis->curl = curl_easy_init();
	if (!pThis->curl) {
		ABORT_FINALIZE(RS_RET_ERR);
	}

	for (int i = 0; i < dst_stream_type_count; i ++) {
		CHKiRet(dockerContLogsBufNew(&pThis->data_bufs[i]));
	}

	*ppThis = pThis;

finalize_it:
	if (iRet != RS_RET_OK) {
		if (pThis) {
			dockerContLogsReqDestruct(pThis);
		}
	}
	RETiRet;
}

static void
dockerContLogsReqDestruct(docker_cont_logs_req_t *pThis) {
	if (pThis) {
		for (int i = 0; i < dst_stream_type_count; i++) {
			dockerContLogsBufDestruct(pThis->data_bufs[i]);
		}

		if (pThis->curl) {
			curl_easy_cleanup(pThis->curl);
			pThis->curl=NULL;
		}

		free(pThis);
		pThis = NULL;
	}
}

/**
 * debugging aide
 */
static rsRetVal
dockerContLogsInstPrint(docker_cont_logs_inst_t * pThis) {
	DEFiRet;
	DBGPRINTF("\t container id: %s\n", pThis->id);
	char* pUrl = NULL;
	curl_easy_getinfo(pThis->logsReq->curl, CURLINFO_EFFECTIVE_URL, &pUrl);
	DBGPRINTF("\t container url: %s\n", pUrl);

	RETiRet;
}

static void
dockerContLogsInstDestruct(docker_cont_logs_inst_t *pThis) {
	if (pThis->id) {
		free((void*)pThis->id);
	}
	if (pThis->container_info) {
		dockerContainerInfoDestruct(pThis->container_info);
	}
	if (pThis->logsReq) {
		dockerContLogsReqDestruct(pThis->logsReq);
	}
}

static rsRetVal
dockerContLogsInstNew(docker_cont_logs_inst_t **ppThis, const char* id, SubmitMsgFuncPtr submitMsg) {
	DEFiRet;

	docker_cont_logs_inst_t *pThis = NULL;
	CHKmalloc(pThis = calloc(1, sizeof(docker_cont_logs_inst_t)));

	pThis->id = strdup((char*)id);
	strncpy((char*) pThis->short_id, id, sizeof(pThis->short_id));
	CHKiRet(dockerContLogsReqNew(&pThis->logsReq, submitMsg));
	pThis->container_info = NULL;
	*ppThis = pThis;

finalize_it:
	if (iRet != RS_RET_OK) {
		if (pThis) {
			dockerContLogsInstDestruct(pThis);
		}
	}
	RETiRet;
}

static rsRetVal
dockerContLogsInstSetUrl(docker_cont_logs_inst_t *pThis, CURLM *curlm, const char* pUrl) {
	DEFiRet;
	CURLcode ccode = CURLE_OK;

	if (curlm) {
		docker_cont_logs_req_t *req = pThis->logsReq;
		if (!runModConf->dockerApiAddr) {
			if ((ccode = curl_easy_setopt(req->curl, CURLOPT_UNIX_SOCKET_PATH, runModConf->dockerApiUnixSockAddr))
					!= CURLE_OK) {
				LogError(0, RS_RET_ERR, "imdocker: curl_easy_setopt(CURLOPT_UNIX_SOCKET_PATH) error - %d:%s\n",
						ccode, curl_easy_strerror(ccode));
				ABORT_FINALIZE(RS_RET_ERR);
			}
		}
		if ((ccode = curl_easy_setopt(req->curl, CURLOPT_WRITEFUNCTION, imdocker_container_logs_curlCB))
				!= CURLE_OK) {
				LogError(0, RS_RET_ERR, "imdocker: curl_easy_setopt(CURLOPT_WRITEFUNCTION) error - %d:%s\n",
						ccode, curl_easy_strerror(ccode));
				ABORT_FINALIZE(RS_RET_ERR);
		}

		if ((ccode = curl_easy_setopt(req->curl, CURLOPT_WRITEDATA, pThis)) != CURLE_OK) {
				LogError(0, RS_RET_ERR, "imdocker: curl_easy_setopt(CURLOPT_WRITEDATA) error - %d:%s\n",
						ccode, curl_easy_strerror(ccode));
				ABORT_FINALIZE(RS_RET_ERR);
		}

		if ((ccode = curl_easy_setopt(pThis->logsReq->curl, CURLOPT_URL, pUrl)) != CURLE_OK) {
			LogError(0, RS_RET_ERR, "imdocker: could not set url - %d:%s\n", ccode, curl_easy_strerror(ccode));
			ABORT_FINALIZE(RS_RET_ERR);
		}
		if ((ccode = curl_easy_setopt(pThis->logsReq->curl, CURLOPT_PRIVATE, pThis->id)) != CURLE_OK) {
			LogError(0, RS_RET_ERR, "imdocker: could not set private data - %d:%s\n", ccode, curl_easy_strerror(ccode));
			ABORT_FINALIZE(RS_RET_ERR);
		}
		if ((ccode = curl_multi_add_handle(curlm, pThis->logsReq->curl)) != CURLE_OK) {
			LogError(0, RS_RET_ERR, "imdocker: error curl_multi_add_handle ret- %d:%s\n", ccode, curl_easy_strerror(ccode));
			ABORT_FINALIZE(RS_RET_ERR);
		}
	}

finalize_it:
	if (ccode != CURLE_OK) {
		STATSCOUNTER_INC(ctrCurlError, mutCtrCurlError);
	}
	RETiRet;
}

static rsRetVal
dockerContLogsInstSetUrlById (docker_cont_logs_inst_t *pThis, CURLM *curlm, const char* containerId) {
	char url[256];
	const uchar* container_log_options = runModConf->getContainerLogOptions;

	const uchar* pApiAddr = (uchar*)"http:";
	if (runModConf->dockerApiAddr) {
		pApiAddr = runModConf->dockerApiAddr;
	}

	snprintf(url, sizeof(url), "%s/%s/containers/%s/logs?%s",
			pApiAddr, runModConf->apiVersionStr, containerId, container_log_options);
	DBGPRINTF("%s() - url: %s\n", __FUNCTION__, url);

	return dockerContLogsInstSetUrl(pThis, curlm, url);
}


/* this is a special destructor for the linkedList class. LinkedList does NOT
 * provide a pointer to the pointer, but rather the raw pointer itself. So we
 * must map this, otherwise the destructor will abort.
 */
static rsRetVal
dockerContLogReqsDestructForLinkedList(void *pData) {
	docker_cont_logs_inst_t *pThis = (docker_cont_logs_inst_t *) pData;
	dockerContLogsInstDestruct(pThis);
	return RS_RET_OK;
}

static rsRetVal llKeyDestruct(void __attribute__((unused)) *pData) {
	if (pData) {
		free(pData);
	}
	return RS_RET_OK;
}

static rsRetVal
dockerContLogReqsNew(docker_cont_log_instances_t **ppThis) {
	DEFiRet;

	docker_cont_log_instances_t *pThis = calloc(1, sizeof(docker_cont_log_instances_t));
	CHKmalloc(pThis);
	CHKiRet(llInit(&pThis->ll_container_log_insts, dockerContLogReqsDestructForLinkedList, llKeyDestruct, strcasecmp));

	pThis->curlm = curl_multi_init();
	if (!pThis->curlm) {
		ABORT_FINALIZE(RS_RET_ERR);
	}

	*ppThis = pThis;

finalize_it:
	RETiRet;
}

static rsRetVal
dockerContLogReqsDestruct(docker_cont_log_instances_t *pThis) {
	DEFiRet;

	llDestroy(&(pThis->ll_container_log_insts));
	curl_multi_cleanup(pThis->curlm);
	free(pThis);
	pThis = NULL;

	RETiRet;
}

static rsRetVal
dockerContLogReqsGet(docker_cont_log_instances_t *pThis,
		docker_cont_logs_inst_t** ppContLogsInst, const char *id) {
	DEFiRet;

	if (ppContLogsInst && id) {
		CHKiRet(llFind(&(pThis->ll_container_log_insts), (void*)id, (void*)ppContLogsInst));
	}

finalize_it:
	RETiRet;
}

/* helper for debugPrintAll(), prints a single container instance */
DEFFUNC_llExecFunc(doDebugPrintAll) {
	return dockerContLogsInstPrint(pData);
}

/* debug print all rulesets
 */
static rsRetVal
dockerContLogReqsPrint(docker_cont_log_instances_t *pThis) {
	DEFiRet;
	int count = 0;
	CHKiRet(llGetNumElts(&pThis->ll_container_log_insts, &count));
	if (count) {
		dbgprintf("%s() - All container instances, count=%d...\n", __FUNCTION__, count);
		llExecFunc(&(pThis->ll_container_log_insts), doDebugPrintAll, NULL);
		dbgprintf("End of container instances.\n");
	}

finalize_it:
	RETiRet;
}

static rsRetVal
dockerContLogReqsAdd(docker_cont_log_instances_t *pThis, docker_cont_logs_inst_t *pContLogsReqInst) {
	DEFiRet;
	if (!pContLogsReqInst) {
		return RS_RET_ERR;
	}

	uchar *keyName = (uchar*)strdup((char*)pContLogsReqInst->id);

	if (keyName) {
		docker_cont_logs_inst_t *pFind;
		if (RS_RET_NOT_FOUND == dockerContLogReqsGet(pThis, &pFind, (void*)keyName)) {
			CHKiRet(llAppend(&(pThis->ll_container_log_insts), keyName, pContLogsReqInst));
		}
	}

finalize_it:
	RETiRet;
}

static rsRetVal
dockerContLogReqsRemove(docker_cont_log_instances_t *pThis, const char *id) {
DEFiRet;

	if (pThis && id) {
		CHKiRet(llFindAndDelete(&(pThis->ll_container_log_insts), (void*)id));
	}

finalize_it:
	RETiRet;
}

static rsRetVal
dockerContainerInfoNew(docker_container_info_t **ppThis) {
	DEFiRet;
	docker_container_info_t* pThis = calloc(1, sizeof(docker_container_info_t));
	CHKmalloc(pThis);
	*ppThis = pThis;

finalize_it:
	if (iRet != RS_RET_OK) {
		dockerContainerInfoDestruct(pThis);
	}
	RETiRet;
}

static void
dockerContainerInfoDestruct(docker_container_info_t *pThis) {
	if (pThis) {
		if (pThis->image_id) { free(pThis->image_id); }
		if (pThis->name) { free(pThis->name); }
		if (pThis->json_str_labels) { free(pThis->json_str_labels); }
		pThis = NULL;
	}
}

BEGINbeginCnfLoad
CODESTARTbeginCnfLoad

	dbgprintf("imdocker: beginCnfLoad\n");

	loadModConf = pModConf;
	pModConf->pConf = pConf;

	/* init our settings */
	loadModConf->iPollInterval     = DFLT_pollingInterval; /* in seconds */
	loadModConf->containersLimit   = DFLT_containersLimit;
	loadModConf->trimLineOverBytes = DFLT_trimLineOverBytes;

	/* Use the default url */
	loadModConf->apiVersionStr          = NULL;
	loadModConf->dockerApiUnixSockAddr  = NULL;
	loadModConf->dockerApiAddr          = NULL;
	loadModConf->listContainersOptions  = NULL;
	loadModConf->getContainerLogOptions = NULL;

	/* init legacy config vars */
	cs.iFacility              = 0;
	cs.iSeverity              = 0;
	cs.iPollInterval          = loadModConf->iPollInterval;	/* in seconds */
	cs.containersLimit        = loadModConf->containersLimit;
	cs.trimLineOverBytes      = loadModConf->trimLineOverBytes;
	cs.dockerApiUnixSockAddr  = loadModConf->dockerApiUnixSockAddr;
	cs.dockerApiAddr          = loadModConf->dockerApiAddr;
	cs.apiVersionStr          = loadModConf->apiVersionStr;
	cs.listContainersOptions  = loadModConf->listContainersOptions;
	cs.getContainerLogOptions = loadModConf->getContainerLogOptions;
ENDbeginCnfLoad

BEGINsetModCnf
	struct cnfparamvals *pvals = NULL;
	int i;
CODESTARTsetModCnf
	pvals = nvlstGetParams(lst, &modpblk, NULL);
	if(pvals == NULL) {
		LogError(0, RS_RET_MISSING_CNFPARAMS, "error processing module "
				"config parameters [module(...)]");
		ABORT_FINALIZE(RS_RET_MISSING_CNFPARAMS);
	}

	if (Debug) {
		dbgprintf("module (global) param blk for imdocker:\n");
		cnfparamsPrint(&modpblk, pvals);
	}

	for(i = 0 ; i < modpblk.nParams ; ++i) {
		dbgprintf("%s() - iteration %d\n", __FUNCTION__,i);
		dbgprintf("%s() - modpblk descr: %s\n", __FUNCTION__, modpblk.descr[i].name);
		if(!pvals[i].bUsed)
			continue;
		if(!strcmp(modpblk.descr[i].name, "pollinginterval")) {
			loadModConf->iPollInterval = (int) pvals[i].val.d.n;
		} else if(!strcmp(modpblk.descr[i].name, "containterlimit")) {
			loadModConf->containersLimit = (int) pvals[i].val.d.n;
		} else if(!strcmp(modpblk.descr[i].name, "trimlineoverbytes")) {
			loadModConf->trimLineOverBytes = (int) pvals[i].val.d.n;
		} else if(!strcmp(modpblk.descr[i].name, "listcontainersoptions")) {
			loadModConf->listContainersOptions = (uchar*)es_str2cstr(pvals[i].val.d.estr, NULL);
		} else if(!strcmp(modpblk.descr[i].name, "getcontainerlogoptions")) {
			loadModConf->getContainerLogOptions = (uchar*)es_str2cstr(pvals[i].val.d.estr, NULL);
		} else if(!strcmp(modpblk.descr[i].name, "dockerapiunixsockaddr")) {
			loadModConf->dockerApiUnixSockAddr = (uchar*)es_str2cstr(pvals[i].val.d.estr, NULL);
		} else if(!strcmp(modpblk.descr[i].name, "dockerapiaddr")) {
			loadModConf->dockerApiAddr = (uchar*)es_str2cstr(pvals[i].val.d.estr, NULL);
		} else if(!strcmp(modpblk.descr[i].name, "apiversionstr")) {
			loadModConf->apiVersionStr = (uchar*)es_str2cstr(pvals[i].val.d.estr, NULL);
		} else {
			LogError(0, RS_RET_INVALID_PARAMS,
					"imdocker: program error, non-handled "
					"param '%s' in setModCnf\n", modpblk.descr[i].name);
		}
	}

	/* disable legacy module-global config directives */
	bLegacyCnfModGlobalsPermitted = 0;

finalize_it:
	if(pvals != NULL)
		cnfparamvalsDestruct(pvals, &modpblk);
ENDsetModCnf

BEGINendCnfLoad
CODESTARTendCnfLoad
ENDendCnfLoad

BEGINcheckCnf
CODESTARTcheckCnf
#ifdef ENABLE_IMDOCKER_UNIT_TESTS
	UnitTests_imdocker_run();
#endif
ENDcheckCnf

BEGINactivateCnf
CODESTARTactivateCnf
	if (!loadModConf->dockerApiUnixSockAddr) {
		loadModConf->dockerApiUnixSockAddr = (uchar*) strdup(DFLT_dockerAPIUnixSockAddr);
	}
	if (!loadModConf->apiVersionStr) {
		loadModConf->apiVersionStr = (uchar*) strdup(DFLT_apiVersionStr);
	}
	if (!loadModConf->listContainersOptions) {
		loadModConf->listContainersOptions = (uchar*) strdup(DFLT_listContainersOptions);
	}
	if (!loadModConf->getContainerLogOptions) {
		loadModConf->getContainerLogOptions = (uchar*) strdup(DFLT_getContainerLogOptions);
	}
	runModConf = loadModConf;

	/* support statistics gathering */
	CHKiRet(statsobj.Construct(&modStats));
	CHKiRet(statsobj.SetName(modStats, UCHAR_CONSTANT("imdocker")));
	CHKiRet(statsobj.SetOrigin(modStats, UCHAR_CONSTANT("imdocker")));

	STATSCOUNTER_INIT(ctrSubmit, mutCtrSubmit);
	CHKiRet(statsobj.AddCounter(modStats, UCHAR_CONSTANT("submitted"),
		ctrType_IntCtr, CTR_FLAG_RESETTABLE, &ctrSubmit));

	STATSCOUNTER_INIT(ctrLostRatelimit, mutCtrLostRatelimit);
	CHKiRet(statsobj.AddCounter(modStats, UCHAR_CONSTANT("ratelimit.discarded"),
		ctrType_IntCtr, CTR_FLAG_RESETTABLE, &ctrLostRatelimit));

	STATSCOUNTER_INIT(ctrCurlError, mutctrCurlError);
	CHKiRet(statsobj.AddCounter(modStats, UCHAR_CONSTANT("curl.errors"),
		ctrType_IntCtr, CTR_FLAG_RESETTABLE, &ctrCurlError));

	CHKiRet(statsobj.ConstructFinalize(modStats));
	/* end stats */
finalize_it:
ENDactivateCnf

BEGINfreeCnf
CODESTARTfreeCnf
	if (loadModConf->dockerApiUnixSockAddr) {
		free(loadModConf->dockerApiUnixSockAddr);
	}
	if (loadModConf->dockerApiAddr) {
		free(loadModConf->dockerApiAddr);
	}
	if (loadModConf->apiVersionStr) {
		free(loadModConf->apiVersionStr);
	}
	if (loadModConf->getContainerLogOptions) {
		free(loadModConf->getContainerLogOptions);
	}
	if (loadModConf->listContainersOptions) {
		free(loadModConf->listContainersOptions);
	}
	statsobj.Destruct(&modStats);
ENDfreeCnf

static rsRetVal
addDockerMetaData(const uchar* container_id, docker_container_info_t* pinfo, smsg_t *pMsg) {
	const uchar *names[4] = {
		(const uchar*) DOCKER_CONTAINER_ID_PARSE_NAME,
		(const uchar*) DOCKER_CONTAINER_NAMES_PARSE_NAME,
		(const uchar*) DOCKER_CONTAINER_IMAGEID_PARSE_NAME,
		(const uchar*) DOCKER_CONTAINER_LABELS_PARSE_NAME
	};

	const uchar * empty_str= (const uchar*) "";
	const uchar *id = container_id ? container_id : empty_str;
	const uchar *name = pinfo->name ? pinfo->name : empty_str;
	const uchar *image_id = pinfo->image_id ? pinfo->image_id : empty_str;
	const uchar *json_str_labels = pinfo->json_str_labels ? pinfo->json_str_labels : empty_str;

	const uchar *values[4] = {
		id,
		name,
		image_id,
		json_str_labels
	};

	return msgAddMultiMetadata(pMsg, names, values, 3);
}

static rsRetVal
enqMsg(docker_cont_logs_inst_t *pInst, uchar *msg, const uchar *pszTag, struct timeval *tp)
{
	struct syslogTime st;
	smsg_t *pMsg;
	size_t len;
	DEFiRet;

	if (!msg) {
		return RS_RET_ERR;
	}

	if(tp == NULL) {
		CHKiRet(msgConstruct(&pMsg));
	} else {
		datetime.timeval2syslogTime(tp, &st, TIME_IN_LOCALTIME);
		CHKiRet(msgConstructWithTime(&pMsg, &st, tp->tv_sec));
	}
	MsgSetFlowControlType(pMsg, eFLOWCTL_LIGHT_DELAY);
	MsgSetInputName(pMsg, pInputName);
	len = strlen((char*)msg);
	MsgSetRawMsg(pMsg, (char*)msg, len);
	if(len > 0)
		parser.SanitizeMsg(pMsg);
	MsgSetMSGoffs(pMsg, 0);  /* we do not have a header... */
	MsgSetRcvFrom(pMsg, glbl.GetLocalHostNameProp());
	MsgSetRcvFromIP(pMsg, pLocalHostIP);
	MsgSetHOSTNAME(pMsg, glbl.GetLocalHostName(), ustrlen(glbl.GetLocalHostName()));
	MsgSetTAG(pMsg, pszTag, ustrlen(pszTag));

	/* docker container metadata */
	addDockerMetaData((const uchar*)pInst->short_id, pInst->container_info, pMsg);

	DBGPRINTF("imdocker: enqMsg - %s\n", msg);
	CHKiRet(ratelimitAddMsg(ratelimiter, NULL, pMsg));
	STATSCOUNTER_INC(ctrSubmit, mutCtrSubmit);

finalize_it:
	if (iRet == RS_RET_DISCARDMSG)
		STATSCOUNTER_INC(ctrLostRatelimit, mutCtrLostRatelimit)

	RETiRet;
}

static int8_t
is_valid_stream_type(int8_t stream_type) {
	return (dst_invalid < stream_type && stream_type < dst_stream_type_count);
}

/* For use to get docker specific stream information */
static sbool
get_stream_info(const uchar* data, size_t size, int8_t *stream_type, size_t *payload_size) {
	if (size < 8 || !data || !stream_type || !payload_size) {
		return 0;
	}
	const uchar* pdata = data;
	*stream_type = pdata[0];
	pdata += 4;

	*payload_size = ntohl(*(uint32_t*)pdata);
	pdata += 4;
	return 1;
}
#ifdef ENABLE_DEBUG_BYTE_BUFFER
static void debug_byte_buffer(const uchar* data, size_t size) {
	if (Debug) {
		DBGPRINTF("%s() - ENTER, size=%lu\n", __FUNCTION__, size);
		for (size_t i = 0; i < size; i++) {
			DBGPRINTF("0x%02x,", data[i]);
		}
		DBGPRINTF("\n");
	}
}
#endif

/**
 * imdocker_container_list_curlCB
 *
 * Callback function for CURLOPT_WRITEFUNCTION to get
 * the results of a docker api call to list all containers.
 *
 */
static size_t
imdocker_container_list_curlCB(void *data, size_t size, size_t nmemb, void *buffer) {
	DEFiRet;

	size_t realsize = size*nmemb;
	uchar		*pbuf=NULL;
	imdocker_buf_t *mem = (imdocker_buf_t*)buffer;

	if ((pbuf = realloc(mem->data, mem->len + realsize + 1)) == NULL) {
		LogError(errno, RS_RET_ERR, "%s() - realloc failed!\n", __FUNCTION__);
		ABORT_FINALIZE(RS_RET_ERR);
	}

	mem->data = pbuf;
	mem->data_size = mem->len + realsize + 1;

	memcpy(&(mem->data[mem->len]), data, realsize);
	mem->len += realsize;
	mem->data[mem->len] = 0;

#ifdef ENABLE_DEBUG_BYTE_BUFFER
	debug_byte_buffer((const uchar*) data, realsize);
#endif
finalize_it:
	if (iRet != RS_RET_OK) {
		return 0;
	}
	return realsize;
}

static rsRetVal
SubmitMsg(docker_cont_logs_inst_t *pInst, docker_cont_logs_buf_t *pBufData, const uchar* pszTag) {
	imdocker_buf_t *mem = (imdocker_buf_t*)pBufData->buf;
	DBGPRINTF("%s() - enqMsg: {type=%d, len=%lu} %s\n",
			__FUNCTION__, pBufData->stream_type, mem->len, mem->data);

	uchar* message = mem->data;
	enqMsg(pInst, message, (const uchar*)pszTag, NULL);

	/* clear existing buffer. */
	mem->len = 0;
	memset(mem->data, 0, mem->data_size);
	pBufData->bytes_remaining = 0;

	return RS_RET_OK;
}

/** imdocker_container_logs_curlCB
 *
 * Callback function for CURLOPT_WRITEFUNCTION, gets container logs
 *
 * The main container log stream handler. This function is registerred with curl to
 * as callback to handle container log streaming. It follows the docker stream protocol
 * as described in the docker container logs api. As per docker's api documentation,
 * Docker Stream format:
 * When the TTY setting is disabled in POST /containers/create, the stream over the
 * hijacked connected is multiplexed to separate out stdout and stderr. The stream
 * consists of a series of frames, each containing a header and a payload.
 *
 * The header contains the information which the stream writes (stdout or stderr). It also
 * contains the size of the associated frame encoded in the last four bytes (uint32).
 *
 * It is encoded on the first eight bytes like this:
 *
 * header := [8]byte{STREAM_TYPE, 0, 0, 0, SIZE1, SIZE2, SIZE3, SIZE4}
 * STREAM_TYPE can be:
 * 0: stdin (is written on stdout)
 * 1: stdout
 * 2: stderr
 *
 * Docker sends out data in 16KB sized frames, however with the addition of a header
 * of 8 bytes, a frame may be split into 2 chunks by curl. The 2nd chunk will only
 * contain enough data to complete the frame (8 leftever bytes). Including the header,
 * this amounts to 16 bytes; 8 bytes for the header, and 8 bytes for the remaining frame
 * data.
 *
 */
static size_t
imdocker_container_logs_curlCB(void *data, size_t size, size_t nmemb, void *buffer) {
	DEFiRet;

	const uint8_t frame_size = 8;
	const char imdocker_eol_char = '\n';
	int8_t stream_type = dst_invalid;

	docker_cont_logs_inst_t* pInst = (docker_cont_logs_inst_t*) buffer;
	docker_cont_logs_req_t* req = pInst->logsReq;

	size_t realsize = size*nmemb;
	const uchar* pdata = data;
	size_t write_size = 0;

#ifdef ENABLE_DEBUG_BYTE_BUFFER
	debug_byte_buffer((const uchar*) data, realsize);
#endif

	if (req->data_bufs[dst_stdout]->bytes_remaining || req->data_bufs[dst_stderr]->bytes_remaining) {
		/* on continuation, stream types should matches with previous */
		if (req->data_bufs[dst_stdout]->bytes_remaining) {
			if (req->data_bufs[dst_stderr]->bytes_remaining != 0) {
				ABORT_FINALIZE(RS_RET_ERR);
			}
		} else if (req->data_bufs[dst_stderr]->bytes_remaining) {
			if (req->data_bufs[dst_stdout]->bytes_remaining != 0) {
				ABORT_FINALIZE(RS_RET_ERR);
			}
		}

		stream_type = req->data_bufs[dst_stdout]->bytes_remaining ? dst_stdout : dst_stderr;
		docker_cont_logs_buf_t *pDataBuf = req->data_bufs[stream_type];

		/* read off the remaining bytes */
		DBGPRINTF("Chunk continuation, remaining bytes: type: %d, "
				"bytes remaining: %lu, realsize: %lu, data pos: %lu\n",
				stream_type, pDataBuf->bytes_remaining, realsize, pDataBuf->buf->len);

		write_size = MIN(pDataBuf->bytes_remaining, realsize);
		CHKiRet(dockerContLogsBufWrite(pDataBuf, pdata, write_size));

		/* submit it */
		if (pDataBuf->bytes_remaining == 0) {
			imdocker_buf_t *mem = pDataBuf->buf;
			if (mem->data[mem->len-1] == imdocker_eol_char) {
				const char* szContainerId = NULL;
				CURLcode ccode;
				if(CURLE_OK != (ccode = curl_easy_getinfo(req->curl, CURLINFO_PRIVATE, &szContainerId))) {
					LogError(0, RS_RET_ERR, "imdocker: could not get private data req[%p] - %d:%s\n",
							req->curl, ccode, curl_easy_strerror(ccode));
					ABORT_FINALIZE(RS_RET_ERR);
				}
				req->submitMsg(pInst, pDataBuf, (const uchar*)"[imdocker]");
			}
		}

		pdata += write_size;
	}

	/* not enough room left */
	if ((size_t)(pdata - (const uchar*)data) >= realsize) {
		return (pdata - (const uchar*)data);
	}

	size_t payload_size = 0;
	const uchar* pread = pdata + frame_size;
	docker_cont_logs_buf_t* pDataBuf = NULL;

	if (get_stream_info(pdata, realsize, &stream_type, &payload_size)
				&& is_valid_stream_type(stream_type)) {
		pDataBuf = req->data_bufs[stream_type];
		pDataBuf->stream_type = stream_type;
		pDataBuf->bytes_remaining = payload_size;
		write_size = MIN(payload_size, realsize - frame_size);
	} else {
		/* copy all the data and submit to prevent data loss */
		stream_type = req->data_bufs[dst_stderr]->bytes_remaining ? dst_stderr : dst_stdout;

		pDataBuf = req->data_bufs[stream_type];
		pDataBuf->stream_type = stream_type;

		/* just write everything out */
		pDataBuf->bytes_remaining = 0;
		write_size = realsize;
		pread = pdata;
	}

	/* allocate the expected payload size */
	if (pDataBuf) {
		CHKiRet(dockerContLogsBufWrite(pDataBuf, pread, write_size));
		if (pDataBuf->bytes_remaining == 0) {
			DBGPRINTF("%s() - write size is same as payload_size\n", __FUNCTION__);
			/* NOTE: We do see if a log line gets extended beyond 16K
			 * if (mem->data[mem->len-1] == imdocker_eol_char)
			 */
			req->submitMsg(pInst, pDataBuf, (const uchar*)"[imdocker]");
		}
	}

finalize_it:
	if (iRet != RS_RET_OK) {
		return 0;
	}
	return realsize;
}

#ifdef ENABLE_IMDOCKER_UNIT_TESTS
/*
 * Following checks the imdocker_container_logs_curlCB(), which is the callback from
 * curl to stream the container log data.
 */
static unit_test_data_t* s_current_test=NULL;
static sbool s_unit_test_submit_successful=0;

static void
unit_test_init(unit_test_data_t *data) {
	s_current_test = data;
	s_unit_test_submit_successful=0;
}

static rsRetVal
UnitTestSubmitMsg(docker_cont_logs_inst_t *pInst, docker_cont_logs_buf_t *pBufData, const uchar* pszTag) {
	ASSERT(pszTag);

	if (s_current_test->reference_text_len != pBufData->buf->len) {
		DBGPRINTF("[imdocker unit test] TEST FAILURE, reference_text length does not match!\n");
		ASSERT(0);
	}
	if (strcmp(s_current_test->reference_text, (char*)pBufData->buf->data) != 0) {
		DBGPRINTF("[imdocker unit test] TEST FAILURE, reference_text does not match!\n");
		ASSERT(0);
	}
	s_unit_test_submit_successful=1;

	return RS_RET_OK;
}

static sbool
UnitTestInput_imdocker_container_logs_curlCB(unit_test_data_t *data, docker_cont_logs_inst_t *pInst) {

	for (size_t i = 0; i < data->frame_count; i++) {
		size_t bytes = imdocker_container_logs_curlCB((void*)&data->test_frames[i].frame,
				data->test_frames[i].size, 1, pInst);
		if (bytes != data->test_frames[i].size) {
			DBGPRINTF("[imdocker unit test] TEST FAILURE - mismatch bytes consumed: %lu, expected: %lu.\n", bytes, data->test_frames[i].size);
			return 0;
		}
	}
	return s_unit_test_submit_successful;
}

static void
UnitTest_imdocker_container_logs_curlCB(unit_test_data_t *test_data) {
	docker_cont_logs_inst_t *pInst=NULL;
	dockerContLogsInstNew(&pInst, "dummy_instance", UnitTestSubmitMsg);
	dbgprintf("[imdocker unit test] '%s'...\n", test_data->name);
	unit_test_init(test_data);
	ASSERT(UnitTestInput_imdocker_container_logs_curlCB(test_data, pInst));
	dbgprintf("[imdocker unit test] '%s' Passed.\n", test_data->name);
	dockerContLogsInstDestruct(pInst);
}

static void
UnitTests_imdocker_run() {
	DBGPRINTF("[imdocker unit test] Running unit tests...\n");
	/* run all unit tests */
	UnitTest_imdocker_container_logs_curlCB(&unit_test_simple);
	UnitTest_imdocker_container_logs_curlCB(&unit_test_large);
	DBGPRINTF("[imdocker unit test] all unit tests pass.\n");
}
#endif

CURLcode docker_get(imdocker_req_t *req, const char* url) {
	CURLcode ccode;

	if (!runModConf->dockerApiAddr) {
		if ((ccode = curl_easy_setopt(req->curl, CURLOPT_UNIX_SOCKET_PATH, runModConf->dockerApiUnixSockAddr))
				!= CURLE_OK) {
			STATSCOUNTER_INC(ctrCurlError, mutCtrCurlError);
			LogError(0, RS_RET_ERR, "imdocker: curl_easy_setopt(CURLOPT_UNIX_SOCKET_PATH) error - %d:%s\n",
					ccode, curl_easy_strerror(ccode));
			return ccode;
		}
	}
	if ((ccode = curl_easy_setopt(req->curl, CURLOPT_WRITEFUNCTION, imdocker_container_list_curlCB)) != CURLE_OK) {
		STATSCOUNTER_INC(ctrCurlError, mutCtrCurlError);
		LogError(0, RS_RET_ERR, "imdocker: curl_easy_setopt(CURLOPT_WRITEFUNCTION) error - %d:%s\n",
				ccode, curl_easy_strerror(ccode));
		return ccode;
	}
	if ((ccode = curl_easy_setopt(req->curl, CURLOPT_WRITEDATA, req->buf)) != CURLE_OK) {
		STATSCOUNTER_INC(ctrCurlError, mutCtrCurlError);
		LogError(0, RS_RET_ERR, "imdocker: curl_easy_setopt(CURLOPT_WRITEDATA) error - %d:%s\n",
				ccode, curl_easy_strerror(ccode));
		return ccode;
	}

	if ((ccode = curl_easy_setopt(req->curl, CURLOPT_URL, url)) != CURLE_OK) {
		STATSCOUNTER_INC(ctrCurlError, mutCtrCurlError);
		LogError(0, RS_RET_ERR, "imdocker: curl_easy_setopt(CURLOPT_URL) error - %d:%s\n",
				ccode, curl_easy_strerror(ccode));
		return ccode;
	}
	CURLcode response = curl_easy_perform(req->curl);

	return response;
}

char* dupDockerContainerName(const char* pname) {
	int skipchars = 0;
	int len = strlen(pname);

	if (len >= 2) {
		if (pname[0] == '"') {
			skipchars++;
		}
		if (pname[1] == '\\') {
			skipchars++;
		}
		if (pname[2] == '/') {
			skipchars++;
		}
	}

	return strdup(pname+skipchars);
}

static rsRetVal
process_json(const char* json, docker_cont_log_instances_t *pDockerContainerInstances) {
	DEFiRet;
	struct fjson_object *json_obj = NULL;
	DBGPRINTF("%s() - parsing json=%s\n", __FUNCTION__, json);

	if (!pDockerContainerInstances) {
		ABORT_FINALIZE(RS_RET_OK);
	}

	json_obj = fjson_tokener_parse(json);
	if (!json_obj) {
		ABORT_FINALIZE(RS_RET_OK);
	}

	int length = fjson_object_array_length(json_obj);

	for (int i = 0; i < length; i++) {
		fjson_object* p_json_elm = json_object_array_get_idx(json_obj, i);

		DBGPRINTF("element: %d...\n", i);
		if (p_json_elm) {
			const char *containerId=NULL;
			docker_container_info_t *pDockerContainerInfo=NULL;
			dockerContainerInfoNew(&pDockerContainerInfo);
			CHKmalloc(pDockerContainerInfo);

			struct fjson_object_iterator it = fjson_object_iter_begin(p_json_elm);
			struct fjson_object_iterator itEnd = fjson_object_iter_end(p_json_elm);
			while (!fjson_object_iter_equal(&it, &itEnd)) {
				if (Debug) {
					DBGPRINTF("\t%s: '%s'\n",
							fjson_object_iter_peek_name(&it),
							fjson_object_get_string(fjson_object_iter_peek_value(&it)));
				}

				if (strcmp(fjson_object_iter_peek_name(&it), DOCKER_CONTAINER_ID_PARSE_NAME) == 0) {
					containerId =
						fjson_object_get_string(fjson_object_iter_peek_value(&it));
				} else if (strcmp(fjson_object_iter_peek_name(&it), DOCKER_CONTAINER_NAMES_PARSE_NAME) == 0) {
					int names_array_length =
						fjson_object_array_length(fjson_object_iter_peek_value(&it));
					if (names_array_length) {
						fjson_object* names_elm = json_object_array_get_idx(fjson_object_iter_peek_value(&it), 0);
						const char* pname = fjson_object_get_string(names_elm);
						/* removes un-needed characters */
						pDockerContainerInfo->name = (uchar*)dupDockerContainerName(pname);
						DBGPRINTF("modified Name0: '%s'\n", pDockerContainerInfo->name);
					}
				} else if (strcmp(fjson_object_iter_peek_name(&it), DOCKER_CONTAINER_IMAGEID_PARSE_NAME) == 0) {
					pDockerContainerInfo->image_id = (uchar*)
						strdup(fjson_object_get_string(fjson_object_iter_peek_value(&it)));

				} else if (strcmp(fjson_object_iter_peek_name(&it), DOCKER_CONTAINER_LABELS_PARSE_NAME) == 0) {
					pDockerContainerInfo->json_str_labels = (uchar*)
						strdup(fjson_object_get_string(fjson_object_iter_peek_value(&it)));

					DBGPRINTF("labels: %s\n", pDockerContainerInfo->json_str_labels);
				}

				fjson_object_iter_next(&it);
			}

			if (containerId) {
				/* append */
				docker_cont_logs_inst_t *pInst = NULL;
				if (RS_RET_NOT_FOUND == dockerContLogReqsGet(pDockerContainerInstances, &pInst, containerId)) {
					if (dockerContLogsInstNew(&pInst, containerId, SubmitMsg) != RS_RET_OK) {
						FINALIZE;
					}
					pInst->container_info = pDockerContainerInfo;
					CHKiRet(dockerContLogsInstSetUrlById(pInst, pDockerContainerInstances->curlm, containerId));
					CHKiRet(dockerContLogReqsAdd(pDockerContainerInstances, pInst));
				}
			}
		}
	}

finalize_it:
	if (json_obj) {
		json_object_put(json_obj);
	}
	RETiRet;
}

static rsRetVal
getContainerIds(docker_cont_log_instances_t *pDockerContainerInstances, const char* url) {
	DEFiRet;
	imdocker_req_t *req=NULL;

	CHKiRet(imdockerReqNew(&req));

	CURLcode response = docker_get(req, url);
	if (response != CURLE_OK) {
		DBGPRINTF("%s() - curl response: %d\n", __FUNCTION__, response);
		ABORT_FINALIZE(RS_RET_ERR);
	}

	CHKiRet(process_json((const char*)req->buf->data, pDockerContainerInstances));

finalize_it:
	if (req) {
		imdockerReqDestruct(req);
	}
	RETiRet;
}

static rsRetVal
getContainerIdsAndAppend(docker_cont_log_instances_t *pDockerContainerInstances) {
	DEFiRet;

	char url[256];
	const uchar* pApiAddr = (uchar*)"http:";

	if (runModConf->dockerApiAddr) {
		pApiAddr = runModConf->dockerApiAddr;
	}

	snprintf(url, sizeof(url), "%s/%s/containers/json?%s",
			pApiAddr, runModConf->apiVersionStr, runModConf->listContainersOptions);

	CHKiRet(getContainerIds(pDockerContainerInstances, (const char*)url));
	if (Debug) { dockerContLogReqsPrint(pDockerContainerInstances); }

finalize_it:
	RETiRet;
}

static void
cleanupCompletedContainerRequests(docker_cont_log_instances_t *pDockerContainerInstances) {
	// clean up
	int rc=0, msgs_left=0;
	CURLMsg *msg=NULL;
	CURL *pCurl;

	while ((msg = curl_multi_info_read(pDockerContainerInstances->curlm, &msgs_left))) {
		if (msg->msg == CURLMSG_DONE) {
			pCurl = msg->easy_handle;
			rc = msg->data.result;
			if (rc != CURLE_OK) {
				STATSCOUNTER_INC(ctrCurlError, mutCtrCurlError);
				LogError(0, RS_RET_ERR, "imdocker: %s() - curl error code: %d:%s\n",
						__FUNCTION__, rc, curl_multi_strerror(rc));
				continue;
			}

			CURLcode ccode;
			if (Debug) {
				long http_status=0;
				curl_easy_getinfo(pCurl, CURLINFO_RESPONSE_CODE, &http_status);
				dbgprintf("http status: %lu\n", http_status);
			}
			curl_multi_remove_handle(pDockerContainerInstances->curlm, pCurl);

			const char* szContainerId = NULL;
			if ((ccode = curl_easy_getinfo(pCurl, CURLINFO_PRIVATE, &szContainerId)) == CURLE_OK) {
				dbgprintf("container disconnected: %s\n", szContainerId);
				dockerContLogReqsRemove(pDockerContainerInstances, szContainerId);
				dbgprintf("container removed...\n");
			} else {
				LogError(0, RS_RET_ERR, "imdocker: private data not found "
						"curl_easy_setopt(CURLINFO_PRIVATE) error - %d:%s\n",
						ccode, curl_easy_strerror(ccode));
				STATSCOUNTER_INC(ctrCurlError, mutCtrCurlError);
			}
		}
	}
}

static rsRetVal
processAndPollContainerLogs(docker_cont_log_instances_t *pDockerContainerInstances, int pollIntervalSecs) {
	DEFiRet;
	int count=0;

	CHKiRet(llGetNumElts(&pDockerContainerInstances->ll_container_log_insts, &count));
	dbgprintf("%s() - container instances: %d\n", __FUNCTION__, count);

	int still_running=0;
	time_t tt_sinceGetContainers = time(NULL);
	int pollIntervalMilliSecs= pollIntervalSecs * 1000;

	curl_multi_perform(pDockerContainerInstances->curlm, &still_running);
	do {
		int numfds = 0;

		int res = curl_multi_wait(pDockerContainerInstances->curlm, NULL, 0, pollIntervalMilliSecs, &numfds);
		if (res != CURLM_OK) {
			LogError(0, RS_RET_ERR, "error: curl_multi_wait() numfds=%d, res=%d:%s\n",
					numfds, res, curl_multi_strerror(res));
			return res;
		}

		/* Only get every pollIntervalMSecs */
		time_t tt_now = time(NULL);
		if (tt_now > (tt_sinceGetContainers + (pollIntervalSecs))) {
			getContainerIdsAndAppend(pDockerContainerInstances);
			tt_sinceGetContainers = time(NULL);
		}

		int prev_still_running = still_running;
		curl_multi_perform(pDockerContainerInstances->curlm, &still_running);

		if (prev_still_running > still_running) {
			cleanupCompletedContainerRequests(pDockerContainerInstances);
		}

	} while (still_running);

	cleanupCompletedContainerRequests(pDockerContainerInstances);
finalize_it:
	RETiRet;
}

/* This function is called to gather input. */
BEGINrunInput
	rsRetVal localRet = RS_RET_OK;
	docker_cont_log_instances_t	*pDockerContainerInstances=NULL;
CODESTARTrunInput

	CHKiRet(ratelimitNew(&ratelimiter, "imdocker", NULL));
	curl_global_init(CURL_GLOBAL_ALL);
	localRet = dockerContLogReqsNew(&pDockerContainerInstances);
	if (localRet != RS_RET_OK) {
		return localRet;
	}

	while(glbl.GetGlobalInputTermState() == 0) {
		getContainerIdsAndAppend(pDockerContainerInstances);
		CHKiRet(processAndPollContainerLogs(pDockerContainerInstances, runModConf->iPollInterval));
		if (glbl.GetGlobalInputTermState() == 0) {
			/* exited from processAndPollContainerLogs, sleep before retrying */
			srSleep(runModConf->iPollInterval, 10);
		}
	}

finalize_it:
	if (pDockerContainerInstances) {
		dockerContLogReqsDestruct(pDockerContainerInstances);
	}
	if (ratelimiter) {
		ratelimitDestruct(ratelimiter);
	}
ENDrunInput

BEGINwillRun
CODESTARTwillRun
ENDwillRun

BEGINafterRun
CODESTARTafterRun
ENDafterRun

BEGINmodExit
CODESTARTmodExit
	if(pInputName != NULL)
		prop.Destruct(&pInputName);

	if(pLocalHostIP != NULL)
		prop.Destruct(&pLocalHostIP);

	objRelease(parser, CORE_COMPONENT);
	objRelease(glbl, CORE_COMPONENT);
	objRelease(prop, CORE_COMPONENT);
	objRelease(statsobj, CORE_COMPONENT);
	objRelease(datetime, CORE_COMPONENT);
	objRelease(ruleset, CORE_COMPONENT);
ENDmodExit

BEGINisCompatibleWithFeature
CODESTARTisCompatibleWithFeature
	if(eFeat == sFEATURENonCancelInputTermination)
		iRet = RS_RET_OK;
ENDisCompatibleWithFeature

BEGINqueryEtryPt
CODESTARTqueryEtryPt
CODEqueryEtryPt_STD_IMOD_QUERIES
CODEqueryEtryPt_STD_CONF2_QUERIES
CODEqueryEtryPt_STD_CONF2_setModCnf_QUERIES
CODEqueryEtryPt_IsCompatibleWithFeature_IF_OMOD_QUERIES
ENDqueryEtryPt

BEGINmodInit()
CODESTARTmodInit
	*ipIFVersProvided = CURR_MOD_IF_VERSION; /* we only support the current interface specification */
CODEmodInit_QueryRegCFSLineHdlr

	CHKiRet(objUse(glbl, CORE_COMPONENT));
	CHKiRet(objUse(prop, CORE_COMPONENT));
	CHKiRet(objUse(statsobj, CORE_COMPONENT));
	CHKiRet(objUse(datetime, CORE_COMPONENT));
	CHKiRet(objUse(parser, CORE_COMPONENT));
	CHKiRet(objUse(ruleset, CORE_COMPONENT));

	DBGPRINTF("imdocker version %s initializing\n", VERSION);

	/* we need to create the inputName property (only once during our lifetime) */
	CHKiRet(prop.Construct(&pInputName));
	CHKiRet(prop.SetString(pInputName, UCHAR_CONSTANT("imdocker"), sizeof("imdocker") - 1));
	CHKiRet(prop.ConstructFinalize(pInputName));

ENDmodInit
