#include "config.h"

#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <float.h>

#include <cjson/cJSON.h>

#include "cache/cache.h"
#include "vcl.h"
#include "vrt_obj.h"

#include "miniobj.h"
#include "vnum.h"
#include "vtim.h"
#include "vcc_noreturn_if.h"


  struct vcl_sub {
          unsigned                magic;
  #define VCL_SUB_MAGIC           0x12c1750b
          const unsigned          methods;        // ok &= ctx->method
          const char * const      name;
          const struct VCL_conf   *vcl_conf;
          vcl_func_f              *func;
          unsigned                n;
          unsigned                nref;
          unsigned                called;
  };


struct vcl_state {
	unsigned magic;
#define DICT_MAGIC 0x0b8908ca
	size_t max_subs;
	size_t nsubs;
	const struct vcl_sub **subs;

	size_t max_bes;
	size_t nbes;
	VCL_BACKEND *bes;
	pthread_rwlock_t rwlock;

	VCL_SUB builtin_recv;
};

int v_matchproto_(vmod_event_f)
vmod_event_function(VRT_CTX, struct vmod_priv *priv, enum vcl_event_e e)
{
	(void) ctx;
	struct vcl_state *d;
	AN(priv);

	switch (e) {
	case VCL_EVENT_LOAD:
		AZ(priv->priv);
		ALLOC_OBJ(d, DICT_MAGIC);
		pthread_rwlock_init(&d->rwlock, NULL);
		priv->priv = d;
		break;
	case VCL_EVENT_WARM:
		break;
	case VCL_EVENT_COLD:
		break;
	case VCL_EVENT_DISCARD:
		CAST_OBJ_NOTNULL(d, priv->priv, DICT_MAGIC);
		free(d->subs);
		free(d->bes);
		pthread_rwlock_destroy(&d->rwlock);
		break;
	default:
	break;
	}
	return (0);
}

static const struct gethdr_s hdr_location = { HDR_RESP, "\011location:"};

#define HDR_PAIR(name, s) \
		static const struct gethdr_s hdr_req_ ## name = { HDR_REQ, s};

HDR_PAIR(action, "\007action:");

enum action {
	action_synth,
	action_redirect,
	action_pass,
	action_cache,
	action_try_cache,
};

struct what_next {
	unsigned magic;
#define WN_MAGIC 0x08ca0b89
	enum action action;
	VCL_SUB sub_ok;
	VCL_SUB sub_err;
	VCL_STRING synth_msg;
	VCL_STRING redirect_location;
	VCL_DURATION ttl;
	VCL_DURATION keep;
	VCL_DURATION grace;
};

void
save_sub(struct vcl_state *vs, const struct vcl_sub *sub) {
	CHECK_OBJ_NOTNULL(vs, DICT_MAGIC);
	CHECK_OBJ_NOTNULL(sub, VCL_SUB_MAGIC);
	size_t i;
	AZ(pthread_rwlock_rdlock(&vs->rwlock));
	for (i = 0; i < vs->nsubs; i++) {
		if (!strcmp(vs->subs[i]->name, sub->name)) {
			return;
		}
	}
	AZ(pthread_rwlock_unlock(&vs->rwlock));
	assert(i == vs->nsubs);

	AZ(pthread_rwlock_wrlock(&vs->rwlock));
	if (vs->nsubs == vs->max_subs) {
		vs->max_subs += 1024;
		vs->subs = realloc(vs->subs, vs->max_subs * sizeof(struct vcl_sub *));
	} else {
		assert(vs->nsubs < vs->max_subs);
	}
	vs->subs[i] = sub;
	vs->nsubs++;
	AZ(pthread_rwlock_unlock(&vs->rwlock));
}

VCL_SUB
find_sub(struct vcl_state *vs, VCL_STRING name)
{
	VCL_SUB sub = NULL;

	CHECK_OBJ_NOTNULL(vs, DICT_MAGIC);
	AN(name);

	AZ(pthread_rwlock_rdlock(&vs->rwlock));
	size_t i;
	for (i = 0; i < vs->nsubs; i++) {
		AN(vs->subs[i]);
		AN(vs->subs[i]->name);
		if (!strcmp(vs->subs[i]->name, name)) {
			sub = vs->subs[i];
		}
	}
	AZ(pthread_rwlock_unlock(&vs->rwlock));
	return sub;
}

void
save_be(struct vcl_state *vs, VCL_BACKEND be) {
	CHECK_OBJ_NOTNULL(vs, DICT_MAGIC);
	CHECK_OBJ_NOTNULL(be, DIRECTOR_MAGIC);
	size_t i;
	AZ(pthread_rwlock_rdlock(&vs->rwlock));
	for (i = 0; i < vs->nbes; i++) {
		if (!strcmp(vs->bes[i]->vcl_name, be->vcl_name)) {
			AZ(pthread_rwlock_unlock(&vs->rwlock));
			return;
		}
	}
	AZ(pthread_rwlock_unlock(&vs->rwlock));
	assert(i == vs->nbes);

	AZ(pthread_rwlock_wrlock(&vs->rwlock));
	if (vs->nbes == vs->max_bes) {
		vs->max_bes += 1024;
		vs->bes = realloc(vs->bes, vs->max_bes * sizeof(struct vcl_be *));
	} else {
		assert(vs->nbes < vs->max_bes);
	}
	vs->bes[i] = be;
	vs->nbes++;
	AZ(pthread_rwlock_unlock(&vs->rwlock));
}

VCL_BACKEND
find_be(struct vcl_state *vs, VCL_STRING name)
{
	VCL_BACKEND be = NULL;
	CHECK_OBJ_NOTNULL(vs, DICT_MAGIC);
	AN(name);

	AZ(pthread_rwlock_rdlock(&vs->rwlock));
	size_t i;
	for (i = 0; i < vs->nbes; i++) {
		AN(vs->bes[i]);
		AN(vs->bes[i]->vcl_name);
		if (!strcmp(vs->bes[i]->vcl_name, name)) {
			be = vs->bes[i];
			break;
		}
	}
	AZ(pthread_rwlock_unlock(&vs->rwlock));
	return be;
}


VCL_VOID
vmod_synth(VRT_CTX, struct VARGS(synth) *args) {
	const struct vcl_sub *sub = args->sub;


	int status = args->valid_status ? args->status : 200;
	const char *reason = args->valid_reason ? args->reason : NULL;
	VRT_synth(ctx, status, reason);

	struct what_next *wn = WS_Alloc(ctx->ws, sizeof(struct what_next));
	INIT_OBJ(wn, WN_MAGIC);
	wn->action = action_synth;
	if (args->valid_message && args->message) {
		wn->synth_msg = args->message;
	}
	if (args->valid_sub) {
		wn->sub_ok = sub;
	}
	args->priv->priv = wn;

	VRT_handling(ctx, VCL_RET_SYNTH);
}

VCL_VOID
vmod_redirect(VRT_CTX, struct VARGS(redirect) *args) {
	int status = args->valid_status ? args->status : 301;
	VRT_synth(ctx, status, NULL);

	struct what_next *wn = WS_Alloc(ctx->ws, sizeof(struct what_next));
	INIT_OBJ(wn, WN_MAGIC);
	wn->action = action_redirect;
	wn->redirect_location = args->location;
	args->priv->priv = wn;

	VRT_handling(ctx, VCL_RET_SYNTH);
}

VCL_VOID
vmod_pass(VRT_CTX, struct VARGS(pass) *args) {

	struct vcl_state *d;

	AN(args);
	AN(args->priv);
	CAST_OBJ_NOTNULL(d, args->priv->priv, DICT_MAGIC);
	cJSON *state = cJSON_CreateObject();
	AN(state);
	cJSON_AddStringToObject(state, "action", "pass");
	cJSON_AddStringToObject(state, "backend", args->backend->vcl_name);
	save_be(d, args->backend);
	if (args->valid_success_sub) {
		save_sub(d, args->success_sub);
		cJSON_AddStringToObject(state, "success_sub", args->success_sub->name);
	}
	if (args->valid_error_sub) {
		save_sub(d, args->error_sub);
		cJSON_AddStringToObject(state, "error_sub", args->error_sub->name);
	}
	char buf[1024];
	AN(cJSON_PrintPreallocated(state, buf, sizeof(buf), 0));
	VRT_SetHdr(ctx, &hdr_req_action, 0, TOSTRAND(buf));
	VRT_handling(ctx, VCL_RET_PASS);
}

VCL_VOID
vmod_cache(VRT_CTX, struct VARGS(cache) *args) {
	struct vcl_state *d;

	AN(args);
	AN(args->priv);
	CAST_OBJ_NOTNULL(d, args->priv->priv, DICT_MAGIC);
	save_be(d, args->backend);

	cJSON *state = cJSON_CreateObject();
	AN(state);
	cJSON_AddStringToObject(state, "action", "cache");

	save_be(d, args->backend);
	cJSON_AddStringToObject(state, "backend", args->backend->vcl_name);

	if (args->valid_success_sub) {
		save_sub(d, args->success_sub);
		cJSON_AddStringToObject(state, "success_sub", args->success_sub->name);
	}
	if (args->valid_error_sub) {
		save_sub(d, args->error_sub);
		cJSON_AddStringToObject(state, "error_sub", args->error_sub->name);
	}
	if (args->valid_ttl) {
		cJSON_AddNumberToObject(state, "ttl", args->ttl);
	}
	if (args->valid_grace) {
		cJSON_AddNumberToObject(state, "grace", args->grace);
	}
	if (args->valid_keep) {
		cJSON_AddNumberToObject(state, "keep", args->keep);
	}
	char buf[1024];
	AN(cJSON_PrintPreallocated(state, buf, sizeof(buf), 0));
	VRT_SetHdr(ctx, &hdr_req_action, 0, TOSTRAND(buf));
	if (!args->force_cache && d->builtin_recv) {
		VRT_call(ctx, d->builtin_recv);
	}
	if (!VRT_handled(ctx)) {
		VRT_handling(ctx, VCL_RET_HASH);
	}
}

VCL_VOID
vmod_internal_load_state(VRT_CTX, struct vmod_priv *priv_vcl, struct vmod_priv *priv_task, VCL_STRING json) {
	struct vcl_state *d;
	struct what_next *wn;

	CAST_OBJ_NOTNULL(d, priv_vcl->priv, DICT_MAGIC);
	AN(priv_vcl);
	AN(priv_task);

	wn = (struct what_next *)(priv_task->priv);
	if (!wn) {
		wn = WS_Alloc(ctx->ws, sizeof(struct what_next));
		priv_task->priv = wn;
	}

	memset(wn, 0, sizeof(struct what_next));
	INIT_OBJ(wn, WN_MAGIC);
	wn->ttl = NAN;
	wn->grace = NAN;
	wn->keep = NAN;

	cJSON *state = cJSON_Parse(json);
	if (!state) {
		VRT_fail(ctx, "couldn't parse JSON: %s", json);
		return;
	}

	cJSON *el;
	el = cJSON_GetObjectItem(state, "ttl");
	if (el) {
		if (!cJSON_IsNumber(el)) {
			VRT_fail(ctx, "invalid ttl in %s", json);
			cJSON_free(state);
			return;
		}
		wn->ttl = cJSON_GetNumberValue(el);
	}
	el = cJSON_GetObjectItem(state, "grace");
	if (el) {
		if (!cJSON_IsNumber(el)) {
			VRT_fail(ctx, "invalid grace in %s", json);
			cJSON_free(state);
			return;
		}
		wn->grace = cJSON_GetNumberValue(el);
	}
	el = cJSON_GetObjectItem(state, "keep");
	if (el) {
		if (!cJSON_IsNumber(el)) {
			VRT_fail(ctx, "invalid keep in %s", json);
			cJSON_free(state);
			return;
		}
		wn->keep = cJSON_GetNumberValue(el);
	}

	el = cJSON_GetObjectItem(state, "backend");
	if (!el || !cJSON_IsString(el)) {
		VRT_fail(ctx, "invalid backend in %s", json);
		cJSON_free(state);
		return;
	}
	VCL_BACKEND be = find_be(d, cJSON_GetStringValue(el));
	if (!be) {
		VRT_fail(ctx, "unknown backend %s in %s", cJSON_GetStringValue(el), json);
		cJSON_free(state);
		return;
	}
	VRT_l_bereq_backend(ctx, be);

	el = cJSON_GetObjectItem(state, "action");
	if (!el || !cJSON_IsString(el)) {
		VRT_fail(ctx, "invalid action in %s", json);
		cJSON_free(state);
		return;
	}
	if (!strcmp(cJSON_GetStringValue(el), "cache")) {
		wn->action = action_cache;
	} else if (!strcmp(cJSON_GetStringValue(el), "try_cache")) {
		wn->action = action_try_cache;
	} else if (!strcmp(cJSON_GetStringValue(el), "pass")) {
		wn->action = action_pass;
	} else {
		VRT_fail(ctx, "invalid action in %s", json);
		cJSON_free(state);
		return;
	}

	el = cJSON_GetObjectItem(state, "success_sub");
	if (el) {
		if (!cJSON_IsString(el) || !(wn->sub_ok = find_sub(d, cJSON_GetStringValue(el)))) {
			VRT_fail(ctx, "invalid success_sub in %s", json);
			cJSON_free(state);
			return;
		}
	}
	el = cJSON_GetObjectItem(state, "error_sub");
	if (el) {
		if (!cJSON_IsString(el) || !(wn->sub_err = find_sub(d, cJSON_GetStringValue(el)))) {
			VRT_fail(ctx, "invalid error_sub in %s", json);
			cJSON_free(state);
			return;
		}
	}

	priv_task->priv = wn;
}

VCL_VOID
vmod_internal_proceed(VRT_CTX, struct vmod_priv *priv)
{
	struct what_next *wn;

	AN(priv);
	CAST_OBJ(wn, priv->priv, WN_MAGIC);
	// we are not needed here
	if (!wn) {
		return;
	}

	if (ctx->method == VCL_MET_BACKEND_RESPONSE) {
		AN(wn->action == action_cache ||
		   wn->action == action_try_cache ||
		   wn->action == action_pass);
		if (!isnan(wn->ttl)) {
			VRT_l_beresp_ttl(ctx, wn->ttl);
		}
		if (!isnan(wn->grace)) {
			VRT_l_beresp_grace(ctx, wn->grace);
		}
		if (!isnan(wn->keep)) {
			VRT_l_beresp_keep(ctx, wn->keep);
		}
		if (wn->sub_ok) {
			VRT_call(ctx, wn->sub_ok);
		}
		if (!VRT_handled(ctx)) {
			VRT_handling(ctx, VCL_RET_DELIVER);
		}
	}

	if (ctx->method == VCL_MET_SYNTH) {
		if (wn->action != action_synth && wn->action != action_redirect) {
			return;
		}
		if (wn->synth_msg) {
			VRT_synth_strands(ctx, TOSTRAND(wn->synth_msg));
		}
		if (wn->redirect_location) {
			VRT_SetHdr(ctx, &hdr_location,
					0,
					TOSTRAND(wn->redirect_location)
				  );
		}
		if (wn->sub_ok) {
			VRT_call(ctx, wn->sub_ok);
		}
		if (!VRT_handled(ctx)) {
			VRT_handling(ctx, VCL_RET_DELIVER);
		}
	}
	return;
}

VCL_VOID
vmod_internal_reset(VRT_CTX, struct vmod_priv *priv) {
	AN(priv);
	priv->priv = NULL;
}


VCL_VOID
vmod_internal_set_builtin_recv(VRT_CTX, struct vmod_priv *priv_vcl, VCL_SUB builtin_recv) {
	struct vcl_state *d;
	CAST_OBJ_NOTNULL(d, priv_vcl->priv, DICT_MAGIC);

	d->builtin_recv = builtin_recv;
}
