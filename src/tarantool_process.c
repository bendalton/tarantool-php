#include "tarantool_process.h"

int64_t tarantool_response(struct TNTResponse *r, char *buf, size_t size)
{
	memset(r, 0, sizeof(*r));
	const char *p = buf;
	const char *end = buf + size;
	/* header */
	const char *check_pos = p;
	if (mp_check(&check_pos, end))
		return -1;
	if (mp_typeof(*p) != MP_MAP)
		return -1;
	uint32_t n = mp_decode_map(&p);
	while (n-- > 0) {
		if (mp_typeof(*p) != MP_UINT)
			return -1;
		uint32_t key = mp_decode_uint(&p);
		if (mp_typeof(*p) != MP_UINT)
			return -1;
		switch (key) {
		case TNT_SYNC:
			r->sync = mp_decode_uint(&p);
			break;
		case TNT_CODE:
			r->code = mp_decode_uint(&p);
			break;
		default:
			return -1;
		}
		r->bitmap |= (1ULL << key);
	}
	/* body */
	check_pos = p;
	if (mp_check(&check_pos, end))
		return -1;
	if (mp_typeof(*p) != MP_MAP)
		return -1;
	n = mp_decode_map(&p);
	while (n-- > 0) {
		if (mp_typeof(*p) != MP_UINT)
			return -1;
		uint32_t key = mp_decode_uint(&p);
		switch (key) {
		case TNT_ERROR:
			if (mp_typeof(*p) != MP_STR)
				return -1;
			uint32_t elen = 0;
			r->error = mp_decode_str(&p, &elen);
			r->error_len = elen;
	    		break;
		case TNT_DATA:
	    		r->data = p;
			mp_next(&p);
			r->data_len = p - r->data;
			break;
		}
		r->bitmap |= (1ULL << key);
	}
	return p - buf;
}
