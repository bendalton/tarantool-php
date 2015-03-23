#ifndef   _TARANTOOL_PROCESS_H_
#define   _TARANTOOL_PROCESS_H_

#include "third_party/msgpuck.h"

#include "tarantool_proto.h"
#include "tarantool_msgpack.h"

struct TNTResponse {
	uint64_t bitmap;
	const char *buf;
	uint32_t code;
	uint32_t sync;
	const char *error;
	size_t error_len;
	const char *data;
	size_t data_len;
};

int64_t tarantool_response(struct TNTResponse *, char *, size_t);

#endif /* _TARANTOOL_PROCESS_H_ */
