#include "tarantool_network.h"

#include <math.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/tcp.h>

inline int tntnet_generate_tcp(char* host, int port, char **dest_addr) {
	return spprintf(dest_addr, 0, "tcp://%s:%d", host, port);
}

inline int tntnet_check_uri(tarantool_object *obj) {
	return (strncmp(obj->uri, "unix://", 7) == 0        ||
			strncmp(obj->uri, "tcp://", 6) == 0 ||
			strstr(obj->uri, "://") == NULL);
}

inline int tntnet_check_unix(tarantool_object *obj) {
	if (strlen(obj->uri) < 7)
		return -1;
	return strncmp(obj->uri, "unix://", 7);
}

int tntnet_stream_open(tarantool_object *obj TSRMLS_DC) {
	int options = ENFORCE_SAFE_MODE | REPORT_ERRORS;
	int flags = STREAM_XPORT_CLIENT | STREAM_XPORT_CONNECT;
	int timeout = floor(INI_FLT("tarantool.timeout"));
	struct timeval tv_timeout = {
		.tv_sec = timeout,
		.tv_usec = (INI_FLT("tarantool.timeout") - timeout) * pow(10, 6),
	};
	int timeout_sleep = floor(INI_FLT("tarantool.retry_sleep"));
	struct timespec ts_timeout_sleep = {
		.tv_sec = timeout_sleep,
		.tv_nsec = (INI_FLT("tarantool.retry_sleep") - timeout_sleep) * pow(10, 9)
	};
	int count = INI_INT("tarantool.retry_count");
	if (count <= 0) count = 10;
	char *errstr = NULL;
	int errcode = 0;
	php_stream *stream = NULL;
retry:
	while (count) {
		stream = php_stream_xport_create(
				obj->uri, strlen(obj->uri), options, flags,
				NULL, &tv_timeout, NULL, &errstr, &errcode);
		if (errcode || !stream) {
			php_error(E_NOTICE, "Failed to connect. Code %d: %s", errcode, errstr);
			php_error(E_NOTICE, "Connection failed. %d attempts left", count);
			if (!count) THROW_EXC("Failed to connect. Code %d: %s", errcode, errstr);
			goto error;
		}
		int socketd = ((php_netstream_data_t* )stream->abstract)->socket;
		flags = 1;
		if (!tntnet_check_unix(obj) &&
				setsockopt(socketd, IPPROTO_TCP, TCP_NODELAY, (char *) &flags, sizeof(int))) {
			char errbuf[128];
			strerror_r(errno, errbuf, sizeof(errbuf));
			php_error(E_NOTICE, "Failed to connect. Code %d: %s", errno, errbuf);
			if (!count)
				THROW_EXC("Failed to connect. Setsockopt error %s", errbuf);
			goto error;
		}
		obj->stream = stream;
		return SUCCESS;
	}

error:
	if (errstr) efree(errstr);
	if (stream) php_stream_close(stream);
	if (count) {
		nanosleep(&ts_timeout_sleep, NULL);
		goto retry;
	}
	return FAILURE;
}

int tntnet_stream_close(tarantool_object *obj TSRMLS_DC) {
	if (obj->stream) php_stream_close(obj->stream);
	obj->stream = NULL;
}

int tntnet_stream_send(tarantool_object *obj TSRMLS_DC) {
	int i = 0;

	if (php_stream_write(obj->stream,
			SSTR_BEG(obj->value),
			SSTR_LEN(obj->value)) != SSTR_LEN(obj->value)) {
		return FAILURE;
	}
	if (php_stream_flush(obj->stream)) {
		return FAILURE;
	}
	SSTR_LEN(obj->value) = 0;
	smart_str_nullify(obj->value);
	return SUCCESS;
}

/*
 * Legacy rtsisyk code:
 * php_stream_read made right
 * See https://bugs.launchpad.net/tarantool/+bug/1182474
 */
size_t tntnet_stream_read(tarantool_object *obj,
				    char *buf, size_t size TSRMLS_DC) {
	size_t total_size = 0;
	size_t read_size = 0;
	int i = 0;

	while (total_size < size) {
		size_t read_size = php_stream_read(obj->stream,
				buf + total_size,
				size - total_size);
		assert(read_size + total_size <= size);
		if (read_size == 0)
			break;
		total_size += read_size;
	}
	return total_size;
}

