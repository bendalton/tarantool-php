#ifndef   PHP_TARANTOOL_NET_H
#define   PHP_TARANTOOL_NET_H

#include "php_tarantool.h"

#include <php.h>
#include <php_network.h>
#include <zend_API.h>
#include <ext/standard/php_smart_str.h>

int tntnet_check_uri(tarantool_object *);
int tntnet_check_unix(tarantool_object *);
int tntnet_stream_open(tarantool_object * TSRMLS_DC);
int tntnet_stream_close(tarantool_object * TSRMLS_DC);
int tntnet_stream_send(tarantool_object * TSRMLS_DC);
size_t tntnet_stream_read(tarantool_object *, char *, size_t TSRMLS_DC);

#endif /* PHP_TARANTOOL_NET_H */
