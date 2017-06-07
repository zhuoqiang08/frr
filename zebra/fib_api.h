

enum fib_result {
	FIB_OK = 0,
	FIB_ERROR = 1,
};
typedef enum fib_result fib_result_t;

/* an instantiated FIB interface, for example Linux netlink or one FPM
 * connection (of possibly multiple) */
struct fib_api {
	/* the idea with config_id is to have it be a configuration handle,
	 * with a zebra.conf like this:
	 *
	 *   ! entry point that zebra is using
	 *   fib-api root multiplex-hardfail NAME1
	 *
	 *   fib-api multiplex-hardfail NAME1 stack linux-netlink NAME2
	 *   fib-api multiplex-hardfail NAME1 stack rewrite-nexthops NAME3
	 *   fib-api multiplex-hardfail NAME1 stack fpm NAME4
	 *
	 *   fib-api linux-netlink NAME2 somestupidoption
	 *
	 *   fib-api rewrite-nexthops NAME3 stack fpm NAME5
	 *   fib-api rewrite-nexthops NAME3 change-all-nexthops-to 192.168.1.1
	 *
	 *   fib-api fpm NAME4 connect 127.0.0.1 1234
	 *
	 *   fib-api fpm NAME5 connect 127.0.0.1 1235
	 */
	const char *config_id;

	/* rt.h equivalents */
	fib_result_t (*route_update)(struct fib_api *fapi,
			struct prefix *p, struct prefix *src_p,
			struct route_entry *old, struct route_entry *new);

	/* could probably combine these into update(old,new) too */
	fib_result_t (*kernel_add_lsp)(struct fib_api *fapi, zebra_lsp_t *);
	fib_result_t (*kernel_upd_lsp)(struct fib_api *fapi, zebra_lsp_t *);
	fib_result_t (*kernel_del_lsp)(struct fib_api *fapi, zebra_lsp_t *);

	/* TBD: address/neigh code? needed? not needed? */
};

struct fib_api_provider {
	const char *type_name;
	struct fib_api (*instantiate)(struct fib_api_provider *self,
			const char *config_id);
};

/* register so we can look up by type_name in zebra_fap_get */
extern void zebra_fap_register(struct fib_api_provider *prov);

/* find instance of type_name, named "config_id";  if not found, just
 * create it */
extern struct fib_api *zebra_fap_get(const char *type_name,
		const char *config_id);

