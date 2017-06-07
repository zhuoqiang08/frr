
#include "fib_api.h"

static fib_result_t hardfail_update(struct fib_api *fapi,
		struct prefix *p, struct prefix *src_p,
		struct route_entry *old, struct route_entry *new);

struct hardfail_api {
	struct fib_api fapi;
	struct list *stacked_modules;
}

static struct fib_api hardfail_instantiate(struct fib_api_provider *self,
			const char *config_id)
{
	struct hardfail_api *api = malloc(sizeof(*api));
	api->fapi.route_update = hardfail_update;
	api->stacked_modules = list_new();

	return &api->fapi;
}

static fib_result_t hardfail_update(struct fib_api *fapi,
		struct prefix *p, struct prefix *src_p,
		struct route_entry *old, struct route_entry *new)
{
	struct hardfail_api *api = (struct hardfail_api *)fapi;
	struct fib_api *next, *undo;
	struct listnode *ln;
	fib_result_t state;

	for (ALL_LIST_ELEMENTS_RO(api->stacked_modules, ln, next)) {
		state = next->route_update(next, p, src_p, old, new);
		if (state != FIB_OK)
			goto fail;
	}
	return FIB_OK;

fail:
	/* undo list in reverse order */
	while (ln = ln->prev) {
		undo = ln->data;

		/* if we fail in rollback, we're screwed.
		 * also, we have a choice here between rollback or straight
		 * up deleting the route */
		undo->route_update(undo, p, src_p, new, old);
	}
	return FIB_ERROR;
}

DEFUN(hardfail_config,
      hardfail_config_cmd,
      "fib-api multiplex-hardfail MYNAME stack NEXTTYPE NEXTNAME",
      "yadda help string")
{
	struct hardfail_api *api = zebra_fap_get("multiplex_hardfail",
			argv[2]->text);
	struct fib_api *stack;

	stack = zebra_fap_get(argv[4]->text, argv[5]->text);
	if (!stack) {
		vty_out(vty, "FAIL!\n");
		return CMD_WARNING;
	}

	list_add(api->stacked_modules, stack);
	return CMD_SUCCESS;
}

static struct fib_api_provider hardfail_provider = {
	.name = "multiplex_hardfail",
	.instantiate = hardfail_create,
};

static int zebra_fap_hardfail_init (void)
{
	zebra_fap_register(&hardfail_provider);
	return 0;
}


FRR_MODULE_SETUP(
	.name = "fib_multiplex_hardfail",
	.version = FRR_VERSION,
	.description = "multiple FIB handlers with one-fail-all-fail behaviour",
	.init = zebra_fap_hardfail_init,
)
