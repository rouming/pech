#include "module.h"
#include "bug.h"

LIST_HEAD(modules_list);

void init_modules(void)
{
	struct module *module;
	int ret;

	list_for_each_entry(module, &modules_list, entry) {
		ret = module->init();
		BUG_ON(ret);
	}
}
