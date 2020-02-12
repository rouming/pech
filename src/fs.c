// SPDX-License-Identifier: GPL-2.0

#include "fs.h"

int __fs_parse(struct p_log *log,
	       const struct fs_parameter_spec *desc,
	       struct fs_parameter *value,
	       struct fs_parse_result *result)
{
	return -ENOTSUP;
}

int fs_param_is_bool(struct p_log *l,
		     const struct fs_parameter_spec *s,
		     struct fs_parameter *p,
		     struct fs_parse_result *r)
{
	return -ENOTSUP;
}

int fs_param_is_u32(struct p_log *l,
		     const struct fs_parameter_spec *s,
		     struct fs_parameter *p,
		     struct fs_parse_result *r)
{
	return -ENOTSUP;
}

int fs_param_is_s32(struct p_log *l,
		     const struct fs_parameter_spec *s,
		     struct fs_parameter *p,
		     struct fs_parse_result *r)
{
	return -ENOTSUP;
}

int fs_param_is_u64(struct p_log *l,
		     const struct fs_parameter_spec *s,
		     struct fs_parameter *p,
		     struct fs_parse_result *r)
{
	return -ENOTSUP;
}

int fs_param_is_enum(struct p_log *l,
		     const struct fs_parameter_spec *s,
		     struct fs_parameter *p,
		     struct fs_parse_result *r)
{
	return -ENOTSUP;
}

int fs_param_is_string(struct p_log *l,
		     const struct fs_parameter_spec *s,
		     struct fs_parameter *p,
		     struct fs_parse_result *r)
{
	return -ENOTSUP;
}

int fs_param_is_blob(struct p_log *l,
		     const struct fs_parameter_spec *s,
		     struct fs_parameter *p,
		     struct fs_parse_result *r)
{
	return -ENOTSUP;
}

int fs_param_is_blockdev(struct p_log *l,
		     const struct fs_parameter_spec *s,
		     struct fs_parameter *p,
		     struct fs_parse_result *r)
{
	return -ENOTSUP;
}

int fs_param_is_path(struct p_log *l,
		     const struct fs_parameter_spec *s,
		     struct fs_parameter *p,
		     struct fs_parse_result *r)
{
	return -ENOTSUP;
}

int fs_param_is_fd(struct p_log *l,
		     const struct fs_parameter_spec *s,
		     struct fs_parameter *p,
		     struct fs_parse_result *r)
{
	return -ENOTSUP;
}
