// SPDX-License-Identifier: GPL-2.0
/*
 * Generic IIO access driver
 *
 * Copyright 2019 Analog Devices Inc.
 */

 /* Possible register operations table:
  * +----------+--------+-----------+--------+-------+
  * |    OP      |  ADDR  |    MASK   |  VAL  | TIME |
  * +------------------------------------------------+
  * |    READ    |    X   |          |        |      |
  * +------------------------------------------------+
  * | READ_MASK  |   X    |     X    |        |      |
  * +------------------------------------------------+
  * | WAIT_MASK  |   X    |     X    |    X   |   X  |
  * +------------------------------------------------+
  * |  WAIT_MS   |        |          |        |   X  |
  * +----------+--------+-----------+--------+-------+
  * |   WRITE    |   X    |          |    X   |      |
  * +----------+--------+-----------+--------+-------+
  * | WRITE_MASK |   X    |     X    |    X   |      |
  * +----------+--------+-----------+--------+-------+
  * Wait times are defined in milliseconds:
  * READ        -> read value at ADDR
  * READ_MASK   -> read value at ADDR with MASK
  * WAIT_MASK   -> wait TIME for ADDR value with MASK to become VAL
  * WAIT_MS     -> wait TIME milliseconds
  * WRTIE       -> write VAL at ADDR
  * WRITE_MASK  -> write VAL at ADDR with MASK
  */

#include <linux/iio/iio.h>
#include <linux/firmware.h>
#include <linux/module.h>
#include <linux/spi/spi.h>
#include <linux/regmap.h>

#include "iio-regmap.h"

#define REG_OP_SIZE		20
#define WAIT_POLL_TIME_US	1000

enum iio_regmap_opcode {
	IIO_REGMAP_READ,
	IIO_REGMAP_READ_MASK,
	IIO_REGMAP_WAIT_MASK,
	IIO_REGMAP_WAIT_MS,
	IIO_REGMAP_WRITE,
	IIO_REGMAP_WRITE_MASK,
};

static char *iio_reg_op_map[] = {
	[IIO_REGMAP_WAIT_MS] = "WAIT_MS",
	[IIO_REGMAP_READ_MASK] = "READ_MASK",
	[IIO_REGMAP_WRITE_MASK] = "WRITE_MASK",
	[IIO_REGMAP_WAIT_MASK] = "WAIT_MASK",
	[IIO_REGMAP_WRITE] = "WRITE",
	[IIO_REGMAP_READ] = "READ",
};

struct iio_regmap_op {
	enum iio_regmap_opcode	op;
	unsigned int		addr;
	unsigned int		mask;
	unsigned int		val;
	unsigned int		time;
	unsigned int		dbg;
};

struct iio_regmap {
	struct device *dev;
	struct regmap *regmap;
};

static const struct iio_info iio_regmap_info = {
};

int iio_regmap_read_config(struct device *dev, struct regmap_config *regmap_cfg)
{
	u32 reg_bits;
	u32 val_bits;
	int ret;

	ret = device_property_read_u32(dev, "reg_bits", &reg_bits);
	if (ret < 0) {
		dev_err(dev, "Reading reg_bits property failed!\n");
		return -EINVAL;
	}

	ret = device_property_read_u32(dev, "val_bits", &val_bits);
	if (ret < 0) {
		dev_err(dev, "Reading val_bits property failed!\n");
		return -EINVAL;
	}

	regmap_cfg->reg_bits = reg_bits;
	regmap_cfg->val_bits = val_bits;

	return 0;
}
EXPORT_SYMBOL_GPL(iio_regmap_read_config);

/* Retrieve from device node the firmware name then
 * read from firmware register operations,
 * allocate a copy of the firmware data
 * and return the start address of register operations within
 * the firmware.
 */
static const char *read_firmware(struct device *dev)
{
	char *reg_ops;
	int ret;
	const char *firmware_name;
	const char *data;
	const struct firmware *firmware;

	ret = device_property_read_string(dev, "firmware", &firmware_name);
	if (ret < 0) {
		dev_err(dev, "Firmware name property read failed!\n");
		return ERR_PTR(-EINVAL);
	}

	ret = request_firmware(&firmware, firmware_name, dev);
	if (ret < 0) {
		dev_err(dev, "request_firmware failed!\n");
		return ERR_PTR(-EINVAL);
	}

	reg_ops = devm_kzalloc(dev, (firmware->size + 1) * sizeof(char),
			       GFP_KERNEL);
	if (!reg_ops)
		return ERR_PTR(-ENOMEM);

	data = firmware->data;
	if (!data) {
		dev_err(dev, "Firmware data not loaded.");
		return ERR_PTR(-EINVAL);
	}
	memcpy(reg_ops, data, (firmware->size) * sizeof(char));
	release_firmware(firmware);

	return reg_ops;
}

static struct iio_regmap_op *alloc_register_ops(struct device *dev,
						const char *fw_reg_ops)
{
	const char *c;
	unsigned int new_lines;
	struct iio_regmap_op *reg_ops;

	if (!fw_reg_ops)
		return NULL;

	new_lines = 0;
	for (c = fw_reg_ops; *c != '\0'; c++)
		if (*c == '\n')
			new_lines++;
	reg_ops = devm_kzalloc(dev, new_lines * sizeof(*reg_ops), GFP_KERNEL);
	if (!reg_ops)
		return NULL;

	return reg_ops;
}

static int parse_read_op(struct device *dev, const char *reg_ops,
			 struct iio_regmap_op *op, int line)
{
	int ret;

	ret = sscanf(reg_ops, "%x,,,,%u", &op->addr, &op->dbg);
	if (ret != 2) {
		dev_err(dev, "Invalid READ op format, line: %d.", line);
		return -EINVAL;
	}
	return 0;
}

static int parse_read_mask_op(struct device *dev, const char *reg_ops,
			      struct iio_regmap_op *op, int line)
{
	int ret;

	ret = sscanf(reg_ops, "%x,%x,,,%u", &op->addr, &op->mask, &op->dbg);
	if (ret != 3) {
		dev_err(dev, "Invalid READ_MASK op format, line: %d.", line);
		return -EINVAL;
	}
	return 0;
}

static int parse_wait_mask_op(struct device *dev, const char *reg_ops,
			      struct iio_regmap_op *op, int line)
{
	int ret;

	ret = sscanf(reg_ops, "%x,%x,%x,%u,%u", &op->addr, &op->mask, &op->val,
		     &op->time, &op->dbg);
	if (ret != 5) {
		dev_err(dev, "Invalid WAIT_MASK op format, line: %d.", line);
		return -EINVAL;
	}
	return 0;
}

static int parse_wait_op(struct device *dev, const char *reg_ops,
			 struct iio_regmap_op *op, int line)
{
	int ret;

	ret = sscanf(reg_ops, ",,,%u,%u", &op->time, &op->dbg);
	if (ret != 2) {
		dev_err(dev, "Invalid WAIT_MS op format, line: %d.", line);
		return -EINVAL;
	}
	return 0;
}

static int parse_write_op(struct device *dev, const char *reg_ops,
			  struct iio_regmap_op *op, int line)
{
	int ret;

	ret = sscanf(reg_ops, "%x,,%x,,%u", &op->addr, &op->val, &op->dbg);
	if (ret != 3) {
		dev_err(dev, "Invalid WRITE op format, line: %d.", line);
		return -EINVAL;
	}
	return 0;
}

static int parse_write_mask_op(struct device *dev, const char *reg_ops,
			       struct iio_regmap_op *op, int line)
{
	int ret;

	ret = sscanf(reg_ops, "%x,%x,%x,,%u", &op->addr, &op->mask, &op->val,
		     &op->dbg);
	if (ret != 4) {
		dev_err(dev, "Invalid WRITE_MASK format, line: %d.", line);
		return -EINVAL;
	}
	return 0;
}

static int read_register_op(struct device *dev, const char *fw_reg_ops,
			    struct iio_regmap_op *reg_op, unsigned int line)
{
	int ret = 0;

	if (!fw_reg_ops || !reg_op)
		return -EINVAL;

	switch (reg_op->op) {
	case IIO_REGMAP_READ:
		ret = parse_read_op(dev, fw_reg_ops, reg_op, line);
		break;
	case IIO_REGMAP_READ_MASK:
		ret = parse_read_mask_op(dev, fw_reg_ops, reg_op, line);
		break;
	case IIO_REGMAP_WAIT_MASK:
		ret = parse_wait_mask_op(dev, fw_reg_ops, reg_op, line);
		break;
	case IIO_REGMAP_WAIT_MS:
		ret = parse_wait_op(dev, fw_reg_ops, reg_op, line);
		break;
	case IIO_REGMAP_WRITE:
		ret = parse_write_op(dev, fw_reg_ops, reg_op, line);
		break;
	case IIO_REGMAP_WRITE_MASK:
		ret = parse_write_mask_op(dev, fw_reg_ops, reg_op, line);
		break;
	default:
		dev_err(dev, "Invalid op at line: %d", line);
		return -EINVAL;
	}

	if (ret < 0)
		return ret;

	return 0;
}

static int regmap_cmd_to_opcode(const char *cmd)
{
	int i;
	int op_code = -1;

	for (i = IIO_REGMAP_READ; i <= IIO_REGMAP_WRITE_MASK; i++) {
		if (!strcmp(cmd, iio_reg_op_map[i])) {
			op_code = i;
			break;
		}
	}
	return op_code;
}

static int parse_register_ops(struct device *dev, const char *fw_reg_ops,
			      struct iio_regmap_op *reg_ops)
{
	char parsed_cmd[REG_OP_SIZE];
	char *reg_op_end;
	unsigned int op_size = 0;
	unsigned int line = 0;
	int op_nr = 0;
	int ret;
	int op_code;

	if (!fw_reg_ops || !reg_ops)
		return -EINVAL;

	while (*fw_reg_ops != '\0') {
		reg_op_end = strchr(fw_reg_ops, ',');
		op_size = reg_op_end - fw_reg_ops;
		if (op_size > REG_OP_SIZE) {
			dev_err(dev, "Invalid op size.");
			return -EINVAL;
		}

		memset(parsed_cmd, 0, REG_OP_SIZE);
		memcpy(parsed_cmd, fw_reg_ops, op_size);
		fw_reg_ops = reg_op_end + 1;

		op_code = regmap_cmd_to_opcode(parsed_cmd);
		if (op_code > 0) {
			reg_ops[op_nr].op = op_code;
			ret = read_register_op(dev, fw_reg_ops,
					       &reg_ops[op_nr], line);
			if (ret < 0)
				return ret;
			op_nr++;
		} else {
			dev_err(dev, "Invalid cmd at line: %d", line);
		}

		fw_reg_ops = strchr(fw_reg_ops, '\n') + 1;
		line++;
	}

	return op_nr;
}

/* Each line represents a register operation.
 * OP,ADDRESS,MASK,VALUE,WAIT_US (see beginning of source file)
 * Allocate an array of iio_regmap_op structs
 * then parse each command stored the firmware file,
 * finally run each command.
 */
static int interpret_register_ops(struct device *dev, struct regmap *regmap,
				  const char *fw_reg_ops)
{
	struct iio_regmap_op *reg_ops;
	int nr_ops;

	reg_ops = alloc_register_ops(dev, fw_reg_ops);
	if (!reg_ops) {
		dev_err(dev, "Could not allocate registers array.");
		return -1;
	}

	nr_ops = parse_register_ops(dev, fw_reg_ops, reg_ops);
	if (nr_ops < 0)
		return nr_ops;

	return 0;
}

int iio_regmap_probe(struct device *dev, struct regmap *regmap,
		     const char *name)
{
	struct iio_dev *indio_dev;
	struct iio_regmap *st;
	const char *register_ops;
	int ret;

	indio_dev = devm_iio_device_alloc(dev, sizeof(*st));
	if (!indio_dev)
		return -ENOMEM;

	st = iio_priv(indio_dev);
	dev_set_drvdata(dev, indio_dev);

	st->dev = dev;
	st->regmap = regmap;

	indio_dev->dev.parent = dev;
	indio_dev->name = name;
	indio_dev->info = &iio_regmap_info;
	indio_dev->modes = INDIO_DIRECT_MODE;

	ret = devm_iio_device_register(dev, indio_dev);
	if (ret < 0)
		dev_err(&indio_dev->dev, "iio-regmap device register failed\n");

	register_ops = read_firmware(dev);
	if (IS_ERR(register_ops)) {
		dev_err(dev, "read_firmware failed!\n");
		return PTR_ERR(register_ops);
	}

	ret = interpret_register_ops(dev, regmap, register_ops);

	return ret;
}
EXPORT_SYMBOL_GPL(iio_regmap_probe);

MODULE_AUTHOR("Alexandru Tachici <alexandru.tachici@analog.com>");
MODULE_DESCRIPTION("Generic IIO access driver");
MODULE_LICENSE("GPL v2");
