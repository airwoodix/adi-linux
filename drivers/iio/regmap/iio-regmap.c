// SPDX-License-Identifier: GPL-2.0
/*
 * Generic IIO access driver
 *
 * Copyright 2019 Analog Devices Inc.
 */

#include <linux/iio/iio.h>
#include <linux/firmware.h>
#include <linux/module.h>
#include <linux/spi/spi.h>
#include <linux/regmap.h>

#include "iio-regmap.h"

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

	return ret;
}
EXPORT_SYMBOL_GPL(iio_regmap_probe);

MODULE_AUTHOR("Alexandru Tachici <alexandru.tachici@analog.com>");
MODULE_DESCRIPTION("Generic IIO access driver");
MODULE_LICENSE("GPL v2");
