IDF_IMAGE := espressif/idf@sha256:f1e9f69dc052b9afc7801ca884e0ef40c17e014bb05ce73d9c09d29290bd17fb
FIRMWARE_DIRECTORY := $(CURDIR)/firmware/esp32-native-frame
PROVISION_TOOLS_DIRECTORY := $(FIRMWARE_DIRECTORY)/build/provision-tools
NVS_PARTITION_TOOL_DIRECTORY := $(PROVISION_TOOLS_DIRECTORY)/nvs-partition-tool
PROVISION_PYTHON := $(PROVISION_TOOLS_DIRECTORY)/venv/bin/python

.PHONY: esp32-native-frame esp32-native-frame-firmware esp32-native-frame-provision-tools

esp32-native-frame: esp32-native-frame-firmware

esp32-native-frame-firmware:
	docker run --rm \
		--mount type=bind,source="$(CURDIR)",target=/project \
		--workdir /project/firmware/esp32-native-frame \
		"$(IDF_IMAGE)" \
		bash -lc 'idf.py set-target esp32s3 && idf.py build'

esp32-native-frame-provision-tools:
	mkdir -p "$(NVS_PARTITION_TOOL_DIRECTORY)"
	docker run --rm \
		--user "$$(id -u):$$(id -g)" \
		--mount type=bind,source="$(NVS_PARTITION_TOOL_DIRECTORY)",target=/output \
		--entrypoint /bin/sh \
		"$(IDF_IMAGE)" \
		-c 'cp /opt/esp/idf/components/nvs_flash/nvs_partition_tool/nvs_tool.py /opt/esp/idf/components/nvs_flash/nvs_partition_tool/nvs_check.py /opt/esp/idf/components/nvs_flash/nvs_partition_tool/nvs_logger.py /opt/esp/idf/components/nvs_flash/nvs_partition_tool/nvs_parser.py /output/'
	python3 -m venv "$(PROVISION_TOOLS_DIRECTORY)/venv"
	"$(PROVISION_PYTHON)" -m pip install --disable-pip-version-check --no-input --upgrade \
		esptool==5.3.1 esp-idf-nvs-partition-gen==0.1.6
	"$(PROVISION_PYTHON)" -m esptool version
