# -*- makefile -*-

APP_NAME = pam-memcached
APP_VERSION ?= $(shell head -n 1 debian/changelog | sed -r 's/.*?([0-9]+\.[0-9]+\.[0-9]+).*?/\1/')

BUILD_DIR = $(APP_NAME)-$(APP_VERSION)

build: prepare
	cd $(BUILD_DIR) && debuild -i -us -uc

prepare: $(BUILD_DIR)
	tar -czf $(APP_NAME)_$(APP_VERSION).orig.tar.gz $(BUILD_DIR)
	rsync -qav --delete debian/ $(BUILD_DIR)/debian

$(BUILD_DIR):
	rsync -a --exclude=".git|build|debian" ../ $(BUILD_DIR)

clean:
	rm -f *.dsc *.changes *.deb *.tar.gz *.tar.xz *.build
	rm -rf $(BUILD_DIR)

.PHONY: build prepare clean