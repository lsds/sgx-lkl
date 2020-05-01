include ../../common.mk

CC_APP_CONFIG_FULL=sgxlkl-exit_status_full-appconfig.json
CC_APP_CONFIG_BINARY=sgxlkl-exit_status_binary-appconfig.json
CC_APP_CONFIG_NONE=sgxlkl-exit_status_none-appconfig.json

CC_IMAGE=sgxlkl-alpine-bash.img
CC_IMAGE_SIZE=16M

VERBOSE_OPTS=SGXLKL_VERBOSE=1 SGXLKL_KERNEL_VERBOSE=1

ifeq ($(SGXLKL_VERBOSE),)
	SGXLKL_ENV+=${VERBOSE_OPTS}
endif

.DELETE_ON_ERROR:
.PHONY: all clean run-hw run-sw

clean:
	rm -f $(CC_IMAGE)

$(CC_IMAGE):
	${SGXLKL_DISK_TOOL} create --size=${CC_IMAGE_SIZE} --alpine="bash" ${CC_IMAGE}

run-hw: $(CC_IMAGE)
	@${SGXLKL_ENV} ${SGXLKL_STARTER} --app-config=${CC_APP_CONFIG_FULL} --hw-debug $(CC_IMAGE); \
            if [ $$? -eq 42 ]; then \
                echo "TEST PASSED: exit_status (HW mode): full"; \
            else \
                echo "TEST FAILED: exit_status (HW mode): full"; \
            fi
	@${SGXLKL_ENV} ${SGXLKL_STARTER} --app-config=${CC_APP_CONFIG_BINARY} --hw-debug $(CC_IMAGE); \
            if [ $$? -eq 1 ]; then \
                echo "TEST PASSED: exit_status (HW mode): binary"; \
            else \
                echo "TEST FAILED: exit_status (HW mode): binary"; \
            fi
	@${SGXLKL_ENV} ${SGXLKL_STARTER} --app-config=${CC_APP_CONFIG_NONE} --hw-debug $(CC_IMAGE); \
            if [ $$? -eq 0 ]; then \
                echo "TEST PASSED: exit_status (HW mode): none"; \
            else \
                echo "TEST FAILED: exit_status (HW mode): none"; \
            fi

run-sw: $(CC_IMAGE)
	@${SGXLKL_ENV} ${SGXLKL_STARTER} --app-config=${CC_APP_CONFIG_FULL} --sw-debug $(CC_IMAGE); \
            if [ $$? -eq 42 ]; then \
                echo "TEST PASSED: exit_status (SW mode): full"; \
            else \
                echo "TEST FAILED: exit_status (SW mode): full"; \
            fi
	@${SGXLKL_ENV} ${SGXLKL_STARTER} --app-config=${CC_APP_CONFIG_BINARY} --sw-debug $(CC_IMAGE); \
            if [ $$? -eq 1 ]; then \
                echo "TEST PASSED: exit_status (SW mode): binary"; \
            else \
                echo "TEST FAILED: exit_status (SW mode): binary"; \
            fi
	@${SGXLKL_ENV} ${SGXLKL_STARTER} --app-config=${CC_APP_CONFIG_NONE} --sw-debug $(CC_IMAGE); \
            if [ $$? -eq 0 ]; then \
                echo "TEST PASSED: exit_status (SW mode): none"; \
            else \
                echo "TEST FAILED: exit_status (SW mode): none"; \
            fi
