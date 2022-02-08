# SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)

XDP_TARGETS  := xflow
USER_TARGETS := xflow_user
USER_LIBS    := -lbpf -lm

LIBBPF_DIR = ./libbpf/src/
COMMON_DIR = ./common

EXTRA_DEPS  += $(COMMON_DIR)/parsing_helpers.h

include $(COMMON_DIR)/common.mk
#COMMON_OBJS := $(COMMON_DIR)/common.o
