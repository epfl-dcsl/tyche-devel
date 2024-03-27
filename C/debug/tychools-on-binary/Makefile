all: redis-server-seg

REDIS_PATH ?= ../../../../tyche-experiment-redis/tyche-redis/src/redis-server
TYCHOOLS_PATH ?= ../../../crates/tychools/

redis-server-seg:
	test -s $(REDIS_PATH) && cp $(REDIS_PATH) redis-server-tmp
	cargo -Z unstable-options -C $(TYCHOOLS_PATH) install --path . --locked
	tychools instrument -s manifests/default.json
	rm redis-server-tmp

.PHONY: clean

clean:
	rm redis-server-seg

