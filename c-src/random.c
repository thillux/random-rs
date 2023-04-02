#include <assert.h>
#include <fcntl.h>
#include <libp11.h>
#include <linux/random.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#define RANDOM_DEV "/dev/random"
#define BUF_SIZE_MAX 4096

uint32_t get_kernel_entropy() {
  int fd = open(RANDOM_DEV, O_RDWR);
  assert(fd > 0);

  int ent_cnt;
  int ret = ioctl(fd, RNDGETENTCNT, &ent_cnt);
  assert(ret == 0);

  close(fd);

  return ent_cnt > 0 ? (uint32_t)ent_cnt : 0;
}

void add_kernel_entropy(int32_t ent_cnt, uint8_t *buffer, size_t size) {
  assert(buffer != NULL);

  const size_t max_size = 65535;
  assert(size <= max_size);

  int fd = open(RANDOM_DEV, 0);
  assert(fd > 0);

  struct {
    int ent_count;
    int size;
    unsigned char data[max_size];
  } entropy;

  entropy.ent_count = ent_cnt;
  entropy.size = size;
  memcpy(entropy.data, buffer, size);

  int ret = ioctl(fd, RNDADDENTROPY, &entropy);
  assert(ret == 0);

  close(fd);
}

struct Pkcs11Context {
  PKCS11_CTX *ctx;
  PKCS11_SLOT *slots;
  unsigned int nslots;
  PKCS11_SLOT *slot;
};

void *sc_open(char *pkcs11_engine_path) {
  struct Pkcs11Context *ctx = malloc(sizeof(struct Pkcs11Context));
  ctx->ctx = PKCS11_CTX_new();
  PKCS11_CTX_load(ctx->ctx, pkcs11_engine_path);

  PKCS11_enumerate_slots(ctx->ctx, &ctx->slots, &ctx->nslots);
  ctx->slot = PKCS11_find_token(ctx->ctx, ctx->slots, ctx->nslots);

  printf("Slot manufacturer......: %s\n", ctx->slot->manufacturer);
  printf("Slot description.......: %s\n", ctx->slot->description);
  printf("Slot token label.......: %s\n", ctx->slot->token->label);
  printf("Slot token manufacturer: %s\n", ctx->slot->token->manufacturer);
  printf("Slot token model.......: %s\n", ctx->slot->token->model);
  printf("Slot token serial......: %s\n", ctx->slot->token->serialnr);

  return ctx;
}

void sc_close(void *ctx_opaque) {
  struct Pkcs11Context *ctx = ctx_opaque;

  PKCS11_release_all_slots(ctx->ctx, ctx->slots, ctx->nslots);
  PKCS11_CTX_unload(ctx->ctx);
  PKCS11_CTX_free(ctx->ctx);
  memset(ctx, 0, sizeof(struct Pkcs11Context));
  free(ctx);
}

void sc_random(void *ctx_opaque, uint8_t *buf, size_t size) {
  struct Pkcs11Context *ctx = ctx_opaque;

  PKCS11_generate_random(ctx->slot, buf, size);
}