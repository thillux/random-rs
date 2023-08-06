#include <assert.h>
#include <fcntl.h>
#include <libp11.h>
#include <linux/random.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <jitterentropy.h>
#include <unistd.h>
#include <gpg-error.h>
#include <gpgme.h>
#include <stdbool.h>

#define RANDOM_DEV "/dev/random"
#define URANDOM_DEV "/dev/urandom"
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

void add_kernel_entropy_unaccounted(uint8_t *buffer, size_t size) {
  assert(buffer != NULL);
  const size_t max_size = 65535;
  assert(size <= max_size);

  int fd = open(URANDOM_DEV, O_WRONLY);
  assert(fd > 0);

  ssize_t ret = write(fd, buffer, size);
  assert(ret == (ssize_t)size);

  close(fd);
}

void add_kernel_entropy(int32_t ent_cnt, uint8_t *buffer, size_t size) {
  assert(buffer != NULL);

  const size_t max_size = 65535;
  assert(size <= max_size);

  int fd = open(RANDOM_DEV, O_RDWR);
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

void reseed() {
    int fd = open(RANDOM_DEV, O_RDWR);
    assert(fd > 0);

    int ret = ioctl(fd, RNDRESEEDCRNG, NULL);
    assert(ret == 0);

    close(fd);
}

struct Pkcs11Context {
  PKCS11_CTX *ctx;
  PKCS11_SLOT *slots;
  unsigned int nslots;
  PKCS11_SLOT *slot;
};

void* jent_open(uint32_t osr) {
  int ret = jent_entropy_init();
  assert(ret == 0);

  struct rand_data* ec = jent_entropy_collector_alloc(osr, 0);
  assert(ec != NULL);

  return (void*) ec;
}

void jent_random(void *ctx_opaque, uint8_t *buf, size_t size) {
  struct rand_data* ec = ctx_opaque;

  ssize_t ret = jent_read_entropy(ec, (char*)buf, size);
  assert(ret == (ssize_t)size);
}

void jent_close(void* ctx_opaque) {
  struct rand_data* ec = ctx_opaque;

  jent_entropy_collector_free(ec);
}

void *sc_open(char *pkcs11_engine_path) {
  struct Pkcs11Context *ctx = malloc(sizeof(struct Pkcs11Context));
  assert(ctx != NULL);
  ctx->ctx = PKCS11_CTX_new();
  assert(ctx->ctx != NULL);

  int ret = PKCS11_CTX_load(ctx->ctx, pkcs11_engine_path);
  assert(ret == 0);

  ret = PKCS11_enumerate_slots(ctx->ctx, &ctx->slots, &ctx->nslots);
  assert(ret == 0);
  ctx->slot = PKCS11_find_token(ctx->ctx, ctx->slots, ctx->nslots);
  assert(ctx->slot != NULL);

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
  assert(ctx != NULL);

  PKCS11_release_all_slots(ctx->ctx, ctx->slots, ctx->nslots);
  PKCS11_CTX_unload(ctx->ctx);
  PKCS11_CTX_free(ctx->ctx);

  memset(ctx, 0, sizeof(struct Pkcs11Context));
  free(ctx);
}

void sc_random(void *ctx_opaque, uint8_t *buf, size_t size) {
  struct Pkcs11Context *ctx = ctx_opaque;

  int ret = PKCS11_generate_random(ctx->slot, buf, size);
  assert(ret == 0);
}

int sc_login(void *ctx_opaque, int so, const char* pin) {
    struct Pkcs11Context *ctx = ctx_opaque;
    assert(ctx != NULL);
    assert(ctx->slot != NULL);
    assert(so == 0 || so == 1);
    assert(pin != NULL);

    return PKCS11_login(ctx->slot, so, pin);
}

int sc_logout(void *ctx_opaque) {
    struct Pkcs11Context *ctx = ctx_opaque;
    assert(ctx != NULL);
    assert(ctx->slot != NULL);

    return PKCS11_logout(ctx->slot);
}

gpgme_error_t read_gpg_data_random(void* target, const void *data, size_t datalen) {
    memcpy(target, data, datalen);
    return GPG_ERR_NO_ERROR;
}

gpgme_error_t read_gpg_data_serial(void* target, const void *data, size_t datalen) {
    printf("Call\n");
    return GPG_ERR_NO_ERROR;
}

gpgme_error_t read_gpg_status_serial(void* target, const char *status, const char *args) {
    printf("Status: %s Args: %s\n", status, args);
    return GPG_ERR_NO_ERROR;
}

void* scd_open() {
    const char* version = gpgme_check_version(NULL);
    printf("Initialized GPG agent with version: %s\n", version);
    gpgme_ctx_t gpgagent;

    gpgme_error_t err = gpgme_new(&gpgagent);
    assert(err == GPG_ERR_NO_ERROR);

    err = gpgme_set_protocol(gpgagent, GPGME_PROTOCOL_ASSUAN);
    assert(err == GPG_ERR_NO_ERROR);

    return (void*)gpgagent;
}

void scd_list_cards(void* ctx) {
    gpgme_ctx_t gpgagent = ctx;
    const char* command = "scd getinfo card_list";
    gpgme_error_t err;
    gpgme_error_t op_err;
    err = gpgme_op_assuan_transact_ext(gpgagent, command, read_gpg_data_serial, NULL, NULL, NULL, read_gpg_status_serial, NULL, &op_err);

    if(op_err != GPG_ERR_NO_ERROR) {
        printf("error listing cards: %s, %s\n", gpgme_strerror(err), gpgme_strerror(op_err));
        gpgme_release(gpgagent);
    }
}

void scd_close(void* ctx) {
    gpgme_ctx_t gpgagent = ctx;
    gpgme_release(gpgagent);
}

void scd_select_card(void* ctx, char* card) {
D276000124010304000FB9FEAE710000
}

bool scd_random(void* ctx, uint8_t *buf, size_t size) {
    gpgme_ctx_t gpgagent = ctx;
    assert(gpgagent != NULL);
    gpgme_error_t err;

    char command[128];
    sprintf(command, "scd random %lu", size);

    gpgme_error_t op_err;
    err = gpgme_op_assuan_transact_ext(gpgagent, command, read_gpg_data_random, buf, NULL, NULL, NULL, NULL, &op_err);

    if(op_err != GPG_ERR_NO_ERROR) {
        printf("error reading random data: %s, %s\n", gpgme_strerror(err), gpgme_strerror(op_err));
        gpgme_release(gpgagent);
        return false;
    }

    return true;
}
