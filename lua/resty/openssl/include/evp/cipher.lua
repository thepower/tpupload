local ffi = require "ffi"

require "resty.openssl.include.ossl_typ"
local OPENSSL_3X = require("resty.openssl.version").OPENSSL_3X

ffi.cdef [[
  EVP_CIPHER_CTX *EVP_CIPHER_CTX_new(void);
  // int EVP_CIPHER_CTX_reset(EVP_CIPHER_CTX *c);
  void EVP_CIPHER_CTX_free(EVP_CIPHER_CTX *c);

  int EVP_CIPHER_CTX_set_padding(EVP_CIPHER_CTX *c, int pad);

  const EVP_CIPHER *EVP_CIPHER_CTX_cipher(const EVP_CIPHER_CTX *ctx);
  const EVP_CIPHER *EVP_get_cipherbyname(const char *name);
  int EVP_CIPHER_CTX_ctrl(EVP_CIPHER_CTX *ctx, int type, int arg, void *ptr);
  // int EVP_EncryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out,
  //         int *outl, const unsigned char *in, int inl);
  // int EVP_DecryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out,
  //         int *outl, const unsigned char *in, int inl);


  int EVP_CipherInit_ex(EVP_CIPHER_CTX *ctx,
            const EVP_CIPHER *cipher, ENGINE *impl,
            const unsigned char *key,
            const unsigned char *iv, int enc);
  int EVP_CipherUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out,
              int *outl, const unsigned char *in, int inl);
  int EVP_CipherFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *outm,
              int *outl);

  // list functions
  typedef void* fake_openssl_cipher_list_fn(const EVP_CIPHER *ciph, const char *from,
                                            const char *to, void *x);
  //void EVP_CIPHER_do_all_sorted(fake_openssl_cipher_list_fn*, void *arg);
  void EVP_CIPHER_do_all_sorted(void (*fn)
                               (const EVP_CIPHER *ciph, const char *from,
                                const char *to, void *x), void *arg);

  int EVP_BytesToKey(const EVP_CIPHER *type, const EVP_MD *md,
                    const unsigned char *salt,
                    const unsigned char *data, int datal, int count,
                    unsigned char *key, unsigned char *iv);

]]


if OPENSSL_3X then
  require "resty.openssl.include.provider"

  ffi.cdef [[
    int EVP_CIPHER_CTX_get_block_size(const EVP_CIPHER_CTX *ctx);
    int EVP_CIPHER_CTX_get_key_length(const EVP_CIPHER_CTX *ctx);
    int EVP_CIPHER_CTX_get_iv_length(const EVP_CIPHER_CTX *ctx);

    int EVP_CIPHER_get_nid(const EVP_CIPHER *cipher);

    const OSSL_PROVIDER *EVP_CIPHER_get0_provider(const EVP_CIPHER *cipher);
    EVP_CIPHER *EVP_CIPHER_fetch(OSSL_LIB_CTX *ctx, const char *algorithm,
                                  const char *properties);

    typedef void* fake_openssl_cipher_provided_list_fn(EVP_CIPHER *cipher, void *arg);
    void EVP_CIPHER_do_all_provided(OSSL_LIB_CTX *libctx,
                                    fake_openssl_cipher_provided_list_fn*,
                                    void *arg);
    // int EVP_CIPHER_up_ref(EVP_CIPHER *cipher);
    // void EVP_CIPHER_free(EVP_CIPHER *cipher);

    const char *EVP_CIPHER_get0_name(const EVP_CIPHER *cipher);

    int EVP_CIPHER_CTX_set_params(EVP_CIPHER_CTX *ctx, const OSSL_PARAM params[]);
    const OSSL_PARAM *EVP_CIPHER_CTX_settable_params(EVP_CIPHER_CTX *ctx);
    int EVP_CIPHER_CTX_get_params(EVP_CIPHER_CTX *ctx, OSSL_PARAM params[]);
    const OSSL_PARAM *EVP_CIPHER_CTX_gettable_params(EVP_CIPHER_CTX *ctx);
  ]]
else
  ffi.cdef [[
    int EVP_CIPHER_CTX_block_size(const EVP_CIPHER_CTX *ctx);
    int EVP_CIPHER_CTX_key_length(const EVP_CIPHER_CTX *ctx);
    int EVP_CIPHER_CTX_iv_length(const EVP_CIPHER_CTX *ctx);

    int EVP_CIPHER_nid(const EVP_CIPHER *cipher);
  ]]
end
