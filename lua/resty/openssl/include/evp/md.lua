local ffi = require "ffi"

require "resty.openssl.include.ossl_typ"
local OPENSSL_3X = require("resty.openssl.version").OPENSSL_3X

ffi.cdef [[
  int EVP_DigestInit_ex(EVP_MD_CTX *ctx, const EVP_MD *type,
  ENGINE *impl);
  int EVP_DigestUpdate(EVP_MD_CTX *ctx, const void *d,
                                  size_t cnt);
  int EVP_DigestFinal_ex(EVP_MD_CTX *ctx, unsigned char *md,
                                  unsigned int *s);
  const EVP_MD *EVP_get_digestbyname(const char *name);
  int EVP_DigestUpdate(EVP_MD_CTX *ctx, const void *d,
                                size_t cnt);
  int EVP_DigestFinal_ex(EVP_MD_CTX *ctx, unsigned char *md,
                                unsigned int *s);

  const EVP_MD *EVP_md_null(void);

  EVP_MD_CTX *EVP_MD_CTX_new(void);
  void EVP_MD_CTX_free(EVP_MD_CTX *ctx);

  typedef void* fake_openssl_md_list_fn(const EVP_MD *ciph, const char *from,
                                        const char *to, void *x);
  void EVP_MD_do_all_sorted(fake_openssl_md_list_fn*, void *arg);

  const EVP_MD *EVP_get_digestbyname(const char *name);
]]

if OPENSSL_3X then
  require "resty.openssl.include.provider"

  ffi.cdef [[
    int EVP_MD_get_size(const EVP_MD *md);
    int EVP_MD_get_type(const EVP_MD *md);
    const OSSL_PROVIDER *EVP_MD_get0_provider(const EVP_MD *md);

    EVP_MD *EVP_MD_fetch(OSSL_LIB_CTX *ctx, const char *algorithm,
                          const char *properties);

    typedef void* fake_openssl_md_provided_list_fn(EVP_MD *md, void *arg);
    void EVP_MD_do_all_provided(OSSL_LIB_CTX *libctx,
                                fake_openssl_md_provided_list_fn*,
                                void *arg);
    // int EVP_MD_up_ref(EVP_MD *md);
    void EVP_MD_free(EVP_MD *md);

    const char *EVP_MD_get0_name(const EVP_MD *md);

    int EVP_MD_CTX_set_params(EVP_MD_CTX *ctx, const OSSL_PARAM params[]);
    const OSSL_PARAM *EVP_MD_CTX_settable_params(EVP_MD_CTX *ctx);
    int EVP_MD_CTX_get_params(EVP_MD_CTX *ctx, OSSL_PARAM params[]);
    const OSSL_PARAM *EVP_MD_CTX_gettable_params(EVP_MD_CTX *ctx);
  ]]
else
  ffi.cdef [[
    int EVP_MD_size(const EVP_MD *md);
    int EVP_MD_type(const EVP_MD *md);
  ]]
end
