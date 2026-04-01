#include <errno.h>
#include <curl/curl.h>
#include <glib.h>
#include <json-c/json.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "enclave_proxy.h"
#include "kms.h"
#include "signer.h"

#define DATAKEY_BITS 256
#define DEFAULT_PROXY_PORT 8000
#define PARENT_CID 3
#define URI_PREFIX_MAX_LEN 256
#define SOCKET_PATH_MAX_LEN 128
#define MAX_STDIN_BYTES (64 * 1024)
#define MAX_RANDOM_BYTES 4096
#define MAX_CIPHERTEXT_BYTES 8192
#define MAX_PLAINTEXT_BYTES 4096
#define SECURITY_TOKEN_HEADER "X-Security-Token"
#define DECRYPT_DATAKEY_API "decrypt-datakey"
#define HTTPS_OK 200

typedef struct bridge_request_s {
    char *action;
    char *access_key;
    char *secret_key;
    char *security_token;
    char *endpoint;
    char *project_id;
    char *key_id;
    int proxy_port;
    int num_bytes;
    char *ciphertext;
} bridge_request_t;

static void free_request(bridge_request_t *request);
static int decrypt_datakey_via_proxy(const bridge_request_t *request, sig_params_t *params, unsigned char *plaintext, unsigned int *plaintext_len);

static void emit_error(const char *message)
{
    struct json_object *response = json_object_new_object();
    json_object_object_add(response, "status", json_object_new_string("error"));
    json_object_object_add(response, "message", json_object_new_string(message ? message : "unknown error"));
    fputs(json_object_to_json_string_ext(response, JSON_C_TO_STRING_PLAIN), stdout);
    fputc('\n', stdout);
    json_object_put(response);
}

static void emit_success(struct json_object *payload)
{
    fputs(json_object_to_json_string_ext(payload, JSON_C_TO_STRING_PLAIN), stdout);
    fputc('\n', stdout);
}

static size_t write_memory_callback(void *contents, size_t size, size_t nmemb, void *userp)
{
    size_t real_size = size * nmemb;
    sig_str_t *resp_data = (sig_str_t *)userp;

    resp_data->data = malloc(real_size + 1);
    if (resp_data->data == NULL) {
        return 0;
    }

    resp_data->len = real_size + 1;
    memset(resp_data->data, 0, real_size + 1);
    memcpy(resp_data->data, contents, real_size);
    resp_data->data[real_size] = '\0';
    return real_size;
}

static char *read_stdin_payload(void)
{
    char *buffer = calloc(1, MAX_STDIN_BYTES + 1);
    size_t total = 0;

    if (buffer == NULL) {
        return NULL;
    }

    while (!feof(stdin)) {
        size_t remain = MAX_STDIN_BYTES - total;
        size_t read_bytes;
        if (remain == 0) {
            free(buffer);
            return NULL;
        }
        read_bytes = fread(buffer + total, 1, remain, stdin);
        total += read_bytes;
        if (ferror(stdin)) {
            free(buffer);
            return NULL;
        }
    }

    buffer[total] = '\0';
    return buffer;
}

static int json_get_string(struct json_object *object, const char *key, char **out)
{
    struct json_object *value = NULL;
    const char *string_value = NULL;
    if (!json_object_object_get_ex(object, key, &value) || value == NULL) {
        return -1;
    }
    string_value = json_object_get_string(value);
    if (string_value == NULL || string_value[0] == '\0') {
        return -1;
    }
    *out = strdup(string_value);
    return *out == NULL ? -1 : 0;
}

static int json_get_optional_string(struct json_object *object, const char *key, char **out)
{
    struct json_object *value = NULL;
    const char *string_value = NULL;
    if (!json_object_object_get_ex(object, key, &value) || value == NULL) {
        *out = NULL;
        return 0;
    }
    string_value = json_object_get_string(value);
    if (string_value == NULL || string_value[0] == '\0') {
        *out = NULL;
        return 0;
    }
    *out = strdup(string_value);
    if (*out == NULL) {
        return -1;
    }
    return 0;
}

static int json_get_int(struct json_object *object, const char *key, int default_value)
{
    struct json_object *value = NULL;
    if (!json_object_object_get_ex(object, key, &value) || value == NULL) {
        return default_value;
    }
    return json_object_get_int(value);
}

static int parse_request(const char *payload, bridge_request_t *request)
{
    struct json_object *root = NULL;
    struct json_object *credentials = NULL;
    struct json_object *kms_config = NULL;

    root = json_tokener_parse(payload);
    if (root == NULL) {
        return -1;
    }

    memset(request, 0, sizeof(*request));

    if (json_get_string(root, "action", &request->action) != 0)
        goto error;
    if (!json_object_object_get_ex(root, "credentials", &credentials) || credentials == NULL) {
        goto error;
    }
    if (!json_object_object_get_ex(root, "kms_config", &kms_config) || kms_config == NULL) {
        goto error;
    }
    if (json_get_string(credentials, "access", &request->access_key) != 0 ||
        json_get_string(credentials, "secret", &request->secret_key) != 0 ||
        json_get_optional_string(credentials, "securitytoken", &request->security_token) != 0 ||
        json_get_string(kms_config, "endpoint", &request->endpoint) != 0 ||
        json_get_string(kms_config, "project_id", &request->project_id) != 0 ||
        json_get_string(kms_config, "key_id", &request->key_id) != 0) {
        goto error;
    }

    request->proxy_port = json_get_int(kms_config, "proxy_port", DEFAULT_PROXY_PORT);
    request->num_bytes = json_get_int(root, "num_bytes", 0);
    if (json_get_optional_string(root, "ciphertext", &request->ciphertext) != 0) {
        goto error;
    }

    json_object_put(root);
    return 0;

error:
    json_object_put(root);
    free_request(request);
    return -1;
}

static void free_request(bridge_request_t *request)
{
    free(request->action);
    free(request->access_key);
    free(request->secret_key);
    free(request->security_token);
    free(request->endpoint);
    free(request->project_id);
    free(request->key_id);
    free(request->ciphertext);
    memset(request, 0, sizeof(*request));
}

static void set_sig_str(sig_str_t *target, char *data)
{
    target->data = data;
    target->len = strlen(data);
}

static int init_sig_params(sig_params_t *params, const bridge_request_t *request)
{
    char *uri_prefix = NULL;
    char *socket_path = NULL;

    sig_params_init(params);

    uri_prefix = calloc(1, URI_PREFIX_MAX_LEN);
    socket_path = calloc(1, SOCKET_PATH_MAX_LEN);
    if (uri_prefix == NULL || socket_path == NULL) {
        free(uri_prefix);
        free(socket_path);
        free_request(request);
        return -1;
    }

    if (snprintf(uri_prefix, URI_PREFIX_MAX_LEN, "/v1.0/%s/kms/", request->project_id) < 0 ||
        snprintf(socket_path, SOCKET_PATH_MAX_LEN, CURL_SOCKET_PATH, request->proxy_port) < 0) {
        free(uri_prefix);
        free(socket_path);
        return -1;
    }

    set_sig_str(&params->key, (char *)request->access_key);
    set_sig_str(&params->secret, (char *)request->secret_key);
    set_sig_str(&params->host, (char *)request->endpoint);
    set_sig_str(&params->uri_prefix, uri_prefix);
    set_sig_str(&params->socket_path, socket_path);

    if (request->security_token != NULL && request->security_token[0] != '\0') {
        if (sig_headers_add(&params->headers, SECURITY_TOKEN_HEADER, request->security_token) == NULL) {
            free(uri_prefix);
            free(socket_path);
            return -1;
        }
    }

    return 0;
}

static void cleanup_sig_params(sig_params_t *params)
{
    if (params->uri_prefix.data != NULL) {
        free(params->uri_prefix.data);
        params->uri_prefix.data = NULL;
    }
    if (params->socket_path.data != NULL) {
        free(params->socket_path.data);
        params->socket_path.data = NULL;
    }
    sig_params_free(params);
}

static int hex_to_bytes(const char *hex, unsigned char *output, unsigned int *output_len)
{
    size_t hex_len;
    if (hex == NULL || output == NULL || output_len == NULL) {
        return -1;
    }
    hex_len = strlen(hex);
    if (hex_len % 2 != 0 || (*output_len) < hex_len / 2) {
        return -1;
    }

    for (size_t i = 0; i < hex_len / 2; i++) {
        unsigned int value = 0;
        if (sscanf(hex + (i * 2), "%2x", &value) != 1) {
            return -1;
        }
        output[i] = (unsigned char)value;
    }
    *output_len = (unsigned int)(hex_len / 2);
    return 0;
}

static int perform_signed_decrypt_datakey_request(sig_params_t *params, const char *payload, sig_str_t *response_body, long *http_status)
{
    CURL *curl = NULL;
    CURLcode curl_code;
    struct curl_slist *headers = NULL;
    sig_params_t request_params;
    char uri[URI_PREFIX_MAX_LEN + 32];
    char url[URL_MAX_LEN];

    memset(&request_params, 0, sizeof(request_params));
    request_params = *params;
    request_params.headers.data = NULL;
    request_params.headers.len = 0;
    request_params.headers.alloc = 0;
    request_params.method = (sig_str_t)sig_str("POST");
    request_params.payload = (sig_str_t)sig_str((char *)payload);
    request_params.query_str = (sig_str_t)sig_str("");

    if (snprintf(uri, sizeof(uri), "%s%s", params->uri_prefix.data, DECRYPT_DATAKEY_API) < 0) {
        return -1;
    }
    request_params.uri = (sig_str_t)sig_str(uri);

    if (sig_headers_add(&request_params.headers, "Content-Type", "application/json") == NULL) {
        sig_headers_free(&request_params.headers);
        return -1;
    }
    if (sig_headers_get(&params->headers, SECURITY_TOKEN_HEADER) != NULL) {
        sig_header_t *token_header = sig_headers_get(&params->headers, SECURITY_TOKEN_HEADER);
        if (sig_headers_add(&request_params.headers, SECURITY_TOKEN_HEADER, token_header->value.data) == NULL) {
            sig_headers_free(&request_params.headers);
            return -1;
        }
    }

    if (sig_sign(&request_params) != SIG_OK) {
        sig_headers_free(&request_params.headers);
        return -1;
    }

    curl_code = curl_global_init(CURL_GLOBAL_ALL);
    if (curl_code != CURLE_OK) {
        sig_headers_free(&request_params.headers);
        return -1;
    }

    curl = curl_easy_init();
    if (curl == NULL) {
        sig_headers_free(&request_params.headers);
        curl_global_cleanup();
        return -1;
    }

    snprintf(url, sizeof(url), "https://%s%s?", params->host.data, uri);
    for (size_t i = 0; i < request_params.headers.len; i++) {
        char header[1024];
        snprintf(
            header,
            sizeof(header),
            "%s: %s",
            request_params.headers.data[i].name.data,
            request_params.headers.data[i].value.data
        );
        headers = curl_slist_append(headers, header);
    }

    curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, 10000L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
    curl_easy_setopt(curl, CURLOPT_NOBODY, 0L);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_memory_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, response_body);
    curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "POST");
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_UNIX_SOCKET_PATH, params->socket_path.data);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, payload);

    curl_code = curl_easy_perform(curl);
    if (curl_code != CURLE_OK) {
        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
        sig_headers_free(&request_params.headers);
        curl_global_cleanup();
        return -1;
    }

    curl_easy_getinfo(curl, CURLINFO_HTTP_CODE, http_status);
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    sig_headers_free(&request_params.headers);
    curl_global_cleanup();
    return 0;
}

static int decrypt_datakey_via_proxy(const bridge_request_t *request, sig_params_t *params, unsigned char *plaintext, unsigned int *plaintext_len)
{
    struct connect_info conn;
    sig_str_t response_body = {0};
    struct json_object *response_json = NULL;
    struct json_object *data_key = NULL;
    char payload[9000];
    char length_str[32];
    long http_status = 0;

    memset(&conn, 0, sizeof(conn));
    if (setup_proxy(&conn, PARENT_CID, request->proxy_port) != PX_NO_ERROR) {
        return -1;
    }

    snprintf(length_str, sizeof(length_str), "%zu", strlen(request->ciphertext) / 2);
    snprintf(
        payload,
        sizeof(payload),
        "{\"key_id\":\"%s\",\"cipher_text\":\"%s\",\"datakey_cipher_length\":\"%s\"}",
        request->key_id,
        request->ciphertext,
        length_str
    );

    if (perform_signed_decrypt_datakey_request(params, payload, &response_body, &http_status) != 0) {
        close_proxy(&conn);
        return -1;
    }
    close_proxy(&conn);

    if (http_status != HTTPS_OK || response_body.data == NULL) {
        if (response_body.data != NULL) {
            fprintf(stderr, "HTTPS status: %ld\nKMS response content:\n%s\n", http_status, response_body.data);
            free(response_body.data);
        }
        return -1;
    }

    response_json = json_tokener_parse(response_body.data);
    free(response_body.data);
    if (response_json == NULL) {
        return -1;
    }
    if (!json_object_object_get_ex(response_json, "data_key", &data_key)) {
        json_object_put(response_json);
        return -1;
    }
    if (hex_to_bytes(json_object_get_string(data_key), plaintext, plaintext_len) != 0) {
        json_object_put(response_json);
        return -1;
    }

    json_object_put(response_json);
    return 0;
}

static const char *kms_status_message(unsigned long status)
{
    switch (status) {
        case KMS_SUCCESS:
            return "ok";
        case KMS_QTSM_ERROR:
            return "qtsm error";
        case KMS_REQ_PARAMS_ERROR:
            return "invalid KMS request parameters";
        case KMS_CURL_ERROR:
            return "curl error";
        case KMS_REQ_FAILED:
            return "KMS request failed";
        case KMS_CJSON_ERROR:
            return "KMS JSON parsing error";
        case KMS_GET_ATTESTATION_ERROR:
            return "attestation acquisition failed";
        case KMS_SETUP_PROXY_ERROR:
            return "qt_proxy setup failed";
        default:
            return "KMS bridge error";
    }
}

static int handle_generate_random(const bridge_request_t *request, sig_params_t *params)
{
    unsigned char random_bytes[MAX_RANDOM_BYTES];
    unsigned int random_len = (unsigned int)request->num_bytes;
    random_data_t random = {
        .random = random_bytes,
        .random_len = &random_len,
    };
    unsigned long status;
    char *encoded = NULL;
    struct json_object *response = NULL;

    if (request->num_bytes <= 0 || request->num_bytes > MAX_RANDOM_BYTES) {
        emit_error("num_bytes must be between 1 and 4096");
        return 1;
    }

    status = kms_gen_random_blocking_with_proxy(params, (unsigned int)request->num_bytes, &random, PARENT_CID, request->proxy_port);
    if (status != KMS_SUCCESS) {
        emit_error(kms_status_message(status));
        return 1;
    }

    fprintf(stderr, "[bridge] generate_random status=%lu len=%u hex=", status, *(random.random_len));
    for (unsigned int i = 0; i < *(random.random_len); i++) {
        fprintf(stderr, "%02x", random.random[i]);
    }
    fprintf(stderr, "\n");
    fflush(stderr);

    encoded = g_base64_encode(random.random, *(random.random_len));
    response = json_object_new_object();
    json_object_object_add(response, "random", json_object_new_string(encoded));
    emit_success(response);
    json_object_put(response);
    g_free(encoded);
    return 0;
}

static int handle_create_data_key(const bridge_request_t *request, sig_params_t *params)
{
    unsigned char plaintext_key[DATAKEY_BITS / 8];
    unsigned int plaintext_key_len = sizeof(plaintext_key);
    unsigned char cipher_key[MAX_CIPHERTEXT_BYTES + 1];
    unsigned int cipher_key_len = MAX_CIPHERTEXT_BYTES;
    unsigned int key_id_len = 128;
    char key_id_output[129];
    datakey_t datakey;
    keyid_handle_t handle;
    unsigned long status;
    char *encoded_plaintext = NULL;
    struct json_object *response = NULL;

    memset(&datakey, 0, sizeof(datakey));
    memset(cipher_key, 0, sizeof(cipher_key));
    memset(key_id_output, 0, sizeof(key_id_output));

    handle.key_id = (char *)request->key_id;
    handle.len = strlen(request->key_id);

    datakey.key_id = key_id_output;
    datakey.key_id_len = &key_id_len;
    datakey.plain_key = plaintext_key;
    datakey.plain_key_len = &plaintext_key_len;
    datakey.cipher_key = cipher_key;
    datakey.cipher_key_len = &cipher_key_len;

    status = kms_generate_datakey_blocking_with_proxy(params, &handle, DATAKEY_BITS, &datakey, PARENT_CID, request->proxy_port);
    if (status != KMS_SUCCESS) {
        emit_error(kms_status_message(status));
        return 1;
    }

    cipher_key[cipher_key_len] = '\0';
    encoded_plaintext = g_base64_encode(datakey.plain_key, *(datakey.plain_key_len));
    response = json_object_new_object();
    json_object_object_add(response, "plaintext", json_object_new_string(encoded_plaintext));
    json_object_object_add(response, "ciphertext", json_object_new_string((char *)datakey.cipher_key));
    emit_success(response);
    json_object_put(response);
    g_free(encoded_plaintext);
    return 0;
}

static int handle_decrypt_data_key(const bridge_request_t *request, sig_params_t *params)
{
    unsigned char plaintext[MAX_PLAINTEXT_BYTES];
    unsigned int plaintext_len = sizeof(plaintext);
    char *encoded_plaintext = NULL;
    struct json_object *response = NULL;

    if (request->ciphertext == NULL || request->ciphertext[0] == '\0') {
        emit_error("ciphertext is required");
        return 1;
    }

    if (decrypt_datakey_via_proxy(request, params, plaintext, &plaintext_len) != 0) {
        emit_error("failed to decrypt DEK via decrypt-datakey");
        return 1;
    }

    encoded_plaintext = g_base64_encode(plaintext, plaintext_len);
    response = json_object_new_object();
    json_object_object_add(response, "plaintext", json_object_new_string(encoded_plaintext));
    emit_success(response);
    json_object_put(response);
    g_free(encoded_plaintext);
    return 0;
}

int main(void)
{
    char *payload = NULL;
    bridge_request_t request;
    sig_params_t params;
    int rc;

    payload = read_stdin_payload();
    if (payload == NULL) {
        emit_error("failed to read bridge request");
        return 1;
    }

    if (parse_request(payload, &request) != 0) {
        free(payload);
        emit_error("invalid bridge request");
        return 1;
    }

    if (init_sig_params(&params, &request) != 0) {
        free_request(&request);
        free(payload);
        emit_error("failed to initialize signature parameters");
        return 1;
    }

    if (strcmp(request.action, "generate_random") == 0) {
        rc = handle_generate_random(&request, &params);
    } else if (strcmp(request.action, "create_data_key") == 0) {
        rc = handle_create_data_key(&request, &params);
    } else if (strcmp(request.action, "decrypt_data_key") == 0) {
        rc = handle_decrypt_data_key(&request, &params);
    } else {
        emit_error("unsupported action");
        rc = 1;
    }

    cleanup_sig_params(&params);
    free_request(&request);
    free(payload);
    return rc;
}
