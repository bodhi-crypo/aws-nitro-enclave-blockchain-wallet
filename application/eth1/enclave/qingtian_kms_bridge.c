#include <errno.h>
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
    plain_cipher_buff_t data;
    keyid_handle_t handle;
    unsigned long status;
    char *encoded_plaintext = NULL;
    struct json_object *response = NULL;

    if (request->ciphertext == NULL || request->ciphertext[0] == '\0') {
        emit_error("ciphertext is required");
        return 1;
    }

    handle.key_id = (char *)request->key_id;
    handle.len = strlen(request->key_id);

    data.data_in = (const unsigned char *)request->ciphertext;
    data.data_in_len = strlen(request->ciphertext);
    data.data_out = plaintext;
    data.data_out_len = &plaintext_len;

    status = kms_decrypt_data_blocking_with_proxy(params, &handle, &data, PARENT_CID, request->proxy_port);
    if (status != KMS_SUCCESS) {
        emit_error(kms_status_message(status));
        return 1;
    }

    encoded_plaintext = g_base64_encode(data.data_out, *(data.data_out_len));
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
