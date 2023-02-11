#include "http.h"

namespace sunfor3 {

typedef u_int bpf_u_int32;

/* internal variables. */
std::string internal_url;
std::unordered_map<std::string, std::string>* internal_header;
std::string internal_field;
std::string internal_value;

/* User callbakcs definations start. */
int handle_on_message_complete(llhttp_t *arg) {
  /* do nothing here. */
  return 0;
}

int handle_on_url(llhttp_t *arg, const char *at, size_t length) {
  internal_url = std::string(at, length);
  return 0;
}

int handle_on_header_field(llhttp_t *arg, const char *at, size_t length) {
  internal_field = std::string(at, length);
  // fprintf(stdout, "header_field=\"%.*s\", ", (int)length, at);
  return 0;
}

int handle_on_header_value(llhttp_t *arg, const char *at, size_t length) {
  internal_value = std::string(at, length);
  // fprintf(stdout, "header_value=\"%.*s\", ", (int)length, at);
  return 0;
}

int handle_on_header_value_complete(llhttp_t *arg) {
  /* Called when a key-value finished. */
  internal_header->emplace(internal_field, internal_value);
  internal_field = "";
  internal_value = "";
  return 0;
}

int handle_on_headers_complete(llhttp_t *arg) {
  /* Called when header parser done. */
  assert(internal_field=="");
  assert(internal_value=="");
  return 0;
}

/* End of user callbakcs definations. */

llhttp_cube_t* http_init() {
  llhttp_cube_t* http_cube = new llhttp_cube_t;
  http_cube->handle = new llhttp_t;
  http_cube->settings = new llhttp_settings_t;

  /* Initialize user callbacks and settings */
  llhttp_settings_init(http_cube->settings);

  /* Set user callback */
  http_cube->settings->on_message_complete = handle_on_message_complete;
  http_cube->settings->on_url = handle_on_url;
  http_cube->settings->on_header_field = handle_on_header_field;
  http_cube->settings->on_header_value = handle_on_header_value;
  http_cube->settings->on_header_value_complete = handle_on_header_value_complete;
  http_cube->settings->on_headers_complete = handle_on_headers_complete;

  /* 
   * Initialize the parser in HTTP_BOTH mode, meaning that it will select between
   * HTTP_REQUEST and HTTP_RESPONSE parsing automatically while reading the first
   * input.
   */
  llhttp_init(http_cube->handle, HTTP_BOTH, http_cube->settings);

  return http_cube;
}

void http_end(llhttp_cube_t* http_cube) {
  if (http_cube != nullptr && http_cube->handle != nullptr)
    delete http_cube->handle;
  if (http_cube != nullptr && http_cube->settings != nullptr)
    delete http_cube->settings;
  if (http_cube != nullptr)
    delete http_cube;
}

void http_parse(llhttp_cube_t* http_cube, const u_char* http_data, bpf_u_int32 http_len, struct http_parser* hp) {
  /* Get llhttp_t* handle. */
  llhttp_t* handle = http_cube->handle;
  /* get header map & clear old k-v. */
  internal_header = &(hp->header);
  internal_header->clear();
  enum llhttp_errno err = llhttp_execute(handle, (const char*)http_data, http_len);
  if (err == HPE_OK) {
    /* Successfully parsed! */
    
    /* Deal with different http types. (REQUEST/RESPONSE) */
    uint8_t http_type = llhttp_get_type(handle);
    if (http_type == HTTP_REQUEST) {
      hp->type = 1;

      struct http_request* request = hp->request;
      request->method = llhttp_method_name(llhttp_method_t(llhttp_get_method(handle)));
      request->url = internal_url;
      request->version = std::to_string(llhttp_get_http_major(handle)) + '.' + std::to_string(llhttp_get_http_minor(handle));
    }
    else if (http_type == HTTP_RESPONSE) {
      hp->type = 2;

      struct http_response* response = hp->response;
      response->version = std::to_string(llhttp_get_http_major(handle)) + '.' + std::to_string(llhttp_get_http_minor(handle));
      response->status_code = llhttp_get_status_code(handle);
      response->status_name = llhttp_status_name(llhttp_status_t(llhttp_get_status_code(handle)));
    }
  }
  else {
    fprintf(stderr, "HTTP parser error: %s, %s\n", llhttp_errno_name(err), handle->reason);
  }

  /* free & Clear internal variables. */
  internal_url = "";
}
}