#ifndef _SRC_HTTP_H_
#define _SRC_HTTP_H_

#include <iostream>
#include <string>
#include <unordered_map>
#include <assert.h>
#include "./native/llhttp.h"
#include "parser.h"

// C++ interface to parse http data.
// Defined sorts of functions to use llhttp.
// --------------------------------------------------

namespace sunfor3 {

typedef u_int bpf_u_int32;

struct llhttp_cube_t {
  llhttp_t* handle;
  llhttp_settings_t* settings;
};

// Get a llhttp struct handle and init it.
// Get a http_parser and new it.
llhttp_cube_t* http_init();

// Free handle and http_parser.
void http_end(llhttp_cube_t* http_cube);

// Parse function, get http_data and http_len,
// the parsed result will store in hp.
void http_parse(llhttp_cube_t* http_cube, const u_char* http_data, bpf_u_int32 http_len, struct http_parser* hp);

void http_parse(llhttp_cube_t* http_cube, const u_char* http_data, bpf_u_int32 http_len, unordered_map& hp);

} /* namespace sunfor3 */

#endif  // _SRC_HTTP_H_