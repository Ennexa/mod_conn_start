/* Include the required headers from httpd */
#include "httpd.h"
#include "http_core.h"
#include "http_protocol.h"
#include "http_request.h"
#include "http_connection.h"
#include "http_log.h"
#include "apr_strings.h"

module AP_MODULE_DECLARE_DATA conn_start_module;

typedef struct req_start_config_t {
    apr_time_t time;
    unsigned short int count;
} req_start_config_t;

static int pre_connection(conn_rec *c, void *csd)
{
    req_start_config_t *cf = apr_pcalloc(c->pool, sizeof(*cf));
    cf->time = apr_time_now();
    cf->count = 0; 
    ap_set_module_config(c->conn_config, &conn_start_module, cf);
    
    // ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, NULL, "Pre Connection: %hu", cf->count);
    
    return OK;
}

static int post_read_request(request_rec *r)
{
    // Set the header if current request is not an internal redirection or sub request
    if (r->prev == NULL && r->main == NULL) {
        req_start_config_t *cf = ap_get_module_config(r->connection->conn_config, &conn_start_module);
    
        char* buf_time = apr_palloc(r->pool, 20);
        char* buf_count = apr_psprintf(r->pool, "%hu", ++cf->count);

        apr_snprintf(buf_time, 20, "%" APR_TIME_T_FMT, cf->time);

        apr_table_setn(r->headers_in, "X-Request-Start", buf_time);
        apr_table_setn(r->headers_in, "X-Request-Count", buf_count);
    
        // ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(01128) "Post Read request: %hu - %s", cf->count, r->uri);
    }
    
    return DECLINED;
}

static void register_hooks(apr_pool_t *pool)
{
    ap_hook_pre_connection(pre_connection, NULL, NULL, APR_HOOK_FIRST);
    ap_hook_post_read_request(post_read_request, NULL, NULL, APR_HOOK_FIRST);
}

AP_DECLARE_MODULE(conn_start) =
{
    STANDARD20_MODULE_STUFF,
    NULL,            /* Per-directory configuration handler */
    NULL,            /* Merge handler for per-directory configurations */
    NULL,            /* Per-server configuration handler */
    NULL,            /* Merge handler for per-server configurations */
    NULL,            /* Any directives we may have for httpd */
    register_hooks   /* Our hook registering function */
};
