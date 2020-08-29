/* Copyright (C) 2020 Seacom srl
 * Copyright (C) 2015-2020, Wazuh Inc.
 * Copyright (C) 2010 Trend Micro Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "shared.h"
#include "logcollector.h"


/* Add str to buffer */
int add_to_buffer(char *str, char *buffer) {
    size_t buffer_size = strlen(buffer);
    if (buffer[0] != '\0') {
        buffer[buffer_size] = '\n';
        buffer_size++;
    }

    strncpy(buffer+buffer_size, str, OS_MAXSTR - OS_LOG_HEADER - buffer_size - 2);
    return (buffer_size + strlen(str)) > (OS_MAXSTR - OS_LOG_HEADER - 2);
}

/* Send buffer to message queue */
void send_buffer_to_queue(logreader *lf, int drop_it, char *buffer) {
    mdebug2("Reading message: '%.*s'%s", sample_log_length, buffer, strlen(buffer) > sample_log_length ? "..." : "");
    /* Send message to queue */
    if (drop_it == 0) {
        w_msg_hash_queues_push(buffer, lf->file, strlen(buffer) + 1, lf->log_target, LOCALFILE_MQ);
    }
    buffer[0] = '\0';
    /* The buffer has been sent at least one time during this loop, so we can set truncated_multiline to false for this source */
    lf->truncated_multiline = 0;
}

/* Read multiline logs with regex pattern */
void *read_multiline_pattern(logreader *lf, int *rc, int drop_it) {
    int __ms = 0;
    int __bs = 0;
    int __ms_reported = 0;
    char str[OS_MAXSTR + 1];
    char buffer[OS_MAXSTR + 1];
    fpos_t fp_pos;
    int lines = 0;
    fpos_t fp_last_multiline_pos;
#ifdef WIN32
    int64_t offset;
    int64_t rbytes;
#else
    long offset = 0;
    long rbytes = 0;
#endif

    str[OS_MAXSTR] = '\0';
    buffer[0] = '\0';
    buffer[OS_MAXSTR] = '\0';
    *rc = 0;

    /* Get initial file location */
    fgetpos(lf->fp, &fp_pos);
    fp_last_multiline_pos = fp_pos;

    for (offset = w_ftell(lf->fp); can_read() && fgets(str, OS_MAXSTR - OS_LOG_HEADER, lf->fp) != NULL && (!maximum_lines || lines < maximum_lines) && offset >= 0; offset += rbytes) {
        rbytes = w_ftell(lf->fp) - offset;
        lines++;

        /* Flow control */
        if (rbytes <= 0) {
            break;
        }

        /* Get the last occurrence of \n */
        if (str[rbytes - 1] == '\n') {
            str[rbytes - 1] = '\0';

            if ((int64_t)strlen(str) != rbytes - 1)
            {
                mdebug2("Line in '%s' contains some zero-bytes (valid=" FTELL_TT "/ total=" FTELL_TT "). Dropping line.", lf->file, FTELL_INT64 strlen(str), FTELL_INT64 rbytes - 1);
                continue;
            }
        }

        /* If we didn't get the new line, because the
         * size is large, send what we got so far.
         */
        else if (rbytes == OS_MAXSTR - OS_LOG_HEADER - 1) {
            /* Message size > maximum allowed */
            __ms = 1;
            str[rbytes - 1] = '\0';
        } else {
            /* We may not have gotten a line feed
             * because we reached EOF.
             */
             if (feof(lf->fp)) {
                /* Message not complete. Return. */
                mdebug2("Message not complete from '%s'. Trying again: '%.*s'%s", lf->file, sample_log_length, str, rbytes > sample_log_length ? "..." : "");
                fsetpos(lf->fp, &fp_pos);
                break;
            }
        }

#ifdef WIN32
        char * p;

        if ((p = strrchr(str, '\r')) != NULL) {
            *p = '\0';
        }

        /* Look for empty string (only on Windows) */
        if (rbytes <= 2) {
            fgetpos(lf->fp, &fp_pos);
            continue;
        }

        /* Windows can have comment on their logs */
        if (str[0] == '#') {
            fgetpos(lf->fp, &fp_pos);
            continue;
        }
#endif


        /* Check if the current line matches the configured regular expression */
        /* OS_Regex returns 0 or 1 */
        if (OS_Regex(lf->multiline_regex, str) ^ lf->multiline_negate) {
            if (lf->multiline_match_after) {
                /* Match after: all lines not matching the regex are aggregated with the line before them.
                 * This means that if a line matches the buffer we will first flush the buffer to the queue and then add the line to the buffer
                 */
                if (buffer[0] != '\0') {
                    /* Buffer is not empty */
                    send_buffer_to_queue(lf, drop_it, buffer);
                    fp_last_multiline_pos = fp_pos;  // position before reading this line, so at the end of the previous buffer
                }
                __bs = add_to_buffer(str, buffer);
            } else {
                /* Match before: all lines not matching the regex are aggregated with the line after them.
                 * This means that if a line matches the buffer we will add the line to the buffer and then flust the buffer to the message queue.
                 */
                __bs = add_to_buffer(str, buffer);
                send_buffer_to_queue(lf, drop_it, buffer);
                fgetpos(lf->fp, &fp_last_multiline_pos);  // position after reading this line
            }
        } else {
            /* Just add the current line to the buffer and go the next iteration */
            __bs = add_to_buffer(str, buffer);
        }

        mdebug2("Reading syslog message: '%.*s'%s", sample_log_length, str, rbytes > sample_log_length ? "..." : "");

        /* Incorrect message or buffer size */
        if (__ms || __bs) {
            // strlen(str) >= (OS_MAXSTR - OS_LOG_HEADER - 2)
            // strlen(str) + buffer_size >= (OS_MAXSTR - OS_LOG_HEADER -2)
            // truncate str before logging to ossec.log

            if (!__ms_reported) {
                merror("Large message size from file '%s' (length = " FTELL_TT "): '%.*s'...", lf->file, FTELL_INT64 rbytes, sample_log_length, buffer);
                __ms_reported = 1;
            } else {
                mdebug2("Large message size from file '%s' (length = " FTELL_TT "): '%.*s'...", lf->file, FTELL_INT64 rbytes, sample_log_length, buffer);
            }

            /* Loop on the line to reach its end, in the __bs case next line will be read again (and discarded) */
            for (offset += rbytes; fgets(str, OS_MAXSTR - 2, lf->fp) != NULL; offset += rbytes) {
                rbytes = w_ftell(lf->fp) - offset;

                /* Flow control */
                if (rbytes <= 0) {
                    break;
                }

                /* Get the last occurrence of \n */
                if (str[rbytes - 1] == '\n') {
                    break;
                }
            }
            __ms = 0;
            __bs = 0;
        }
        fgetpos(lf->fp, &fp_pos);
        continue;
    }
    if (buffer[0] != '\0') {
        /* There is still something in the buffer, we want to wait for new
         * lines of the message until the next loop
         */
        if (lf->truncated_multiline) {
            /* We set this variable the last time the function was called and
             * it has never been resetted, this means that we have in the
             * buffer lines from the last loop 
             */
            /* Flush the buffer before it is stale */
            send_buffer_to_queue(lf, drop_it, buffer);
        } else {
            /* In the last call we didn't leave any line behind or that lines
             * has been sent during this interation
             */
            /* There are still lines in the buffer, we will reset the file
             * position in order to process them in the next call, we also set
             * the truncated_multiline variabile to be sure to flush them in
             * the next function call
             */
            fsetpos(lf->fp, &fp_last_multiline_pos);
            lf->truncated_multiline = 1;
        }

    }

    mdebug2("Read %d lines from %s", lines, lf->file);
    return (NULL);
}
