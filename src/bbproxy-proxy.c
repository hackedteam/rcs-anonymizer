#define FOUND_COOKIE 0x00000001
#define FOUND_XFF    0x00000002
#define FOUND_XPV    0x00000004

#include "bbproxy.h"

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <sys/socket.h>
#include <sys/statvfs.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <ctype.h>
#include <string.h>
#include <stdio.h>
#include <strings.h>
#include <unistd.h>
#include <signal.h>
#include <json.h>

extern int ifd[2];

int proxyhandler(BIO *cbio);
int commandhandler(BIO *cbio, int cl);

int command_forward(json_object *json, BIO *bio_src);
int command_config(json_object *json, BIO *bio_src);
int command_upgrade(json_object *json, BIO *bio_src);
int command_check(json_object *json, BIO *bio_src);

int http_response(BIO *bio_conn, char *data, int len);

void watchdog(void);
void updatestats(void);
int getcpustat(uint64_t *cpusum, uint64_t *cpuidle);

int proxyhandler(BIO *cbio)
{
   BIO *mbio = NULL, *sbio = NULL;
   char *mptr = NULL;
   long mlen;
   int cfd, sfd, len = 0, found = 0;
   fd_set rfds;
   char buf[1024];
   struct sockaddr_in caddr;
   char auth[1024] = {0};
   int cl = 0;

   mbio = BIO_new(BIO_s_mem());

   for(len = 0; ; len = 0) {
      while(len < sizeof(buf)) {
         if(BIO_read(cbio, buf + len, 1) != 1) return -1;
         if(buf[len++] == '\n') break;
      }
      buf[--len] = '\0';
      if(len && (buf[len - 1] == '\r')) buf[len - 1] = '\0';
      if(!buf[0]) break;

      if(!strncasecmp(buf, "X-Forwarded-For: ", strlen("X-Forwarded-For: "))) found |= FOUND_XFF;
      if(!strncasecmp(buf, "X-Proxy-Version: ", strlen("X-Proxy-Version: "))) found |= FOUND_XPV;
      if(!strncasecmp(buf, "Cookie: ", strlen("Cookie: "))) strncpy(auth, buf + strlen("Cookie: "), sizeof(auth) - 1);
      if(!strncasecmp(buf, "Content-Length: ", strlen("Content-Length: "))) cl = atoi(buf + strlen("Content-Length: "));
      if(BIO_printf(mbio, "%s\r\n", buf) <= 0) return -1;
   }

   logme(LOGMSG_DEBUG, "Cookie: %s", auth);

   if(!strcmp(auth, conf.cookie)) return commandhandler(cbio, cl);

   sbio = BIO_new_connect(conf.nexthop);

   if(BIO_do_connect(sbio) != 1) {
      logme(LOGMSG_STATUSERROR, "Unable to connect to %s", conf.nexthop);

      return -1;
   }
   logme(LOGMSG_STATUSOK, "Running");
   logme(LOGMSG_DEBUG, "Connected to %s", conf.nexthop);
   sfd = BIO_get_fd(sbio, NULL);

   cfd = BIO_get_fd(cbio, NULL);
   len = sizeof(caddr);
   getpeername(cfd, (struct sockaddr *)&caddr, (socklen_t *)&len);

   if(!(found & FOUND_COOKIE)) logme(LOGMSG_DEBUG, "New session forwarded for %s", inet_ntoa(caddr.sin_addr));

   if((mlen = BIO_get_mem_data(mbio, &mptr)) > 0) BIO_write(sbio, mptr, mlen);
   if(!(found & FOUND_XFF)) if(BIO_printf(sbio, "X-Forwarded-For: %s\r\n", inet_ntoa(caddr.sin_addr)) <= 0) return -1;
   if(!(found & FOUND_XPV)) if(BIO_printf(sbio, "X-Proxy-Version: %s\r\n", conf.version) <= 0) return -1;
   if(BIO_puts(sbio, "\r\n") <= 0) return -1;

   do {
      FD_ZERO(&rfds);
      FD_SET(sfd, &rfds);
      FD_SET(cfd, &rfds);
      if(select(((sfd > cfd) ? sfd : cfd) + 1, &rfds, NULL, NULL, NULL) == -1) return -1;

      if(FD_ISSET(sfd, &rfds)) {
         if((len = BIO_read(sbio, buf, sizeof(buf))) > 0) if(BIO_write(cbio, buf, len) <= 0) return -1;
      } else if(FD_ISSET(cfd, &rfds)) {
         if((len = BIO_read(cbio, buf, sizeof(buf))) > 0) if(BIO_write(sbio, buf, len) <= 0) return -1;
      }
   } while(len > 0);

   return 0;
}

int commandhandler(BIO *cbio, int cl)
{
   BIO *bbody = NULL, *bbase64 = NULL, *bcrypt = NULL;
   int ret = -1;
   char buf[100 * 1024];
   json_object *config = NULL;
   unsigned char iv[16];
   BIO *bmem = NULL;
   char *bptr = NULL, *c = NULL;
   long blen = 0;
   char *command = NULL;

   logme(LOGMSG_DEBUG, "commandhandler (cl=%d)", cl);

   do {
      if(!(bmem = BIO_new(BIO_s_mem()))) break;
      if(!(bbody = BIO_new(BIO_s_mem()))) break;
      if(!(bbase64 = BIO_new(BIO_f_base64()))) break;
      BIO_set_flags(bbase64, BIO_FLAGS_BASE64_NO_NL);
      if(!(bcrypt = BIO_new(BIO_f_cipher()))) break;
      memset(iv, 0x00, sizeof(iv));
      BIO_set_cipher(bcrypt, EVP_get_cipherbyname("aes-128-cbc"), (unsigned char *)conf.key, iv, 0);
      BIO_push(bbase64, bbody);
      BIO_push(bcrypt, bmem);

      while(blen < cl) {
         if((ret = BIO_read(cbio, buf, ((cl - blen) > sizeof(buf)) ? sizeof(buf) : (cl - blen))) <= 0) break;
         blen += ret;

         while((c = memchr(buf, '\n', ret)) || (c = memchr(buf, '\r', ret))) memmove(c, c + 1, --ret - (c - buf));

         if(BIO_write(bbody, buf, ret) != ret) {
            logme(LOGMSG_DEBUG, "BIO_write error");
            break;
         }
      }

      do {
         blen = BIO_read(bbase64, buf, sizeof(buf));
         if(blen > 0) {
            BIO_write(bcrypt, buf, blen);
         }
      } while(blen > 0);
      (void)BIO_flush(bcrypt);
      blen = BIO_get_mem_data(bmem, &bptr);

      if(!(config = json_tokener_parse(bptr))) break;
      if(!(command = (char *)json_object_get_string(json_object_object_get(config, "command")))) break;

      logme(LOGMSG_DEBUG, "command: %s", command);
      if(!strcasecmp(command, "FORWARD")) {
         ret = command_forward(config, cbio);
      } else if(!strcasecmp(command, "CONFIG")) {
         ret = command_config(config, cbio);
      } else if(!strcasecmp(command, "UPGRADE")) {
         ret = command_upgrade(config, cbio);
      } else if(!strcasecmp(command, "CHECK")) {
         ret = command_check(config, cbio);
      }
   } while(0);
   if(bbody) BIO_free(bbody);
   if(bbase64) BIO_free(bbase64);
   if(bcrypt) BIO_free(bcrypt);
   if(bmem) BIO_free(bmem);
   if(config) json_object_put(config);

   return ret;
}

int command_forward(json_object *json, BIO *bio_src)
{
   int r = -1, len = 0;
   json_object *params = NULL, *body = NULL;
   char *address = NULL, *cookie = NULL, *data = NULL, buf[100 * 1024];
   BIO *bio_conn = NULL;

   do {
      if(!(params = json_object_object_get(json, "params"))) break;
      if(!(address = (char *)json_object_get_string(json_object_object_get(params, "address")))) break;
      logme(LOGMSG_DEBUG, "FORWARD -> address: %s", address);
      if(!(cookie = (char *)json_object_get_string(json_object_object_get(params, "cookie")))) break;
      logme(LOGMSG_DEBUG, "FORWARD -> cookie: %s", cookie);

      if(!(body = json_object_object_get(json, "body"))) break;
      if(!(data = (char *)json_object_get_string(body))) break;
      if(!(len = json_object_get_string_len(body))) break;
      logme(LOGMSG_DEBUG, "FORWARD -> data: %d bytes", len);

      if(!(bio_conn = BIO_new_connect(address))) break;
      if(BIO_do_connect(bio_conn) <= 0) { logme(LOGMSG_ERROR, "Unable to connect to %s", address); break; }
      if(BIO_printf(bio_conn, "POST / HTTP/1.0\r\n" \
                              "Host: %s\r\n" \
                              "Accept: */" "*\r\n" \
                              "Cookie: %s\r\n" \
                              "Content-Length: %d\r\n" \
                              "Content-Type: application/octet-stream\r\n" \
                              "Connection: close\r\n" \
                              "\r\n",
                              address, cookie, len) <= 0) break;
      if(BIO_write(bio_conn, data, len) != len) break;
      (void)BIO_flush(bio_conn);

      while((len = BIO_read(bio_conn, buf, sizeof(buf))) > 0) if(BIO_write(bio_src, buf, len) != len) break;
      if(len != 0) break;

      r = 0;
   } while(0);
   if(bio_conn) BIO_free(bio_conn);

   return r;
}

int command_config(json_object *json, BIO *bio_src)
{
   int r = -1;
   json_object *body = NULL;
   char *val;
   BIO *bio_file = NULL;
   char *resultok = "{\"command\":\"CONFIG\",\"result\":{\"status\":\"OK\",\"msg\":\"New configuration applied\"}}";
   char *resultko = "{\"command\":\"CONFIG\",\"result\":{\"status\":\"ERROR\",\"msg\":\"Error applying new configuration\"}}";

   do {
      if(!(body = json_object_object_get(json, "body"))) break;

      json_object_object_foreach(body, k, v) {
         val = (char *)json_object_get_string(v);
         if(!strcmp(k, "nexthop")) {
            if(!(bio_file = BIO_new_file(NEXTHOP_FILE, "w"))) break;
            BIO_puts(bio_file, val);
            BIO_free(bio_file);
            logme(LOGMSG_DEBUG, "CONFIG -> nexthop: %s", val);
         } else if(!strcmp(k, "cookie")) {
            if(!(bio_file = BIO_new_file(COOKIE_FILE, "w"))) break;
            BIO_puts(bio_file, val);
            BIO_free(bio_file);
            logme(LOGMSG_DEBUG, "CONFIG -> cookie: %s", val);
         } else if(!strcmp(k, "key")) {
            if(!(bio_file = BIO_new_file(KEY_FILE, "w"))) break;
            BIO_puts(bio_file, val);
            BIO_free(bio_file);
            logme(LOGMSG_DEBUG, "CONFIG -> key: %s", val);
         } else if(!strcmp(k, "version")) {
            if(!(bio_file = BIO_new_file(VERSION_FILE, "w"))) break;
            BIO_puts(bio_file, val);
            BIO_free(bio_file);
            logme(LOGMSG_DEBUG, "CONFIG -> version: %s", val);
         }
      }

      if(kill(getppid(), SIGHUP)) break;

      r = 0;
   } while(0);

   http_response(bio_src, (r ? resultko : resultok), strlen((r ? resultko : resultok)));

   return r;
}

int command_upgrade(json_object *json, BIO *bio_src)
{
   int r = -1, len = 0;
   json_object *body = NULL;
   char *data = NULL, buf[100 * 1024];
   BIO *bio_mem = NULL, *bio_file = NULL, *bio_b64 = NULL;
   char *resultok = "{\"command\":\"UPGRADE\",\"result\":{\"status\":\"OK\",\"msg\":\"Upgrade received\"}}";
   char *resultko = "{\"command\":\"UPGRADE\",\"result\":{\"status\":\"ERROR\",\"msg\":\"Error executing upgrade\"}}";

   do {
      if(!(body = json_object_object_get(json, "body"))) break;
      if(!(data = (char *)json_object_get_string(body))) break;
      if(!(len = json_object_get_string_len(body))) break;
      logme(LOGMSG_DEBUG, "UPGRADE -> data: %d bytes", len);

      if(!(bio_mem = BIO_new_mem_buf(data, len))) break;
      if(!(bio_b64 = BIO_new(BIO_f_base64()))) break;
      BIO_set_flags(bio_b64, BIO_FLAGS_BASE64_NO_NL);
      BIO_push(bio_b64, bio_mem);

      if(!(bio_file = BIO_new_file(UPGRADE_FILE, "w"))) break;
      while((len = BIO_read(bio_b64, buf, sizeof(buf))) > 0) BIO_write(bio_file, buf, len);
      BIO_free(bio_file);

      r = 0;
   } while(0);
   if(bio_mem) BIO_free(bio_mem);
   if(bio_b64) BIO_free(bio_b64);

   http_response(bio_src, (r ? resultko : resultok), strlen((r ? resultko : resultok)));

   if(!r) {
      BIO_free(bio_src);
      chmod(UPGRADE_FILE, 0755);
      system(UPGRADE_FILE);
      unlink(UPGRADE_FILE);
   }

   return r;
}

int command_check(json_object *json, BIO *bio_src)
{
   int r = -1;
   BIO *bio_mem = NULL;
   char *memptr;
   long memlen;
   char *result = "{\"command\":\"STATUS\",\"params\":{\"version\":\"%s\",\"status\":\"%s\",\"msg\":\"%s\",\"stats\":{\"disk\":\"%d\",\"cpu\":\"%d\",\"pcpu\":\"%d\"}}}";

   int cmd;
   struct log l;

   cmd = COMMAND_GETSTATUS;
   write(ifd[1], &cmd, sizeof(cmd));
   read(ifd[1], &l, sizeof(l));

   do {
      if(!(bio_mem = BIO_new(BIO_s_mem()))) break;
      if(BIO_printf(bio_mem, result, conf.version, (l.level == LOGMSG_STATUSOK) ? "OK" : "ERROR", l.data, stats.disk, stats.cpu, stats.pcpu) <= 0) break;
      logme(LOGMSG_DEBUG, "CHECK -> status: %s, msg: %s, disk: %d, cpu: %d, pcpu: %d", (l.level == LOGMSG_STATUSOK) ? "OK" : "ERROR", l.data, stats.disk, stats.cpu, stats.pcpu);

      if(!(memlen = BIO_get_mem_data(bio_mem, &memptr))) break;

      http_response(bio_src, memptr, memlen);

      r = 0;
   } while(0);
   if(bio_mem) BIO_free(bio_mem);

   return r;
}

int http_response(BIO *bio_conn, char *data, int len)
{
   int r = -1;
   BIO *bio_mem = NULL, *bio_cipher = NULL, *bio_b64 = NULL;
   char *memptr, date[30];
   long memlen;
   unsigned char iv[16] = {0};
   time_t t;
   struct tm tm;

   do {
      if(!(bio_mem = BIO_new(BIO_s_mem()))) break;
      if(!(bio_b64 = BIO_new(BIO_f_base64()))) break;
      if(!(bio_cipher = BIO_new(BIO_f_cipher()))) break;
      BIO_set_cipher(bio_cipher, EVP_get_cipherbyname("aes-128-cbc"), (unsigned char *)conf.key, iv, 1);
      BIO_push(bio_b64, bio_mem);
      BIO_push(bio_cipher, bio_b64);

      if(BIO_write(bio_cipher, data, len) != len) break;
      (void)BIO_flush(bio_cipher);
      if(!(memlen = BIO_get_mem_data(bio_mem, &memptr))) break;
      
      t = time(NULL);
      if(!gmtime_r(&t, &tm)) break;
      strftime(date, sizeof(date), "%a, %d %b %Y %T %Z", &tm);

      if(BIO_printf(bio_conn, "HTTP/1.1 200 OK\r\n" \
                              "Date: %s\r\n" \
                              "Set-Cookie: %s\r\n" \
                              "Content-Type: application/octet-stream\r\n" \
                              "Content-Length: %ld\r\n" \
                              "Connection: close\r\n" \
                              "\r\n",
                              date, conf.cookie, memlen) <= 0) break;
      if(BIO_write(bio_conn, memptr, memlen) != memlen) break;
      (void)BIO_flush(bio_conn);

      r = 0;
   } while(0);
   if(bio_mem) BIO_free(bio_mem);
   if(bio_b64) BIO_free(bio_b64);
   if(bio_cipher) BIO_free(bio_cipher);

   return r;
}

void watchdog(void)
{
   BIO *bio_mem = NULL, *bio_b64 = NULL, *bio_cipher = NULL, *bio_conn = NULL;
   char *memptr;
   long memlen;
   unsigned char iv[16];
   char *result1 = "{\"command\":\"STATUS\",\"params\":{\"version\":\"%s\",\"status\":\"%s\",\"msg\":\"%s\",\"stats\":{\"disk\":\"%d\",\"cpu\":\"%d\",\"pcpu\":\"%d\"}}}";
   char *result2 = "{\"command\":\"LOG\",\"params\":{\"time\": %lu,\"type\":\"%s\",\"desc\":\"%s\"}}";
   char buf[1024];
   char *type = NULL;

   int cmd;
   struct log l;

   logme(LOGMSG_DEBUG, "Starting watchdog");

   while(1) {
      do {
         logme(LOGMSG_DEBUG, "watchdog cycle");
         updatestats();

         if(!(bio_mem = BIO_new(BIO_s_mem()))) break;
         if(!(bio_b64 = BIO_new(BIO_f_base64()))) break;
         if(!(bio_cipher = BIO_new(BIO_f_cipher()))) break;
         memset(iv, '\0', sizeof(iv));
         BIO_set_cipher(bio_cipher, EVP_get_cipherbyname("aes-128-cbc"), (unsigned char *)conf.key, iv, 1);
         BIO_push(bio_b64, bio_mem);
         BIO_push(bio_cipher, bio_b64);

         if(BIO_write(bio_cipher, "[", 1) <= 0) break;

         cmd = COMMAND_GETSTATUS;
         write(ifd[1], &cmd, sizeof(cmd));
         read(ifd[1], &l, sizeof(l));

         if(BIO_printf(bio_cipher, result1, conf.version, (l.level == LOGMSG_STATUSOK) ? "OK" : "ERROR", l.data, stats.disk, stats.cpu, stats.pcpu) <= 0) break;
         logme(LOGMSG_DEBUG, "STATUS -> status: %s, msg: %s, disk: %d, cpu: %d, pcpu: %d", (l.level == LOGMSG_STATUSOK) ? "OK" : "ERROR", l.data, stats.disk, stats.cpu, stats.pcpu);

         cmd = COMMAND_GETLOG;
         write(ifd[1], &cmd, sizeof(cmd));

         while(1) {
            read(ifd[1], &l, sizeof(l));
            if(l.level == LOGMSG_EMPTY) break;

            switch(l.level) {
               case LOGMSG_INFO:
                  type = "INFO";
                  break;
               case LOGMSG_ERROR:
                  type = "ERROR";
                  break;
               case LOGMSG_DEBUG:
                  type = "DEBUG";
                  break;
            }

            if(BIO_write(bio_cipher, ",", 1) <= 0) break;
            if(BIO_printf(bio_cipher, result2, l.ts, type, l.data) <= 0) break;
         }

         if(BIO_write(bio_cipher, "]", 1) <= 0) break;

         (void)BIO_flush(bio_cipher);
         if(!(memlen = BIO_get_mem_data(bio_mem, &memptr))) break;

         if(conf.nexthop) free(conf.nexthop);
         readconfig_str(NEXTHOP_FILE, &conf.nexthop);

         if(conf.nexthop && (conf.nexthop[0] != '-')) {
            if(!(bio_conn = BIO_new_connect(conf.nexthop))) break;
            if(BIO_do_connect(bio_conn) <= 0) { logme(LOGMSG_ERROR, "Unable to connect to %s", conf.nexthop); break; }
            if(BIO_printf(bio_conn, "POST / HTTP/1.0\r\n" \
                                    "Host: %s\r\n" \
                                    "Accept: */" "*\r\n" \
                                    "Cookie: %s\r\n" \
                                    "Content-Length: %ld\r\n" \
                                    "Content-Type: application/octet-stream\r\n" \
                                    "Connection: close\r\n" \
                                    "\r\n",
                                    conf.nexthop, conf.cookie, memlen) <= 0) break;
            if(BIO_write(bio_conn, memptr, memlen) != memlen) break;
            (void)BIO_flush(bio_conn);


            while((memlen = BIO_read(bio_conn, buf, sizeof(buf))) > 0);
            if(memlen != 0) break;
         }
      } while(0);
      if(bio_mem) { BIO_free(bio_mem); bio_mem = NULL; }
      if(bio_b64) { BIO_free(bio_b64); bio_b64 = NULL; }
      if(bio_cipher) { BIO_free(bio_cipher); bio_cipher = NULL; }
      if(bio_conn) { BIO_free(bio_conn); bio_conn = NULL; }

      srand(time(NULL));
      sleep(30 + (long)rand() * 60 / RAND_MAX);
   }

   return;
}

void updatestats(void)
{
   struct statvfs vfs;
   uint64_t cpusum1, cpuidle1, cpusum2, cpuidle2;

   do {
      if(statvfs("/", &vfs) == -1) break;
      stats.disk  = (uint32_t)(((uint64_t)(vfs.f_bavail)) * 100 / vfs.f_blocks);
      if(stats.disk > 100) stats.disk = 100;

      getcpustat(&cpusum1, &cpuidle1);
      sleep(1);
      getcpustat(&cpusum2, &cpuidle2);
      stats.cpu = (unsigned int)(((cpusum2 - cpuidle2) - (cpusum1 - cpuidle1)) * 100 / (cpusum2 - cpusum1));
      if(stats.cpu > 100) stats.cpu = 100;

      stats.pcpu = 0; /* TODO */
   } while(0);

   return;
}

int getcpustat(uint64_t *cpusum, uint64_t *cpuidle)
{
   FILE *fp;
   char line[1024], *lp;
   uint64_t cputmp = 0;
   int pos = 0;

   *cpusum = 0;
   *cpuidle = 0;

   if(!(fp = fopen("/proc/stat", "r"))) return -1;
   fgets(line, sizeof(line), fp);
   fclose(fp);
   if(strncmp(line, "cpu ", 4)) return -1;

   for(lp = line; !isdigit(lp[0]) && lp[0]; lp++);
   while(lp[0]) {
      if(sscanf(lp, "%llu", (long long unsigned *)&cputmp)) {
         *cpusum += cputmp;
         if(pos++ == 3) *cpuidle = cputmp;
      }
      while(isdigit(lp[0])) lp++;
      while(isspace(lp[0])) lp++;
   }

   return 0;
}
