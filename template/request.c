/*
    Name - Apoorva Kumar
    Roll No. - BT19CSE008
    OS Assignment-2 Multithreading
*/

#include "io_helper.h"
#include "request.h"
#define BUFMAX (8192)
#define MAX (1000)

pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t empty = PTHREAD_COND_INITIALIZER;
pthread_cond_t full = PTHREAD_COND_INITIALIZER;

//
//	TODO: add code to create and manage the buffer
//
//? Request struct and methods----------------------------------------
typedef struct __call
{
  int fd;
  char *identity_file;
  int size_file;
} request;

void newRequest(request *r,int fd, char *identity_file, int size_file)
{
  r->identity_file = strdup(identity_file);
  r->fd = fd;
  r->size_file = size_file;
}

void printRequest(request r)
{
    printf("Request: fd = %d, identity_file = %s, size_file = %d\n",r.fd,r.identity_file,r.size_file);
}

void callRequest(request *t,request s)
{
    t->fd = s.fd;
    t->identity_file = strdup(s.identity_file);
    t->size_file = s.size_file;
}
//? Request ends here--------------------------------------------------

//TODO : First In First Out
// * FIFO Starts here--------------------------------------------------

typedef struct __circ_screen
{
  int after;
  int before;
  int size_current;
  request scr[MAX];
} screen_FIFO;

void put_FIFO(screen_FIFO *scr, int fd, char *identity_file, int size_file)
{
    if((scr->after == 0 && scr->before == buffer_max_size-1) || (scr->before == (scr->after-1)%(buffer_max_size-1)))
    {
        scr->size_current = buffer_max_size;
        printf("buffer is full\n");
        return;
    }
    else if(scr->after == -1)
    {
        scr->after = scr->before =  0;
        scr->size_current++;
        newRequest(&scr->scr[scr->before],fd,identity_file,size_file);
    }
    else if (scr->before == buffer_max_size-1 && scr->after != 0)
    {
        scr->size_current++;
        scr->before = 0;
        newRequest(&scr->scr[scr->before],fd,identity_file,size_file);
    }
    else
    {
        scr->size_current++;
        scr->before++;
        newRequest(&scr->scr[scr->before],fd,identity_file,size_file);
    }
}

void pullFIFO(screen_FIFO *scr,request *r)
{
    if(scr->after == -1)
    {
        scr->size_current = 0;
        printf("buffer is empty\n");
        return;
    }

    newRequest(r,scr->scr[scr->after].fd,scr->scr[scr->after].identity_file,scr->scr[scr->after].size_file);
    free(scr->scr[scr->after].identity_file);

    if(scr->after == scr->before)
    {
        scr->size_current = 0;
        scr->after = -1;
        scr->before = -1;
    }
    else if(scr->after == buffer_max_size-1)
    {
        scr->size_current--;
        scr->after = 0;
    }
    else
    {
        scr->size_current--;
        scr->after++;
    }
}
//* FIFO ends here-------------------------------------------------------




//TODO : Shortest File First
// *SFF Starts here------------------------------------------------------
typedef struct __heap
{
    request scr[MAX];
    int size_current;
}screen_SFF;


void HeapifySSF(screen_SFF *s,int idx)
{
    int min = idx;
    if(2*idx+1 < s->size_current && s->scr[2*idx+1].size_file < s->scr[min].size_file)
        min = 2*idx+1;
    if(2*idx+2 < s->size_current && s->scr[2*idx+2].size_file < s->scr[min].size_file)
        min = 2*idx+2;
    if(min==idx)
        return;
    else
    {
        request t;
        callRequest(&t,s->scr[min]);
        callRequest(&s->scr[min],s->scr[idx]);
        callRequest(&s->scr[idx],t);
        HeapifySSF(s,min);
    }

}

void put_SSF(screen_SFF *s,int fd,char *identity_file,int size_file)
{
    if(s->size_current == buffer_max_size)
    {
        printf("buffer is full\n");
        return;
    }

    newRequest(&s->scr[s->size_current],fd,identity_file,size_file);
    int up = s->size_current++;

    while (up>0 && s->scr[(up-1)/2].size_file > s->scr[up].size_file)
    {
        request t;
        callRequest(&t,s->scr[(up-1)/2]);
        callRequest(&s->scr[(up-1)/2],s->scr[up]);
        callRequest(&s->scr[up],t);
        up = (up-1)/2;
    }
}

void get_SFF(screen_SFF *s,request *r)
{
    if(s->size_current  <=0)
    {
        printf("buffer is empty\n");
        return;
    }
    callRequest(r,s->scr[0]);
    s->size_current--;
    if(s->size_current!=0)
    {
        callRequest(&s->scr[0],s->scr[s->size_current]);
        HeapifySSF(s,0);
    }
}

//* SFF ends here-----------------------------------------------

// ! Global buffers for FIFO and SFF ---------------------------
screen_FIFO effort = { .after = -1, .before=-1, .size_current=0 };
screen_FIFO *f = &effort;

screen_SFF std = {.size_current=0};
screen_SFF *s = &std;
// !-------------------------------------------------------------
//
// Sends out HTTP response in case of errors
//
void request_error(int fd, char *cause, char *errnum, char *shortmsg, char *longmsg) {
    char buf[BUFMAX], body[BUFMAX];

    // Create the body of error message first (have to know its length for header)
    sprintf(body, ""
	    "<!doctype html>\r\n"
	    "<head>\r\n"
	    "  <title>OSTEP WebServer Error</title>\r\n"
	    "</head>\r\n"
	    "<body>\r\n"
	    "  <h2>%s: %s</h2>\r\n"
	    "  <p>%s: %s</p>\r\n"
	    "</body>\r\n"
	    "</html>\r\n", errnum, shortmsg, longmsg, cause);

    // Write out the header information for this response
    sprintf(buf, "HTTP/1.0 %s %s\r\n", errnum, shortmsg);
    write_or_die(fd, buf, strlen(buf));

    sprintf(buf, "Content-Type: text/html\r\n");
    write_or_die(fd, buf, strlen(buf));

    sprintf(buf, "Content-Length: %lu\r\n\r\n", strlen(body));
    write_or_die(fd, buf, strlen(buf));

    // Write out the body last
    write_or_die(fd, body, strlen(body));

    // close the socket connection
    close_or_die(fd);
}

//
// Reads and discards everything up to an empty text line
//
void request_read_headers(int fd) {
    char buf[BUFMAX];

    readline_or_die(fd, buf, BUFMAX);
    while (strcmp(buf, "\r\n")) {
		readline_or_die(fd, buf, BUFMAX);
    }
    return;
}

//
// Return 1 if static, 0 if dynamic content (executable file)
// Calculates identity_file (and cgiargs, for dynamic) from uri
//
int request_parse_uri(char *uri, char *identity_file, char *cgiargs) {
    char *ptr;

    if (!strstr(uri, "cgi")) {
	// static
	strcpy(cgiargs, "");
	sprintf(identity_file, ".%s", uri);
	if (uri[strlen(uri)-1] == '/') {
	    strcat(identity_file, "index.html");
	}
	return 1;
    } else {
	// dynamic
	ptr = index(uri, '?');
	if (ptr) {
	    strcpy(cgiargs, ptr+1);
	    *ptr = '\0';
	} else {
	    strcpy(cgiargs, "");
	}
	sprintf(identity_file, ".%s", uri);
	return 0;
    }
}

//
// Fills in the filetype given the identity_file
//
void request_get_filetype(char *identity_file, char *filetype) {
    if (strstr(identity_file, ".html"))
		strcpy(filetype, "text/html");
    else if (strstr(identity_file, ".gif"))
		strcpy(filetype, "image/gif");
    else if (strstr(identity_file, ".jpg"))
		strcpy(filetype, "image/jpeg");
    else
		strcpy(filetype, "text/plain");
}

//
// Handles requests for static content
//
void request_serve_static(int fd, char *identity_file, int size_file) {
    int srcfd;
    char *srcp, filetype[BUFMAX], buf[BUFMAX];

    request_get_filetype(identity_file, filetype);
    srcfd = open_or_die(identity_file, O_RDONLY, 0);

    // Rather than call read() to read the file into memory,
    // which would require that we allocate a buffer, we memory-map the file
    srcp = mmap_or_die(0, size_file, PROT_READ, MAP_PRIVATE, srcfd, 0);
    close_or_die(srcfd);

    // put together response
    sprintf(buf, ""
	    "HTTP/1.0 200 OK\r\n"
	    "Server: OSTEP WebServer\r\n"
	    "Content-Length: %d\r\n"
	    "Content-Type: %s\r\n\r\n",
	    size_file, filetype);

    write_or_die(fd, buf, strlen(buf));

    //  Writes out to the client socket the memory-mapped file
    write_or_die(fd, srcp, size_file);
    munmap_or_die(srcp, size_file);
}

//
// Fetches the requests from the buffer and handles them (thread locic)
//
void* thread_request_serve_static(void* arg)
{
	// TODO: write code to actualy respond to HTTP requests
    int i;
    while(1)
    {
        sleep(1);
        pthread_mutex_lock(&mutex);
        if(scheduling_algo)
        {
            while(s->size_current == 0)
                pthread_cond_wait(&full,&mutex);
        }
        else
        {
            while(f->size_current == 0)
                pthread_cond_wait(&full,&mutex);
        }
        request r;
        if(scheduling_algo)
            get_SFF(s,&r);
        else
            pullFIFO(f,&r);
        printf("Request for %s is removed from the buffer\n",r.identity_file);

        pthread_cond_signal(&empty);
        pthread_mutex_unlock(&mutex);

        // *Actual request serving
        request_serve_static(r.fd,r.identity_file,r.size_file);
        close_or_die(r.fd);
        // *----------------------
    }

}

//
// Initial handling of the request
//
void request_handle(int fd) {
    int is_static;
    struct stat sbuf;
    char buf[BUFMAX], method[BUFMAX], uri[BUFMAX], version[BUFMAX];
    char identity_file[BUFMAX], cgiargs[BUFMAX];

	// get the request type, file path and HTTP version
    readline_or_die(fd, buf, BUFMAX);
    sscanf(buf, "%s %s %s", method, uri, version);
    printf("method:%s uri:%s version:%s\n", method, uri, version);

	// verify if the request type is GET is not
    if (strcasecmp(method, "GET")) {
		request_error(fd, method, "501", "Not Implemented", "server does not implement this method");
		return;
    }
    request_read_headers(fd);

	// check requested content type (static/dynamic)
    is_static = request_parse_uri(uri, identity_file, cgiargs);

    // TODO: code for security check
    if(strstr(identity_file, "..") != NULL){
        request_error(fd, identity_file, "403", "Forbidden", "Traversing up in filesystem is not allowed");
        return;
    }
	// get some data regarding the requested file, also check if requested file is present on server
    if (stat(identity_file, &sbuf) < 0) {
		request_error(fd, identity_file, "404", "Not found", "server could not find this file");
		return;
    }

	// verify if requested content is static
    if (is_static) {
		if (!(S_ISREG(sbuf.st_mode)) || !(S_IRUSR & sbuf.st_mode)) {
			request_error(fd, identity_file, "403", "Forbidden", "server could not read this file");
			return;
		}

		// TODO: write code to add HTTP requests in the buffer based on the scheduling policy
        pthread_mutex_lock(&mutex);
        if(scheduling_algo)
        {
            while(s->size_current == buffer_max_size )
                pthread_cond_wait(&empty,&mutex);
            put_SSF(s,fd,identity_file,sbuf.st_size);
        }
        else
        {
            while(f->size_current == buffer_max_size )
                pthread_cond_wait(&empty,&mutex);
            put_FIFO(f,fd,identity_file,sbuf.st_size);
        }
        printf("Request for %s is added to the buffer\n",identity_file);
        if(scheduling_algo)
            printf("Added size SFF = %d\n",s->size_current);
        else
            printf("Added size FIFO = %d\n",f->size_current);
        pthread_cond_signal(&full);
        pthread_mutex_unlock(&mutex);

    } else {
		request_error(fd, identity_file, "501", "Not Implemented", "server does not serve dynamic content request");
    }
}
